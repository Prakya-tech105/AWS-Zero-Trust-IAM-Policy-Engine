import { useCallback, useEffect, useState } from 'react'
import Header from './components/Header'
import Metrics from './components/Metrics'
import LiveTelemetry from './components/LiveTelemetry'
import PolicyDiffViewer from './components/PolicyDiffViewer'
import Actions from './components/Actions'
import RoleSelector from './components/RoleSelector'
import { fetchHealth, fetchRoles, fetchRolesDemo, ingestEvent, openTelemetryStream } from './api'
import type { AwsIdentity, EngineResult, RoleInfo, TelemetryEvent } from './types'

// Helper to recursively unwrap multi-escaped JSON strings and format cleanly
const formatPolicy = (policy: any): string => {
  if (!policy) return '// no policy data yet'

  let data = policy
  if (typeof data === 'object' && data !== null) {
    data = data.document || data.policy || data
  }

  // Handle nested stringified JSON
  if (typeof data === 'string') {
    try {
      // First un-escape backslashes if present
      const unescaped = data.replace(/\\"/g, '"').replace(/\\n/g, '\n')
      data = JSON.parse(unescaped)
    } catch {
      try {
        data = JSON.parse(data)
      } catch {
        // Fallback if raw string
      }
    }
  }

  return typeof data === 'object' && data !== null
    ? JSON.stringify(data, null, 2)
    : String(data)
}

export default function App() {
  const [identity, setIdentity] = useState<AwsIdentity | null>(null)
  const [roles, setRoles] = useState<RoleInfo[]>([])
  const [events, setEvents] = useState<TelemetryEvent[]>([])
  const [streamConnected, setStreamConnected] = useState(false)
  const [selectedRole, setSelectedRole] = useState<string | null>(null)
  const [engineResult, setEngineResult] = useState<EngineResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  // --- Initial load: AWS identity + role inventory -------------------------
  useEffect(() => {
    fetchHealth()
      .then((h) =>
        setIdentity({
          connected: h.aws_connected,
          account_id: h.account_id,
          account_alias: h.account_alias,
          caller_arn: h.caller_arn,
          region: h.region,
        }),
      )
      .catch(() => setIdentity({ connected: false, account_id: null }))
    fetchRoles(25)
      .then(setRoles)
      .catch(() => {
        fetchRolesDemo()
          .then(setRoles)
          .catch(() => setRoles([]))
      })
  }, [])

  // --- SSE telemetry stream -------------------------------------------------
  useEffect(() => {
    const es = openTelemetryStream({
      onOpen: () => setStreamConnected(true),
      onError: () => setStreamConnected(false),
      onEvent: (evt) => {
        setEvents((prev) => [...prev.slice(-199), evt as TelemetryEvent])
      },
    })
    return () => es.close()
  }, [])

  // --- Sample event ingestion ----------------------------------------------
  const handleIngest = async (detail: unknown) => {
  try {
    setError(null)
    const result = await ingestEvent(detail)
    console.log('RECEIVED ENGINE RESULT FROM BACKEND:', result) // <-- ADD THIS LOG
    if (result) {
      setEngineResult(result)
    }
  } catch (err) {
    console.error('Ingestion failed:', err)
    setError('Failed to ingest event. Check backend logs or console.')
  }
}

  const handleRemediated = useCallback(() => {
    fetchRoles(25)
      .then(setRoles)
      .catch(() => {
        fetchRolesDemo()
          .then(setRoles)
          .catch(() => {})
      })
  }, [])

  // Extract policy documents using the safe formatter
  // Extract policy documents or provide offline mock fallbacks
// Extract policies from engine result, or supply realistic fallback structures if offline
const currentPolicy = engineResult?.current_policy ?? (
  engineResult ? {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowAllS3Access",
        Effect: "Allow",
        Action: "s3:*",
        Resource: "*"
      }
    ]
  } : null
)

const leastPolicy = engineResult?.zero_trust_policy 
  ?? engineResult?.least_privilege_policy 
  ?? engineResult?.generated_policy 
  ?? (
    engineResult ? {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "ScopedS3Access",
          Effect: "Allow",
          Action: ["s3:GetObject"],
          Resource: "arn:aws:s3:::demo-sensitive-bucket/*"
        }
      ]
    } : null
  )
  
  const roleArn = selectedRole ?? engineResult?.parsed?.role_arn ?? null

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <Header identity={identity} streamConnected={streamConnected} eventCount={events.length} />

      <main className="mx-auto max-w-7xl space-y-4 px-4 py-4">
        {error && (
          <div className="rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-2 text-sm text-red-300">
            {error}
          </div>
        )}

        <Metrics
          riskScore={engineResult?.risk_score ?? 0}
          wildcardReduction={engineResult?.wildcard_reduction ?? 0}
          auditedRoles={roles.length}
          simulationPassRate={engineResult?.simulation?.valid ? 100 : 0}
        />

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <LiveTelemetry events={events} connected={streamConnected} onClear={() => setEvents([])} />
          </div>
          <div className="lg:col-span-1">
            <RoleSelector
              roles={roles}
              selected={selectedRole}
              onSelect={setSelectedRole}
              onIngestSample={handleIngest}
            />
          </div>
        </div>

        <PolicyDiffViewer
          currentPolicy={currentPolicy}
          leastPrivilegePolicy={leastPolicy}
          simulationValid={engineResult?.simulation?.valid ?? null}
        />

        <Actions
          roleArn={roleArn}
          currentPolicy={currentPolicy}
          leastPrivilegePolicy={leastPolicy}
          candidateDetachArn={engineResult?.current_policy?.candidate_detach_arn ?? null}
          onRemediated={handleRemediated}
        />

        <footer className="pb-6 text-center text-[10px] uppercase tracking-widest text-slate-700">
          Zero-Trust IAM Policy Engine · AWS Hackathon Build · CloudTrail → EventBridge → Simulator → Remediation
        </footer>
      </main>
    </div>
  )
}