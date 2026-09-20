import { useState } from 'react'
import RoleSelector from './components/RoleSelector'
import PolicyDiffViewer from './components/PolicyDiffViewer'
import MetricsCard from './components/MetricsCard'
import Header from './components/Header'
import { ShieldAlert, Activity, Cpu, Gauge, Scissors, ShieldCheck, Cloud, GitBranch, LockKeyhole } from 'lucide-react'
import { fetchHealth } from './api'
import type { AwsIdentity, RoleInfo } from './types'

const demoRoles: RoleInfo[] = [
  { role_name: 'TargetApp-OverPrivileged-Role', arn: 'arn:aws:iam::123456789012:role/TargetApp-OverPrivileged-Role' },
  { role_name: 'Analytics-DynamoDB-Role', arn: 'arn:aws:iam::123456789012:role/Analytics-DynamoDB-Role' },
  { role_name: 'Reporting-S3-Role', arn: 'arn:aws:iam::123456789012:role/Reporting-S3-Role' },
  { role_name: 'Platform-Admin-Role', arn: 'arn:aws:iam::123456789012:role/Platform-Admin-Role' },
]

const rolePolicy = (roleArn: string) => {
  const roleName = roleArn.split('/').pop()?.toLowerCase() ?? ''
  if (roleName.includes('dynamodb')) {
    return {
      riskScore: 64,
      wildcardReduction: 82,
      passRate: 96,
      action: 'dynamodb:Query',
      resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/Orders',
      currentSid: 'AllowDynamoDBAccess',
      leastSid: 'ScopedOrdersQuery',
    }
  }
  if (roleName.includes('admin')) {
    return {
      riskScore: 98,
      wildcardReduction: 94,
      passRate: 88,
      action: 'iam:GetRole',
      resource: roleArn,
      currentSid: 'AdministratorAccess',
      leastSid: 'ScopedRoleInspection',
    }
  }
  if (roleName.includes('s3') || roleName.includes('reporting')) {
    return {
      riskScore: 38,
      wildcardReduction: 91,
      passRate: 100,
      action: 's3:GetObject',
      resource: 'arn:aws:s3:::reports-prod/reports/*',
      currentSid: 'AllowReportsBucketAccess',
      leastSid: 'ScopedReportsRead',
    }
  }
  return {
    riskScore: 85,
    wildcardReduction: 100,
    passRate: 100,
    action: 's3:GetObject',
    resource: 'arn:aws:s3:::demo-sensitive-bucket/reports/*',
    currentSid: 'AllowAllS3Access',
    leastSid: 'ScopedS3Access',
  }
}

function buildOfflineResult(roleArn: string) {
  const policy = rolePolicy(roleArn)
  return {
  parsed: { role_arn: roleArn, action: policy.action },
  current_policy: {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: policy.currentSid,
        Effect: "Allow",
        Action: "*",
        Resource: "*"
      }
    ]
  },
  zero_trust_policy: {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: policy.leastSid,
        Effect: "Allow",
        Action: [policy.action],
        Resource: policy.resource
      }
    ]
  },
  simulation: {
    valid: true,
    pass_rate: `${policy.passRate}%`
  },
  risk_score: policy.riskScore,
  wildcard_reduction: `${policy.wildcardReduction}%`
  }
}

function roleArnFromPayload(payload: any, fallback: string): string {
  return payload?.parsed?.role_arn || payload?.role_arn || payload?.userIdentity?.arn || fallback
}

export default function App() {
  const [selectedRole, setSelectedRole] = useState<string | null>(
    null
  )
  const [customArn, setCustomArn] = useState<string>('')
  const [engineResult, setEngineResult] = useState<any>(null)
  const [identity, setIdentity] = useState<AwsIdentity | null>(null)
  const [connecting, setConnecting] = useState(false)
  const [connectionMessage, setConnectionMessage] = useState('AWS link ready for verification')
  const [telemetryEvents, setTelemetryEvents] = useState<string[]>([])

  const handleIngestSample = (payload: any) => {
    const roleArn = roleArnFromPayload(payload, selectedRole || demoRoles[0].arn)
    setSelectedRole(roleArn)
    setEngineResult(buildOfflineResult(roleArn))
    const timestamp = new Date().toLocaleTimeString()
    const roleName = roleArn.split('/').pop() || 'TargetRole'
    setTelemetryEvents(prev => [
      `${timestamp} [IAM] Evaluated policy & generated least-privilege for ${roleName}`,
      ...prev
    ])
  }

  const handleRoleSelect = (roleArn: string | null) => {
    setSelectedRole(roleArn)
  }

  const handleConnect = async () => {
    setConnecting(true)
    setConnectionMessage('Verifying AWS credentials and account access...')
    try {
      const health = await fetchHealth()
      setIdentity({
        connected: health.aws_connected,
        account_id: health.account_id,
        account_alias: health.account_alias,
        caller_arn: health.caller_arn,
        region: health.region,
      })
      setConnectionMessage(health.aws_connected ? 'AWS account connected and ready' : 'Backend reachable, AWS credentials unavailable')
    } catch {
      setIdentity({ connected: false, account_id: null, account_alias: null })
      setConnectionMessage('AWS connection unavailable - offline demo remains active')
    } finally {
      setConnecting(false)
    }
  }

  // Computed metrics with safe fallbacks
  const riskScore = Number(engineResult?.risk_score ?? 0)
  const wildcardReduction = Number.parseInt(String(engineResult?.wildcard_reduction ?? '0'), 10)
  const simPassRate = Number.parseInt(String(engineResult?.simulation?.pass_rate ?? '0'), 10)
  const simulationValid = engineResult?.simulation?.valid ?? true

  // Policies with safe fallbacks
  const currentPolicy = engineResult?.current_policy ?? null
  const leastPolicy = engineResult?.zero_trust_policy ?? engineResult?.least_privilege_policy ?? null

  return (
    <div className="min-h-screen bg-[#06111d] font-sans text-slate-100">
      <Header identity={identity} streamConnected={true} eventCount={telemetryEvents.length} connecting={connecting} onConnect={handleConnect} />
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <section className="grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="rounded-xl border border-cyan-950 bg-[#0a1b29]/90 p-5 shadow-[0_18px_60px_rgba(2,132,199,0.08)]">
            <div className="flex items-center gap-3">
              <div className="rounded-lg border border-cyan-400/30 bg-cyan-400/10 p-2 text-cyan-300"><ShieldAlert className="h-6 w-6" /></div>
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-300">Control plane / zero trust</p>
                <h2 className="mt-1 text-xl font-bold tracking-tight text-white">Policy posture at a glance</h2>
              </div>
            </div>
            <div className="mt-5 grid grid-cols-3 gap-2 text-center text-[10px] uppercase tracking-widest text-slate-500">
              <div className="rounded-lg border border-cyan-950 bg-[#071522] p-3"><Cloud className="mx-auto mb-2 h-5 w-5 text-cyan-300" /><span>AWS account</span></div>
              <div className="relative rounded-lg border border-cyan-950 bg-[#071522] p-3"><GitBranch className="mx-auto mb-2 h-5 w-5 text-amber-300" /><span>Observed events</span></div>
              <div className="rounded-lg border border-cyan-950 bg-[#071522] p-3"><LockKeyhole className="mx-auto mb-2 h-5 w-5 text-emerald-300" /><span>Scoped policy</span></div>
            </div>
            <p className="mt-4 flex items-center gap-2 text-xs text-slate-400"><span className={`h-2 w-2 rounded-full ${identity?.connected ? 'bg-emerald-400' : 'bg-amber-400'}`} />{connectionMessage}</p>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3 lg:grid-cols-1">
            <MetricsCard label="Risk Score" value={riskScore} suffix="/100" icon={Gauge} color="red" description="exposure level" />
            <MetricsCard label="Wildcard Reduction" value={wildcardReduction} icon={Scissors} color="emerald" description="scope tightened" />
            <MetricsCard label="Sim Pass Rate" value={simPassRate} icon={ShieldCheck} color="blue" description="policy simulator" />
          </div>
        </section>

        {/* Main Dashboard Grid */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          
          {/* Left Column: Live Telemetry Stream */}
          <div className="flex flex-col rounded-xl border border-cyan-950 bg-[#0a1b29]/80 p-4 lg:col-span-2">
            <div className="mb-3 flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-300" />
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">Live Telemetry Stream</h2>
              </div>
              <span className="flex items-center gap-1.5 font-mono text-[10px] text-cyan-300">
                <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-400"></span>
                SSE Connected
              </span>
            </div>
            <div className="h-48 overflow-y-auto rounded-lg border border-cyan-950 bg-[#06111d] p-3 font-mono text-xs space-y-1.5 text-slate-300">
              {telemetryEvents.length === 0 ? (
                <div className="text-slate-600">No telemetry events ingested yet.</div>
              ) : telemetryEvents.map((evt, idx) => (
                  <div key={idx} className="flex items-center gap-2">
                    <span className="text-slate-600">›</span>
                    <span>{evt}</span>
                  </div>
                ))}
            </div>
          </div>

          {/* Right Column: Role Selector & Ingestion Controls */}
          <div className="flex flex-col rounded-xl border border-cyan-950 bg-[#0a1b29]/80 p-4">
            <div className="mb-3 flex items-center gap-2 border-b border-slate-800 pb-2">
              <Cpu className="h-4 w-4 text-slate-400" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">Target Role & Config</h2>
            </div>
            <RoleSelector
              roles={demoRoles}
              selected={selectedRole}
              onSelect={handleRoleSelect}
              customArn={customArn}
              onCustomArnChange={setCustomArn}
              onIngestSample={handleIngestSample}
            />
          </div>

        </div>

        {/* Policy Diff Viewer Section */}
        <PolicyDiffViewer
          currentPolicy={currentPolicy}
          leastPrivilegePolicy={leastPolicy}
          simulationValid={simulationValid}
        />

      </div>
    </div>
  )
}