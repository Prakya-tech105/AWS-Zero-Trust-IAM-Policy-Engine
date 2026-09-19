import { useState } from 'react'
import { Download, Send } from 'lucide-react'
import type { RoleInfo } from '../types'

interface RoleSelectorProps {
  roles: RoleInfo[]
  selected: string | null
  onSelect: (arn: string | null) => void
  onIngestSample: (detail: unknown) => void
}

function sampleEvent(roleArn: string): unknown {
  return {
    eventVersion: '1.09',
    eventSource: 's3.amazonaws.com',
    eventName: 'GetObject',
    eventTime: new Date().toISOString(),
    awsRegion: 'us-east-1',
    sourceIPAddress: '203.0.113.42',
    eventID: crypto.randomUUID(),
    requestID: crypto.randomUUID(),
    role_arn: roleArn,
    userIdentity: {
      type: 'AssumedRole',
      arn: roleArn,
      sessionContext: {
        sessionIssuer: {
          type: 'Role',
          arn: roleArn,
        },
      },
    },
    requestParameters: { bucketName: 'demo-sensitive-bucket', key: 'reports/q3.pdf' },
    errorCode: null,
  }
}

export default function RoleSelector({ roles, selected, onSelect, onIngestSample }: RoleSelectorProps) {
  const [customArn, setCustomArn] = useState('')

  const handleIngestCustom = () => {
    const trimmed = customArn.trim()
    if (!trimmed) return

    if (trimmed.startsWith('{')) {
      try {
        onIngestSample(JSON.parse(trimmed))
      } catch (err) {
        console.error('Failed to parse pasted JSON payload:', err)
      }
    } else {
      onIngestSample(sampleEvent(trimmed))
    }
  }

  return (
    <section className="flex h-full flex-col rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-3 flex items-center gap-2">
        <Download className="h-4 w-4 text-sky-400" />
        <h2 className="text-sm font-semibold text-slate-200">Target Role</h2>
      </div>

      <select
        value={selected ?? ''}
        onChange={(e) => onSelect(e.target.value || null)}
        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 focus:border-emerald-500 focus:outline-none"
      >
        <option value="">— select role —</option>
        {roles.map((r) => (
          <option key={r.arn} value={r.arn}>
            {r.role_name}
          </option>
        ))}
      </select>

      <div className="mt-3">
        <label className="mb-1 block text-[10px] uppercase tracking-widest text-slate-500">
          or paste role ARN / JSON payload
        </label>
        <textarea
          value={customArn}
          onChange={(e) => setCustomArn(e.target.value)}
          placeholder="arn:aws:iam::123456789012:role/MyRole OR paste JSON"
          rows={3}
          className="w-full resize-none rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs text-slate-200 placeholder-slate-600 focus:border-emerald-500 focus:outline-none"
        />
      </div>

      <div className="mt-auto space-y-2 pt-4">
  <button
    onClick={() => {
      const arnToUse = selected || 'arn:aws:iam::123456789012:role/TargetApp-OverPrivileged-Role'
      onIngestSample(sampleEvent(arnToUse))
    }}
    className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-xs font-semibold text-slate-300 transition-colors hover:border-emerald-500/50 hover:text-emerald-300"
  >
    <Send className="h-3.5 w-3.5" />
    Inject sample CloudTrail event
  </button>

  {customArn.trim() && (
    <button
      onClick={() => {
        const trimmed = customArn.trim()
        if (!trimmed) return

        if (trimmed.startsWith('{')) {
          try {
            onIngestSample(JSON.parse(trimmed))
          } catch (err) {
            console.error('Failed to parse pasted JSON payload:', err)
          }
        } else {
          onIngestSample(sampleEvent(trimmed))
        }
      }}
      className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs font-semibold text-amber-300 transition-colors hover:bg-amber-500/20"
    >
      <Send className="h-3.5 w-3.5" />
      Ingest for pasted ARN / Payload
    </button>
  )}
</div>
    </section>
  )
}