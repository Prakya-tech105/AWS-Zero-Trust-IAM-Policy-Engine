import { Cloud, CloudOff, ShieldCheck, Radio } from 'lucide-react'
import type { AwsIdentity } from '../types'

interface HeaderProps {
  identity: AwsIdentity | null
  streamConnected: boolean
  eventCount: number
}

export default function Header({ identity, streamConnected, eventCount }: HeaderProps) {
  const awsConnected = identity?.connected ?? false

  return (
    <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-4 px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg border border-emerald-500/40 bg-emerald-500/10">
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-slate-100">
              Zero-Trust IAM Policy Engine
            </h1>
            <p className="text-xs text-slate-500">
              CloudTrail → EventBridge → Policy Simulator → Auto-Remediation
            </p>
          </div>
          <span className="ml-2 hidden rounded border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-widest text-amber-400 sm:inline">
            Hackathon Build
          </span>
        </div>

        <div className="ml-auto flex items-center gap-3">
          {/* Event throughput */}
          <div className="hidden items-center gap-1.5 rounded-md border border-slate-800 bg-slate-900 px-3 py-1.5 sm:flex">
            <Radio className="h-3.5 w-3.5 text-slate-400" />
            <span className="text-xs text-slate-400">
              events: <span className="font-mono text-slate-200">{eventCount}</span>
            </span>
          </div>

          {/* SSE stream status */}
          <div
            className={`flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium ${
              streamConnected
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                : 'border-slate-700 bg-slate-900 text-slate-500'
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                streamConnected ? 'bg-emerald-400 zt-live-dot' : 'bg-slate-600'
              }`}
            />
            {streamConnected ? 'LIVE' : 'OFFLINE'}
          </div>

          {/* AWS account badge */}
          <div
            className={`flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium ${
              awsConnected
                ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400'
                : 'border-red-500/40 bg-red-500/10 text-red-400'
            }`}
          >
            {awsConnected ? <Cloud className="h-3.5 w-3.5" /> : <CloudOff className="h-3.5 w-3.5" />}
            {awsConnected ? (
              <span>
                AWS <span className="font-mono">{identity?.account_alias || identity?.account_id}</span>
                {identity?.region ? ` · ${identity.region}` : ''}
              </span>
            ) : (
              <span>AWS UNAVAILABLE</span>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
