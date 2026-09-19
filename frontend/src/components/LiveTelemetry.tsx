import { useEffect, useRef } from 'react'
import { Terminal, CircleStop, Trash2 } from 'lucide-react'
import type { TelemetryEvent } from '../types'

interface LiveTelemetryProps {
  events: TelemetryEvent[]
  connected: boolean
  onClear: () => void
}

function tsToClock(ts: string): string {
  try {
    return new Date(ts).toLocaleTimeString([], { hour12: false })
  } catch {
    return ts
  }
}

function eventColor(evt: TelemetryEvent): string {
  if (evt.type === 'remediation') return evt.success ? 'text-emerald-400' : 'text-red-400'
  if (evt.error_code) return 'text-amber-400'
  return 'text-slate-300'
}

function eventBodyText(evt: TelemetryEvent): string {
  if (evt.type === 'remediation') {
    const steps = (evt.steps ?? []).map((s) => ` ${s.step}:${s.status}`).join('')
    return `[REMEDIATE] ${evt.role_arn ?? ''} ${evt.success ? 'SUCCESS' : 'FAILED'}${steps}`
  }
  const parts: string[] = []
  parts.push(`[${(evt.service ?? 'svc').toUpperCase()}] ${evt.event_name ?? evt.action ?? ''}`)
  if (evt.role_arn) parts.push(`by ${evt.role_arn.split('/').pop()}`)
  if (evt.resource) parts.push(`-> ${evt.resource}`)
  if (evt.risk_score != null) parts.push(`risk=${evt.risk_score}`)
  if (evt.wildcard_reduction != null) parts.push(`wildcards-${evt.wildcard_reduction}%`)
  if (evt.error_code) parts.push(`ERR=${evt.error_code}`)
  return parts.join(' ')
}

export default function LiveTelemetry({ events, connected, onClear }: LiveTelemetryProps) {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [events])

  return (
    <section className="flex h-full min-h-[280px] flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-900 px-4 py-2.5">
        <Terminal className="h-4 w-4 text-emerald-400" />
        <h2 className="text-sm font-semibold text-slate-200">Live Telemetry</h2>
        <span className="text-[10px] uppercase tracking-widest text-slate-500">
          cloudtrail to eventbridge
        </span>
        <div className="ml-auto flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 zt-live-dot' : 'bg-slate-600'}`}
            title={connected ? 'stream connected' : 'stream disconnected'}
          />
          <button
            onClick={onClear}
            className="rounded p-1 text-slate-500 transition-colors hover:bg-slate-800 hover:text-slate-300"
            title="clear log"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="zt-scroll zt-scanlines flex-1 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed"
      >
        {events.length === 0 ? (
          <p className="text-slate-600">
            <span className="text-emerald-500">$</span> awaiting CloudTrail events
            <span className="zt-live-dot ml-1 inline-block h-2 w-2 rounded-full bg-emerald-500 align-middle" />
          </p>
        ) : (
          events.map((evt, i) => (
            <div key={evt.event_id ?? `${evt.ts}-${i}`} className="py-0.5">
              <span className="text-slate-600">{tsToClock(evt.ts)}</span>{' '}
              <span className={eventColor(evt)}>{eventBodyText(evt)}</span>
            </div>
          ))
        )}
      </div>

      {connected && (
        <div className="flex items-center gap-2 border-t border-slate-800 bg-slate-900 px-4 py-1.5 text-[10px] text-slate-500">
          <CircleStop className="h-3 w-3 text-emerald-500" />
          SSE /api/v1/telemetry/stream | keep-alive 15s
        </div>
      )}
    </section>
  )
}
