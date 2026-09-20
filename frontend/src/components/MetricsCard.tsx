import type { LucideIcon } from 'lucide-react'

interface MetricsCardProps {
  label: string
  value: number
  suffix?: string
  icon: LucideIcon
  color: 'red' | 'emerald' | 'blue'
  description: string
}

const colorStyles = {
  red: {
    text: 'text-red-400',
    track: 'bg-red-950',
    fill: 'bg-red-500',
  },
  emerald: {
    text: 'text-emerald-400',
    track: 'bg-emerald-950',
    fill: 'bg-emerald-500',
  },
  blue: {
    text: 'text-blue-400',
    track: 'bg-blue-950',
    fill: 'bg-blue-500',
  },
}

export default function MetricsCard({ label, value, suffix = '%', icon: Icon, color, description }: MetricsCardProps) {
  const styles = colorStyles[color]
  const progress = Math.max(0, Math.min(100, value))

  return (
    <div className="min-w-[150px] flex-1 rounded-lg border border-slate-800 bg-slate-950 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
        <Icon className={`h-3.5 w-3.5 ${styles.text}`} />
      </div>
      <div className="mt-1 flex items-baseline gap-1">
        <span className={`font-mono text-xl font-bold ${styles.text}`}>{value}</span>
        <span className="text-xs text-slate-500">{suffix}</span>
      </div>
      <div className={`mt-2 h-1.5 overflow-hidden rounded-full ${styles.track}`}>
        <div className={`h-full rounded-full transition-[width] duration-500 ${styles.fill}`} style={{ width: `${progress}%` }} />
      </div>
      <div className="mt-1 text-[9px] uppercase tracking-wider text-slate-600">{description}</div>
    </div>
  )
}