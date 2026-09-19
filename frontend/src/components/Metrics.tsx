import { Gauge, Scissors, Users, ShieldCheck } from 'lucide-react'

interface MetricsProps {
  riskScore: number
  wildcardReduction: number
  auditedRoles: number
  simulationPassRate: number
}

function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400 border-red-500/40 bg-red-500/10'
  if (score >= 40) return 'text-amber-400 border-amber-500/40 bg-amber-500/10'
  return 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10'
}

export default function Metrics({ riskScore, wildcardReduction, auditedRoles, simulationPassRate }: MetricsProps) {
  const metrics = [
    {
      icon: Gauge,
      label: 'RISK SCORE',
      value: String(riskScore),
      suffix: '/100',
      cls: riskColor(riskScore),
      sub: riskScore >= 75 ? 'CRITICAL' : riskScore >= 40 ? 'ELEVATED' : 'LOW',
    },
    {
      icon: Scissors,
      label: 'WILDCARD REDUCTION',
      value: String(wildcardReduction),
      suffix: '%',
      cls: 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10',
      sub: 'scope tightened',
    },
    {
      icon: Users,
      label: 'ROLES AUDITED',
      value: String(auditedRoles),
      suffix: '',
      cls: 'text-sky-400 border-sky-500/40 bg-sky-500/10',
      sub: 'in scope',
    },
    {
      icon: ShieldCheck,
      label: 'SIM PASS RATE',
      value: String(simulationPassRate),
      suffix: '%',
      cls: 'text-violet-400 border-violet-500/40 bg-violet-500/10',
      sub: 'policy simulator',
    },
  ]

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
      {metrics.map((m) => (
        <div
          key={m.label}
          className={`rounded-xl border p-4 transition-colors ${m.cls}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-widest opacity-80">{m.label}</span>
            <m.icon className="h-4 w-4 opacity-70" />
          </div>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="font-mono text-3xl font-bold">{m.value}</span>
            <span className="text-sm opacity-70">{m.suffix}</span>
          </div>
          <div className="mt-1 text-[10px] uppercase tracking-wider opacity-60">{m.sub}</div>
        </div>
      ))}
    </div>
  )
}
