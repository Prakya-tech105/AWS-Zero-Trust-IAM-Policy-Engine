import { useState } from 'react'
import { FlaskConical, Wrench, Loader2, CheckCircle2, XCircle } from 'lucide-react'
import { simulatePolicy, remediatePolicy } from '../api'
import type { PolicyDocument, SimulationResult, RemediationResult } from '../types'

interface ActionsProps {
  roleArn: string | null
  currentPolicy: PolicyDocument | null
  leastPrivilegePolicy: PolicyDocument | null
  candidateDetachArn?: string | null
  onRemediated: () => void
}

export default function Actions({
  roleArn,
  currentPolicy,
  leastPrivilegePolicy,
  candidateDetachArn,
  onRemediated,
}: ActionsProps) {
  const [busy, setBusy] = useState<'simulate' | 'remediate' | null>(null)
  const [simResult, setSimResult] = useState<SimulationResult | null>(null)
  const [remResult, setRemResult] = useState<RemediationResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const actionsUnderTest = ['s3:ListBuckets', 's3:GetObject']

  async function runSimulation() {
    if (!roleArn || !currentPolicy) return
    setBusy('simulate')
    setError(null)
    setSimResult(null)
    try {
      const result = await simulatePolicy(roleArn, currentPolicy, actionsUnderTest)
      setSimResult(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  async function runRemediation() {
    if (!roleArn || !leastPrivilegePolicy) return
    setBusy('remediate')
    setError(null)
    setRemResult(null)
    try {
      const result = await remediatePolicy(roleArn, leastPrivilegePolicy, candidateDetachArn)
      setRemResult(result)
      if (result.success) onRemediated()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const disabled = !roleArn

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={runSimulation}
          disabled={disabled || busy !== null}
          className="inline-flex items-center gap-2 rounded-lg border border-sky-500/40 bg-sky-500/10 px-4 py-2 text-sm font-semibold text-sky-300 transition-colors hover:bg-sky-500/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy === 'simulate' ? <Loader2 className="h-4 w-4 animate-spin" /> : <FlaskConical className="h-4 w-4" />}
          Run Policy Simulator Test
        </button>

        <button
          onClick={runRemediation}
          disabled={disabled || busy !== null}
          className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-4 py-2 text-sm font-semibold text-emerald-300 transition-colors hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy === 'remediate' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
          Enforce Zero-Trust Policy
        </button>

        <span className="text-xs text-slate-500">
          {roleArn ? (
            <>target: <span className="font-mono text-slate-400">{roleArn}</span></>
          ) : (
            'ingest a CloudTrail event to select a role'
          )}
        </span>
      </div>

      {error && (
        <div className="mt-3 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-300">
          <XCircle className="mr-1 inline h-3.5 w-3.5" /> {error}
        </div>
      )}

      {simResult && (
        <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs">
          <div className="mb-1 font-semibold uppercase tracking-widest text-slate-500">Simulator result</div>
          <div className="font-mono">
            <div>custom: {simResult.custom_policy_simulation.valid ? <span className="text-emerald-400">PASS</span> : <span className="text-red-400">FAIL</span>}</div>
            {simResult.custom_policy_simulation.denied.length > 0 && (
              <div className="text-red-400">denied: {simResult.custom_policy_simulation.denied.join(', ')}</div>
            )}
            {simResult.current_principal_simulation && (
              <div className="text-slate-400">
                current role: {simResult.current_principal_simulation.allowed.length > 0
                  ? <span className="text-amber-400">allows {simResult.current_principal_simulation.allowed.join(', ')}</span>
                  : 'allows none of the tested actions'}
              </div>
            )}
          </div>
        </div>
      )}

      {remResult && (
        <div className="mt-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs font-mono">
          <div className={`mb-1 font-semibold ${remResult.success ? 'text-emerald-400' : 'text-red-400'}`}>
            {remResult.success ? 'Remediation applied' : 'Remediation failed'}
          </div>
          {remResult.steps.map((s) => (
            <div key={s.step}>
              <CheckCircle2 className="mr-1 inline h-3 w-3 text-emerald-500" />
              {s.step}: {s.status} — <span className="text-slate-400">{s.detail}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
