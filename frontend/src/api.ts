// Thin API client over the FastAPI backend. In dev, Vite proxies /api -> :8000.

import type {
  EngineResult,
  RemediationResult,
  RoleInfo,
  SimulationResult,
} from './types'

const BASE = '/api/v1'

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const body = await res.json()
      detail = body.detail ? (typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)) : detail
    } catch {
      /* keep default */
    }
    throw new Error(detail)
  }
  return res.json() as Promise<T>
}

export async function fetchHealth() {
  return handle<{
    status: string
    aws_connected: boolean
    account_id: string | null
    account_alias: string | null
    caller_arn: string | null
    region: string
  }>(await fetch(`${BASE}/health`))
}

export async function fetchRoles(limit = 25): Promise<RoleInfo[]> {
  const data = await handle<{ roles: RoleInfo[]; count: number }>(
    await fetch(`${BASE}/roles?limit=${limit}`),
  )
  return data.roles
}

export async function fetchRolesDemo(): Promise<RoleInfo[]> {
  const data = await handle<{ roles: RoleInfo[]; count: number; demo: boolean }>(
    await fetch(`${BASE}/roles?demo=1&limit=25`),
  )
  return data.roles
}

export async function ingestEvent(detail: unknown): Promise<EngineResult> {
  // If detail is an object containing an inner detail property, extract it;
  // otherwise, use detail directly at the root.
  const payload = 
    typeof detail === 'object' && detail !== null && 'detail' in detail 
      ? (detail as { detail: unknown }).detail 
      : detail

  return handle<EngineResult>(
    await fetch(`${BASE}/events/ingest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  )
}

export async function simulatePolicy(
  roleArn: string,
  policyDocument: Record<string, unknown>,
  actionNames: string[],
): Promise<SimulationResult> {
  return handle<SimulationResult>(
    await fetch(`${BASE}/policy/simulate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role_arn: roleArn,
        policy_document: policyDocument,
        action_names: actionNames,
      }),
    }),
  )
}

export async function remediatePolicy(
  roleArn: string,
  policyDocument: Record<string, unknown>,
  detachArn?: string | null,
): Promise<RemediationResult> {
  return handle<RemediationResult>(
    await fetch(`${BASE}/policy/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role_arn: roleArn,
        policy_document: policyDocument,
        detach_arn: detachArn ?? null,
      }),
    }),
  )
}

// ---------------------------------------------------------------------------
// SSE telemetry
// ---------------------------------------------------------------------------
export interface StreamHandlers {
  onEvent: (evt: TelemetryEventLike) => void
  onOpen?: () => void
  onError?: (err: Event) => void
}

export interface TelemetryEventLike {
  type: string
  ts: string
  [key: string]: unknown
}

export function openTelemetryStream(handlers: StreamHandlers): EventSource {
  const es = new EventSource(`${BASE}/telemetry/stream`)
  es.onopen = () => handlers.onOpen?.()
  es.onerror = (err) => handlers.onError?.(err)
  es.onmessage = (msg) => {
    try {
      handlers.onEvent(JSON.parse(msg.data))
    } catch {
      /* ignore malformed frames */
    }
  }
  return es
}

// Import placed last to keep the type-only import list tidy.
import type { TelemetryEvent } from './types'
export type { TelemetryEvent }
