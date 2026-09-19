// Shared types for the Zero-Trust IAM Policy Engine Dashboard.

export interface AwsIdentity {
  connected: boolean
  account_id: string | null
  account_alias?: string | null
  caller_arn?: string | null
  region?: string
}

export interface RoleInfo {
  role_name: string
  arn: string
  path?: string
  description?: string | null
}

export interface TelemetryEvent {
  type: 'event' | 'remediation' | 'hello'
  ts: string
  event_id?: string | null
  event_name?: string | null
  event_source?: string | null
  service?: string | null
  action?: string | null
  role_arn?: string | null
  resource?: string | null
  error_code?: string | null
  risk_score?: number | null
  wildcard_reduction?: number | null
  simulated?: boolean | null
  success?: boolean
  steps?: { step: string; status: string; detail: string }[]
}

export interface PolicyDocument {
  Version?: string
  Id?: string
  Statement: Record<string, unknown>[]
  [key: string]: unknown
}

export interface EngineResult {
  parsed?: {
    event_id?: string
    event_name?: string
    event_source?: string
    service?: string
    action?: string
    role_arn?: string
    resource?: string
    error_code?: string
  }
  current_evaluation?: { allowed: string[]; denied: string[]; error?: string }
  current_policy?: {
    role_name: string
    policies: { type: string; name: string; arn?: string | null }[]
    document: PolicyDocument
    statement_count: number
    wildcard_actions: number
    total_actions: number
    candidate_detach_arn?: string
    candidate_detach_name?: string
  }
  risk_score?: number
  least_privilege_policy?: PolicyDocument
  simulation?: { valid: boolean; allowed: string[]; denied: string[]; error?: string }
  wildcard_reduction?: number
  note?: string
}

export interface SimulationResult {
  custom_policy_simulation: { valid: boolean; allowed: string[]; denied: string[]; error?: string }
  current_principal_simulation: { allowed: string[]; denied: string[]; error?: string } | null
  role_arn: string
  actions_tested: string[]
}

export interface RemediationResult {
  success: boolean
  role_arn: string
  policy_name: string
  steps: { step: string; status: string; detail: string }[]
}
