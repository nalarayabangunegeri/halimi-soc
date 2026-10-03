// Types mirroring the HalimiSOC API contract.
//
// They are written by hand rather than generated, deliberately: a generator would
// make it easy to accept a server change without noticing, and these types are the
// place a contract change should surface as a compile error in the UI.

export type Severity = 'low' | 'medium' | 'high' | 'critical'

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical']

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'DISMISSED'

export type IncidentStatus =
  | 'NEW'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'CLOSED'
  | 'FALSE_POSITIVE'

export interface Network {
  src_ip?: string
  src_port?: number
  dst_ip?: string
  dst_port?: number
  protocol?: string
}

export interface Event {
  id: string
  schema_version: string
  type: string
  time: string
  received_at: string
  observed_at: string
  host: string
  agent_id?: string
  source: string
  source_path?: string
  actor?: string
  target?: string
  network?: Network
  outcome?: string
  severity: Severity
  attributes?: Record<string, string>
  message?: string
  raw?: string
}

export interface Alert {
  id: string
  rule_id: string
  rule_version: number
  rule_name: string
  severity: Severity
  status: AlertStatus
  title: string
  reason: string
  host?: string
  actor?: string
  src_ip?: string
  entity?: string
  event_ids: string[]
  count: number
  window_start: string
  window_end: string
  dedupe_key: string
  created_at: string
  updated_at: string
}

export interface IncidentStage {
  name: string
  alert_id: string
  rule_id: string
  at: string
  severity: Severity
}

export interface Incident {
  id: string
  title: string
  summary: string
  severity: Severity
  status: IncidentStatus
  hosts: string[]
  actors: string[]
  source_ips?: string[]
  alert_ids: string[]
  event_ids: string[]
  stages: IncidentStage[]
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
}

export interface Agent {
  id: string
  host: string
  version?: string
  os?: string
  status: 'ONLINE' | 'OFFLINE' | 'DEGRADED' | 'UNKNOWN'
  enrolled_at: string
  last_heartbeat: string
  revoked_at?: string
  queue_depth: number
  spool_bytes: number
}

export interface AlertPage {
  alerts: Alert[]
  next_cursor?: string
}

export interface EventPage {
  events: Event[]
  next_cursor?: string
}

export interface IncidentPage {
  incidents: Incident[]
  next_cursor?: string
}

export interface RuleView {
  id: string
  version: number
  name: string
  description: string
  severity: Severity
  group_by: string[]
  threshold: { count: number; window: string }
  requires?: string
}

export interface Summary {
  events_total: number
  alerts_by_severity: Record<string, number>
  open_incidents: number
  agents_total: number
  agents_online: number
  rules_loaded: number
  detection_state_size: number
  ai_enabled: boolean
}

export interface AuditEntry {
  id: string
  actor: string
  action: string
  resource: string
  resource_id: string
  result: 'success' | 'failure' | 'denied'
  timestamp: string
  source_ip?: string
  detail?: string
}

export interface AnalysisEvidenceItem {
  kind: 'ALERT' | 'EVENT' | 'INCIDENT' | 'AGENT'
  id: string
  timestamp: string
  summary: string
  detail?: string
}

export interface Analysis {
  incident_id: string
  analysis: string
  mode: 'DISABLED' | 'PROVIDER' | 'UNAVAILABLE' | 'REJECTED'
  grounded: boolean
  evidence: AnalysisEvidenceItem[]
  provider?: string
  advisory: boolean
}

export interface SessionInfo {
  user: { id: string; username: string; role: 'ADMIN' | 'ANALYST' | 'READONLY' }
  csrf_token: string
  expires_at: string
}

/** The single error envelope the API returns. */
export interface ApiErrorBody {
  error: { code: string; message: string }
}

/** Incident transitions the UI offers, mirroring the server state machine. */
export const INCIDENT_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  NEW: ['ACKNOWLEDGED', 'INVESTIGATING', 'FALSE_POSITIVE'],
  ACKNOWLEDGED: ['INVESTIGATING', 'FALSE_POSITIVE'],
  INVESTIGATING: ['CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'],
  CONTAINED: ['RESOLVED', 'FALSE_POSITIVE'],
  RESOLVED: ['CLOSED'],
  CLOSED: [],
  FALSE_POSITIVE: [],
}

/** Alert transitions the UI offers, mirroring the server state machine. */
export const ALERT_TRANSITIONS: Record<AlertStatus, AlertStatus[]> = {
  OPEN: ['ACKNOWLEDGED', 'RESOLVED', 'DISMISSED'],
  ACKNOWLEDGED: ['RESOLVED', 'DISMISSED'],
  RESOLVED: [],
  DISMISSED: [],
}
