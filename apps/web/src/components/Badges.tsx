import type { AlertStatus, IncidentStatus, Severity } from '@/lib/types'
import { humanizeEnum } from '@/lib/format'

// Presentation of the enum contracts.
//
// The components accept the server's enum values and never invent their own. If
// the server gains a severity, this renders it with the neutral style rather than
// crashing, and the mismatch shows up as an unstyled badge instead of a blank page.

export function SeverityBadge({ severity }: { severity: Severity | string }) {
  const known = ['low', 'medium', 'high', 'critical'].includes(severity)
  return (
    <span className={`badge ${known ? `badge-${severity}` : 'badge-status'}`}>{String(severity)}</span>
  )
}

export function StatusBadge({ status }: { status: AlertStatus | IncidentStatus | string }) {
  return <span className="badge badge-status">{humanizeEnum(String(status))}</span>
}

const DOT_CLASS: Record<string, string> = {
  ONLINE: 'dot-online',
  OFFLINE: 'dot-offline',
  DEGRADED: 'dot-degraded',
  UNKNOWN: 'dot-unknown',
}

export function AgentStatus({ status }: { status: string }) {
  const dot = DOT_CLASS[status] ?? 'dot-unknown'
  return (
    <span className="nowrap">
      <span className={`status-dot ${dot}`} aria-hidden="true" />
      {humanizeEnum(status)}
    </span>
  )
}

/** A labelled counter for the header. */
export function Stat({ label, value, title }: { label: string; value: string | number; title?: string }) {
  return (
    <div className="stat" title={title}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  )
}

/** The empty state. It always explains what would appear, never just "no data". */
export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="empty">
      <div>{title}</div>
      {hint ? <div className="dim" style={{ marginTop: 6, fontSize: 12 }}>{hint}</div> : null}
    </div>
  )
}
