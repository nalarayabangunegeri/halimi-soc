import Link from 'next/link'
import { notFound } from 'next/navigation'
import { Shell } from '@/components/Shell'
import { SeverityBadge, StatusBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { IncidentControls } from '@/components/IncidentControls'
import { AnalysisPanel } from '@/components/AnalysisPanel'
import { getIncident, ApiError } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatTime, humanizeEnum } from '@/lib/format'

// The incident detail view.
//
// This is the page the product exists for: what happened, in what order, with what
// evidence, and what an analyst can do about it. It states the correlation basis
// explicitly, because "why are these alerts one incident" is the question that
// decides whether an operator trusts the grouping.

export const dynamic = 'force-dynamic'

export default async function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requireSession()
  const { id } = await params

  let incident: Awaited<ReturnType<typeof getIncident>> | null = null
  let error: unknown = null

  try {
    incident = await getIncident(session, id)
  } catch (cause) {
    // A missing incident is a 404 page, not an error banner: the operator
    // followed a stale link, which is not a failure worth alarming them about.
    if (cause instanceof ApiError && cause.status === 404) notFound()
    error = cause
  }

  const canMutate = session.role === 'ADMIN' || session.role === 'ANALYST'

  return (
    <Shell
      title={incident?.title ?? 'Incident'}
      subtitle={incident ? incident.id : undefined}
      username={session.username}
      role={session.role}
      active="incidents"
    >
      {error ? <ErrorBanner error={error} /> : null}

      {incident ? (
        <>
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">
                <SeverityBadge severity={incident.severity} /> <StatusBadge status={incident.status} />
              </h2>
              {canMutate ? <IncidentControls id={incident.id} status={incident.status} /> : null}
            </div>
            <div style={{ padding: 16 }}>
              <div style={{ display: 'flex', gap: 40, flexWrap: 'wrap' }}>
                <Detail label="Hosts" value={incident.hosts.join(', ') || '—'} />
                <Detail label="Accounts" value={incident.actors.join(', ') || '—'} />
                <Detail label="First seen" value={formatTime(incident.first_seen)} />
                <Detail label="Last seen" value={formatTime(incident.last_seen)} />
                <Detail label="Alerts" value={String(incident.alert_ids.length)} />
                <Detail label="Events" value={String(incident.event_ids.length)} />
              </div>
              <p className="muted" style={{ marginTop: 16, marginBottom: 0 }}>
                {incident.summary}
              </p>
              <p className="dim" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
                Correlation basis: alerts joined this incident because they share a host, account or source
                address within the correlation window. Alerts with no entity in common are never merged.
              </p>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Timeline</h2>
              <span className="dim" style={{ fontSize: 12 }}>
                Stages are derived from the rule that fired, in detection order.
              </span>
            </div>
            {incident.stages.length === 0 ? (
              <div className="empty">No stages recorded.</div>
            ) : (
              <ul className="timeline">
                {incident.stages.map((stage, index) => (
                  <li className="timeline-item" key={`${stage.alert_id}-${stage.name}-${index}`}>
                    <div>
                      <div className="timeline-time">{formatTime(stage.at)}</div>
                      <SeverityBadge severity={stage.severity} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600 }}>{humanizeEnum(stage.name)}</div>
                      <div className="mono dim">{stage.rule_id}</div>
                      <div className="mono dim" style={{ fontSize: 11 }}>
                        alert {stage.alert_id}
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <AnalysisPanel incidentId={incident.id} />

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Evidence</h2>
              <span className="dim" style={{ fontSize: 12 }}>
                {incident.alert_ids.length} alert(s) · {incident.event_ids.length} event(s)
              </span>
            </div>
            <div style={{ padding: 16 }}>
              <div className="button-row">
                {incident.alert_ids.map((alertId) => (
                  <Link key={alertId} href={`/alerts?rule_id=`} className="mono">
                    <span className="badge badge-status">{alertId}</span>
                  </Link>
                ))}
              </div>
              <details style={{ marginTop: 16 }}>
                <summary className="muted" style={{ cursor: 'pointer', fontSize: 13 }}>
                  Event identifiers ({incident.event_ids.length})
                </summary>
                <div className="mono dim" style={{ marginTop: 8, fontSize: 11, lineHeight: 1.8 }}>
                  {incident.event_ids.join('\n')}
                </div>
              </details>
            </div>
          </div>
        </>
      ) : null}
    </Shell>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="stat-label">{label}</div>
      <div className="mono">{value}</div>
    </div>
  )
}
