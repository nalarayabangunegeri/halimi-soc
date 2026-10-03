import Link from 'next/link'
import { Shell } from '@/components/Shell'
import { EmptyState, SeverityBadge, Stat, StatusBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { getSummary, listAlerts, listEvents, listIncidents } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatSpan, formatTime, humanizeEnum } from '@/lib/format'
import { bucketEventsByHour } from '@/lib/stats'
import { SEVERITIES } from '@/lib/types'

// The overview.
//
// It answers three questions in order: is anything on fire, what changed recently,
// and is collection healthy. Everything is fetched in parallel because an overview
// that loads in sequence is slower than its slowest query times three.

export const dynamic = 'force-dynamic'

export default async function OverviewPage() {
  const session = await requireSession()

  const [summaryResult, alertsResult, incidentsResult, eventsResult] = await Promise.allSettled([
    getSummary(session),
    listAlerts(session, { status: 'OPEN', limit: 8 }),
    listIncidents(session, { limit: 6 }),
    listEvents(session, { limit: 100 }),
  ])

  const summary = summaryResult.status === 'fulfilled' ? summaryResult.value : null
  const alerts = alertsResult.status === 'fulfilled' ? alertsResult.value.alerts : []
  const incidents = incidentsResult.status === 'fulfilled' ? incidentsResult.value.incidents : []
  const recentEvents = eventsResult.status === 'fulfilled' ? eventsResult.value.events : []
  const volume = bucketEventsByHour(
    recentEvents.map((e) => e.time),
    24,
    Date.now(),
  )
  const volumeMax = Math.max(1, ...volume.map((b) => b.count))
  const firstError =
    summaryResult.status === 'rejected'
      ? summaryResult.reason
      : alertsResult.status === 'rejected'
        ? alertsResult.reason
        : incidentsResult.status === 'rejected'
          ? incidentsResult.reason
          : null

  return (
    <Shell
      title="Overview"
      subtitle="Current security posture across monitored hosts"
      username={session.username}
      role={session.role}
      active="overview"
      counts={{
        alerts: summary ? sumSeverities(summary.alerts_by_severity) : undefined,
        incidents: summary?.open_incidents,
        agents: summary ? `${summary.agents_online}/${summary.agents_total}` as unknown as number : undefined,
      }}
      headerExtras={
        summary ? (
          <div className="header-stats">
            <Stat label="Events" value={summary.events_total} title="Normalized events retained" />
            <Stat label="Open alerts" value={sumSeverities(summary.alerts_by_severity)} />
            <Stat label="Open incidents" value={summary.open_incidents} />
            <Stat
              label="Agents"
              value={`${summary.agents_online}/${summary.agents_total}`}
              title="Online agents out of enrolled agents"
            />
            <Stat label="Rules" value={summary.rules_loaded} title="Loaded detection rules" />
            <Stat
              label="AI"
              value={summary.ai_enabled ? 'on' : 'off'}
              title={summary.ai_enabled ? 'An advisory provider is configured' : 'No provider: analysis uses the computed summary'}
            />
          </div>
        ) : null
      }
    >
      {firstError ? <ErrorBanner error={firstError} /> : null}

      {summary ? (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Alerts by severity</h2>
            <span className="dim" style={{ fontSize: 12 }}>
              Detection is deterministic; severity comes from the rule that fired.
            </span>
          </div>
          <div style={{ padding: '16px', display: 'flex', gap: 28, flexWrap: 'wrap' }}>
            {SEVERITIES.map((severity) => (
              <Link key={severity} href={`/alerts?severity=${severity}`} style={{ color: 'inherit' }}>
                <div className="stat">
                  <span className="stat-value">{summary.alerts_by_severity[severity] ?? 0}</span>
                  <span className="stat-label">
                    <SeverityBadge severity={severity} />
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      ) : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Event volume</h2>
          <span className="dim" style={{ fontSize: 12 }}>
            Last 24 hours, from the same events the explorer lists.
          </span>
        </div>
        <div style={{ padding: '16px' }} role="img" aria-label={`Event volume, peak ${volumeMax} events per hour`}>
          <svg viewBox={`0 0 ${volume.length * 14} 64`} width="100%" height="64" preserveAspectRatio="none">
            {volume.map((bucket, i) => {
              const height = Math.max(2, Math.round((bucket.count / volumeMax) * 56))
              return (
                <rect
                  key={bucket.start}
                  x={i * 14 + 2}
                  y={64 - height}
                  width="10"
                  height={height}
                  rx="2"
                  fill={bucket.count > 0 ? 'var(--accent)' : 'var(--border)'}
                >
                  <title>{`${new Date(bucket.start).toLocaleString()}: ${bucket.count} event(s)`}</title>
                </rect>
              )
            })}
          </svg>
        </div>
      </div>

      {summary ? (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Detection health</h2>
            <span className="dim" style={{ fontSize: 12 }}>
              The pipeline behind the numbers above.
            </span>
          </div>
          <div style={{ padding: '16px', display: 'flex', gap: 28, flexWrap: 'wrap' }}>
            <Stat label="Rules loaded" value={summary.rules_loaded} title="Detection refuses to run with zero rules" />
            <Stat
              label="Tracked windows"
              value={summary.detection_state_size}
              title="Bounded in-memory detection state"
            />
            <Stat
              label="AI"
              value={summary.ai_enabled ? 'on' : 'off'}
              title={summary.ai_enabled ? 'An advisory provider is configured' : 'No provider: analysis uses the computed summary'}
            />
          </div>
        </div>
      ) : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Open incidents</h2>
          <Link href="/incidents">View all →</Link>
        </div>
        {incidents.length === 0 ? (
          <EmptyState
            title="No incidents"
            hint="An incident appears when correlated alerts share a host, account or source address."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Incident</th>
                  <th>Status</th>
                  <th>Hosts</th>
                  <th>Stages</th>
                  <th>Window</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>
                      <SeverityBadge severity={incident.severity} />
                    </td>
                    <td>
                      <Link href={`/incidents/${incident.id}`}>{incident.title}</Link>
                      <div className="mono dim">{incident.id}</div>
                    </td>
                    <td>
                      <StatusBadge status={incident.status} />
                    </td>
                    <td className="mono">{incident.hosts.join(', ') || '—'}</td>
                    <td>
                      {incident.stages.length > 0
                        ? incident.stages.map((s) => humanizeEnum(s.name)).join(' → ')
                        : '—'}
                    </td>
                    <td className="nowrap dim">{formatSpan(incident.first_seen, incident.last_seen)}</td>
                    <td className="nowrap muted">{formatTime(incident.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">Open alerts</h2>
          <Link href="/alerts">View all →</Link>
        </div>
        {alerts.length === 0 ? (
          <EmptyState
            title="No open alerts"
            hint="Alerts appear when a detection rule crosses its threshold within its window."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Alert</th>
                  <th>Rule</th>
                  <th>Host</th>
                  <th>Source IP</th>
                  <th>Count</th>
                  <th>Raised</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      {alert.title}
                      <div className="mono dim">{alert.id}</div>
                    </td>
                    <td className="mono nowrap">
                      {alert.rule_id}
                      <span className="dim">@{alert.rule_version}</span>
                    </td>
                    <td className="mono">{alert.host || '—'}</td>
                    <td className="mono">{alert.src_ip || '—'}</td>
                    <td>{alert.count}</td>
                    <td className="nowrap muted">{formatTime(alert.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Shell>
  )
}

function sumSeverities(bySeverity: Record<string, number>): number {
  return Object.values(bySeverity).reduce((total, n) => total + n, 0)
}
