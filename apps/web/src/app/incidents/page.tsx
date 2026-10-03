import Link from 'next/link'
import { Shell } from '@/components/Shell'
import { EmptyState, SeverityBadge, StatusBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { listIncidents } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatSpan, formatTime, humanizeEnum } from '@/lib/format'

// The incident list.
//
// An incident is a correlated story, so the list shows the stages rather than only
// a status: an operator can see at a glance whether an incident reached persistence
// or stopped at credential access.

export const dynamic = 'force-dynamic'

export default async function IncidentsPage() {
  const session = await requireSession()

  let incidents: Awaited<ReturnType<typeof listIncidents>>['incidents'] = []
  let error: unknown = null

  try {
    const page = await listIncidents(session, { limit: 100 })
    incidents = page.incidents
  } catch (cause) {
    error = cause
  }

  const open = incidents.filter((i) => !['RESOLVED', 'CLOSED', 'FALSE_POSITIVE'].includes(i.status))

  return (
    <Shell
      title="Incidents"
      subtitle="Alerts correlated by shared host, account or source address"
      username={session.username}
      role={session.role}
      active="incidents"
      counts={{ incidents: open.length }}
    >
      {error ? <ErrorBanner error={error} /> : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            {incidents.length} incident{incidents.length === 1 ? '' : 's'} · {open.length} open
          </h2>
        </div>

        {incidents.length === 0 ? (
          <EmptyState
            title="No incidents"
            hint="Correlation only merges alerts that share a concrete entity. Alerts with no entity in common stay separate."
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
                  <th>Accounts</th>
                  <th>Stages</th>
                  <th>Evidence</th>
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
                    <td className="mono">{incident.actors.join(', ') || '—'}</td>
                    <td>
                      <div className="button-row">
                        {incident.stages.map((stage) => (
                          <span key={`${stage.alert_id}-${stage.name}`} className="badge badge-status">
                            {humanizeEnum(stage.name)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="nowrap dim">{incident.alert_ids.length} alert(s)</td>
                    <td className="nowrap dim">{formatSpan(incident.first_seen, incident.last_seen)}</td>
                    <td className="nowrap muted">{formatTime(incident.last_seen)}</td>
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
