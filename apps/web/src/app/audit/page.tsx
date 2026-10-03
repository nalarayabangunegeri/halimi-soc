import { Shell } from '@/components/Shell'
import { EmptyState } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { ApiError, listAudit } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatTime, humanizeEnum } from '@/lib/format'

// The audit log.
//
// Admin-only: the API enforces view_audit server-side, so a non-admin sees an
// explicit permission-denied state here rather than an empty log. An empty log
// shown to someone without permission would be a lie about what happened.
export const dynamic = 'force-dynamic'

export default async function AuditPage() {
  const session = await requireSession()

  let entries: Awaited<ReturnType<typeof listAudit>>['entries'] = []
  let error: unknown = null

  try {
    const result = await listAudit(session, { limit: 50 })
    entries = result.entries
  } catch (cause) {
    error = cause
  }

  const denied = error instanceof ApiError && error.status === 403

  return (
    <Shell
      title="Audit log"
      subtitle="Security-sensitive operations, newest first"
      username={session.username}
      role={session.role}
      active="audit"
    >
      {error ? <ErrorBanner error={error} /> : null}

      {denied ? (
        <div className="card">
          <EmptyState
            title="Permission denied"
            hint="The audit log is visible to ADMIN operators only. Your role does not permit this view."
          />
        </div>
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">Recent entries</h2>
            <span className="dim" style={{ fontSize: 12 }}>
              Stored alongside operational data; not tamper-proof forensic storage.
            </span>
          </div>

          {entries.length === 0 && !error ? (
            <EmptyState
              title="No audit entries"
              hint="Logins, enrollments, status changes and analysis requests appear here."
            />
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Resource</th>
                    <th>Result</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((entry) => (
                    <tr key={entry.id}>
                      <td className="nowrap muted">{formatTime(entry.timestamp)}</td>
                      <td className="mono">{entry.actor}</td>
                      <td className="mono nowrap">{humanizeEnum(entry.action)}</td>
                      <td className="mono">
                        {entry.resource}
                        {entry.resource_id ? <div className="dim" style={{ fontSize: 11 }}>{entry.resource_id}</div> : null}
                      </td>
                      <td>{entry.result}</td>
                      <td className="dim">{entry.detail || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </Shell>
  )
}
