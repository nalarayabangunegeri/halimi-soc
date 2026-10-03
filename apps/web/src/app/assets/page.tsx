import { Shell } from '@/components/Shell'
import { AgentStatus, EmptyState } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { listAssets } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatTime } from '@/lib/format'

// The asset inventory.
//
// Assets are derived from enrolled agents and their events, not from a
// separate CMDB: what is shown here is exactly what the platform has observed.
// An asset the agent never reported on appears with the event count as its only
// evidence, which is honest about the platform's visibility.
export const dynamic = 'force-dynamic'

export default async function AssetsPage() {
  const session = await requireSession()

  let assets: Awaited<ReturnType<typeof listAssets>>['assets'] = []
  let error: unknown = null

  try {
    const result = await listAssets(session)
    assets = result.assets
  } catch (cause) {
    error = cause
  }

  const online = assets.filter((a) => a.status === 'ONLINE').length

  return (
    <Shell
      title="Assets"
      subtitle="Monitored hosts and their collection health"
      username={session.username}
      role={session.role}
      active="assets"
      counts={{ agents: assets.length }}
    >
      {error ? <ErrorBanner error={error} /> : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">
            {assets.length} asset(s) · {online} online
          </h2>
          <span className="dim" style={{ fontSize: 12 }}>
            Status follows the agent heartbeat; event counts follow observed telemetry.
          </span>
        </div>

        {assets.length === 0 ? (
          <EmptyState
            title="No assets observed"
            hint="Enroll an agent or wait for its first events to appear here."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Host</th>
                  <th>OS</th>
                  <th>Agent version</th>
                  <th>Events</th>
                  <th>Last heartbeat</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((asset) => (
                  <tr key={asset.host}>
                    <td>
                      <AgentStatus status={asset.status} />
                    </td>
                    <td className="mono">{asset.host}</td>
                    <td className="mono dim">{asset.os || '—'}</td>
                    <td className="mono dim">{asset.agent_version || '—'}</td>
                    <td>{asset.event_count}</td>
                    <td className="nowrap muted">{formatTime(asset.last_heartbeat)}</td>
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
