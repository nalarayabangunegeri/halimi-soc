import { Shell } from '@/components/Shell'
import { AgentStatus, EmptyState } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { AgentActions } from '@/components/AgentActions'
import { listAgents } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import { formatBytes, formatTime } from '@/lib/format'

// The agent fleet.
//
// Spool bytes and queue depth are self-reported by the agent. They are displayed as
// reported rather than interpreted: an agent that has been spooling for a while is
// the signal an operator needs, and inventing a health verdict from them would hide
// the raw number they might want to act on.

export const dynamic = 'force-dynamic'

export default async function AgentsPage() {
  const session = await requireSession()

  let agents: Awaited<ReturnType<typeof listAgents>>['agents'] = []
  let error: unknown = null

  try {
    const result = await listAgents(session)
    agents = result.agents
  } catch (cause) {
    error = cause
  }

  const isAdmin = session.role === 'ADMIN'

  return (
    <Shell
      title="Agents"
      subtitle="Enrolled collection endpoints"
      username={session.username}
      role={session.role}
      active="agents"
      counts={{ agents: agents.length }}
    >
      {error ? <ErrorBanner error={error} /> : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">{agents.length} agent(s)</h2>
          <span className="dim" style={{ fontSize: 12 }}>
            An agent credential is scoped to one host and cannot be used as an operator credential.
          </span>
        </div>

        {agents.length === 0 ? (
          <EmptyState
            title="No agents enrolled"
            hint="Enroll an agent with the shared enrollment secret to start collecting telemetry."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Status</th>
                  <th>Host</th>
                  <th>Version</th>
                  <th>Platform</th>
                  <th>Last heartbeat</th>
                  <th>Queue</th>
                  <th>Spool</th>
                  <th>Agent id</th>
                  {isAdmin ? <th>Action</th> : null}
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => (
                  <tr key={agent.id}>
                    <td>
                      <AgentStatus status={agent.revoked_at ? 'OFFLINE' : agent.status} />
                      {agent.revoked_at ? <div className="dim" style={{ fontSize: 11 }}>revoked</div> : null}
                    </td>
                    <td className="mono">{agent.host}</td>
                    <td className="mono dim">{agent.version || '—'}</td>
                    <td className="mono dim">{agent.os || '—'}</td>
                    <td className="nowrap muted">{formatTime(agent.last_heartbeat)}</td>
                    <td>{agent.queue_depth}</td>
                    <td title={agent.spool_bytes > 0 ? 'Telemetry is being buffered; the API may be unreachable from this host.' : undefined}>
                      {formatBytes(agent.spool_bytes)}
                    </td>
                    <td className="mono dim nowrap" style={{ fontSize: 11 }}>
                      {agent.id}
                    </td>
                    {isAdmin ? (
                      <td>
                        <AgentActions id={agent.id} host={agent.host} revoked={Boolean(agent.revoked_at)} />
                      </td>
                    ) : null}
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
