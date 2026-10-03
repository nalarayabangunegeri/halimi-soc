import { Shell } from '@/components/Shell'
import { EmptyState, SeverityBadge } from '@/components/Badges'
import { ErrorBanner } from '@/components/ErrorState'
import { RuleRowActions } from '@/components/RuleRowActions'
import { listRules } from '@/lib/api'
import { requireSession } from '@/lib/guard'
import Link from 'next/link'

// The loaded detection rule set.
//
// This page is read-only and exists to answer "what is actually deployed". Rule
// files are validated as a whole at startup, so what is shown here is exactly what
// the engine is running; there is no partially applied state to explain.
//
// Editing rules is deliberately not exposed in the MVP: a rule change is a
// configuration change that should be reviewed and deployed, not clicked.

export const dynamic = 'force-dynamic'

export default async function RulesPage() {
  const session = await requireSession()

  let rules: Awaited<ReturnType<typeof listRules>>['rules'] = []
  let error: unknown = null

  try {
    const result = await listRules(session)
    rules = result.rules
  } catch (cause) {
    error = cause
  }

  const isAdmin = session.role === 'ADMIN'

  return (
    <Shell
      title="Detection rules"
      subtitle="Rules are data, validated as a whole at startup"
      username={session.username}
      role={session.role}
      active="rules"
    >
      {error ? <ErrorBanner error={error} /> : null}

      <div className="notice">
        Severity comes from the rule, never from the event or from AI. A rule file that fails validation
        stops the server: the engine never runs a partially applied rule set.
        {isAdmin ? (
          <>
            {' '}
            <Link href="/rules/new">Author a new rule</Link> — validate, save, then reload to activate.
          </>
        ) : null}
      </div>

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">{rules.length} rule(s) loaded</h2>
        </div>

        {rules.length === 0 ? (
          <EmptyState
            title="No rules loaded"
            hint="The server refuses to start with an empty rule set, so this should not be reachable. Readiness will report degraded."
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Threshold</th>
                  <th>Group by</th>
                  <th>Requires</th>
                  {isAdmin ? <th>Action</th> : null}
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={`${rule.id}@${rule.version}`}>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>
                      <div>{rule.name}</div>
                      <div className="mono dim">
                        {rule.id}
                        <span>@{rule.version}</span>
                      </div>
                      {rule.description ? (
                        <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                          {rule.description}
                        </div>
                      ) : null}
                    </td>
                    <td className="nowrap">
                      {rule.threshold.count} in {rule.threshold.window}
                    </td>
                    <td className="mono nowrap">{rule.group_by.join(', ')}</td>
                    <td className="mono">
                      {rule.requires ? (
                        <span title="This rule only fires when the named rule fired recently for the same chaining key.">
                          {rule.requires}
                        </span>
                      ) : (
                        <span className="dim">—</span>
                      )}
                    </td>
                    {isAdmin ? (
                      <td className="nowrap">
                        <Link href={`/rules/edit/${rule.id}`}>Edit</Link>
                        {' · '}
                        <RuleRowActions id={rule.id} />
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
