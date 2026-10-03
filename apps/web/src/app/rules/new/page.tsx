import Link from 'next/link'
import { Shell } from '@/components/Shell'
import { RuleEditor } from '@/components/RuleEditor'
import { requireSession } from '@/lib/guard'
import { ErrorBanner } from '@/components/ErrorState'

// New rule.
//
// Admin-only: the page redirects non-admins before rendering the form, and the
// API enforces manage_rules again on every action, so hiding the form is
// convenience, not control.
export const dynamic = 'force-dynamic'

export default async function NewRulePage() {
  const session = await requireSession()

  if (session.role !== 'ADMIN') {
    return (
      <Shell title="New rule" username={session.username} role={session.role} active="rules">
        <ErrorBanner error={new Error('Not permitted: rule authoring requires ADMIN.')} />
        <p className="dim">
          Rule authoring is an ADMIN operation. <Link href="/rules">Back to rules</Link>
        </p>
      </Shell>
    )
  }

  return (
    <Shell
      title="New rule"
      subtitle="Validate, save, then reload to activate"
      username={session.username}
      role={session.role}
      active="rules"
    >
      <div className="card">
        <div style={{ padding: '16px' }}>
          <RuleEditor />
        </div>
      </div>
    </Shell>
  )
}
