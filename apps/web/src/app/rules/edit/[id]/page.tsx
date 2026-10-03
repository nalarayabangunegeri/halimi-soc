import Link from 'next/link'
import { Shell } from '@/components/Shell'
import { RuleEditor } from '@/components/RuleEditor'
import { ErrorBanner } from '@/components/ErrorState'
import { getRuleBody } from '@/lib/api'
import { requireSession } from '@/lib/guard'

// Edit rule.
//
// The form is prefilled from the file body the API returns. Saving writes the
// file; activation stays a separate reload step, which the editor offers next
// to the save button.
export const dynamic = 'force-dynamic'

export default async function EditRulePage({ params }: { params: Promise<{ id: string }> }) {
  const session = await requireSession()
  const { id } = await params

  if (session.role !== 'ADMIN') {
    return (
      <Shell title="Edit rule" username={session.username} role={session.role} active="rules">
        <ErrorBanner error={new Error('Not permitted: rule authoring requires ADMIN.')} />
        <p className="dim">
          <Link href="/rules">Back to rules</Link>
        </p>
      </Shell>
    )
  }

  let yaml: string | null = null
  let error: unknown = null
  try {
    const body = await getRuleBody(session, id)
    yaml = body.yaml
  } catch (cause) {
    error = cause
  }

  return (
    <Shell
      title={`Edit rule ${id}`}
      subtitle="Validate, save, then reload to activate"
      username={session.username}
      role={session.role}
      active="rules"
    >
      {error ? <ErrorBanner error={error} /> : null}
      {yaml !== null ? (
        <div className="card">
          <div style={{ padding: '16px' }}>
            <RuleEditor initialId={id} initialYaml={yaml} />
          </div>
        </div>
      ) : null}
    </Shell>
  )
}
