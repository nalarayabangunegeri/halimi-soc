import { redirect } from 'next/navigation'
import { LoginForm } from '@/components/LoginForm'
import { readSession } from '@/lib/session'

// The login page.
//
// It reads the session cookie, so it is inherently per-request and must never be
// prerendered: a cached login page would be served with a stale redirect decision.
export const dynamic = 'force-dynamic'

// If a session already exists the operator is sent to the overview rather than
// being shown a login form they do not need.
export default async function LoginPage() {
  const session = await readSession()
  if (session) redirect('/')

  return (
    <div className="login-shell">
      <div className="login-card">
        <h1>HalimiSOC</h1>
        <p>Sign in to the security operations console.</p>
        <LoginForm />
      </div>
    </div>
  )
}
