'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { getCsrfToken } from '@/lib/browser'

// Sign out.
//
// The request carries the double-submit CSRF token, because the logout route is
// authenticated by a cookie. On success the operator is sent to the login page; a
// failed logout still navigates, because the local session is cleared either way
// and leaving them on a page they believe they signed out of would be worse.
export function SignOutButton() {
  const router = useRouter()
  const [busy, setBusy] = useState(false)

  return (
    <button
      type="button"
      className="small"
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          await fetch('/api/auth/logout', {
            method: 'POST',
            headers: { 'x-halimisoc-csrf': getCsrfToken() },
          })
        } finally {
          router.replace('/login')
        }
      }}
    >
      {busy ? 'Signing out…' : 'Sign out'}
    </button>
  )
}
