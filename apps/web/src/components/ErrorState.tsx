import { ApiError } from '@/lib/api'

// Error rendering.
//
// The API returns a stable code, so the UI can explain what happened without
// guessing. The message shown is the API's own generic message; an unrecognised
// code is still displayed, because hiding it would make a genuine contract change
// indistinguishable from an outage.

const HINTS: Record<string, string> = {
  API_UNREACHABLE: 'The dashboard could not reach the HalimiSOC API. Check that the API is running.',
  INVALID_RESPONSE: 'The API returned a response the dashboard could not parse.',
  UNAUTHORIZED: 'Your session is no longer valid. Sign in again.',
  FORBIDDEN: 'Your role does not permit this view.',
  SERVICE_UNAVAILABLE: 'The API is up but not ready. It may still be starting, or no detection rules are loaded.',
  STREAM_UNAVAILABLE: 'The realtime feed is at its connection limit or is not yet available.',
}

export function errorMessage(error: unknown): { title: string; hint?: string } {
  if (error instanceof ApiError) {
    return {
      title: `${error.message} (${error.code})`,
      hint: HINTS[error.code],
    }
  }
  if (error instanceof Error) {
    return { title: error.message }
  }
  return { title: 'An unexpected error occurred.' }
}

export function ErrorBanner({ error }: { error: unknown }) {
  const { title, hint } = errorMessage(error)
  return (
    <div className="error-banner" role="alert">
      <div style={{ fontWeight: 600 }}>{title}</div>
      {hint ? <div style={{ marginTop: 6, color: 'var(--text-muted)' }}>{hint}</div> : null}
    </div>
  )
}
