'use client'

// Browser-side helpers.
//
// This module is the only place the client reads the CSRF cookie. The cookie is
// intentionally readable: it is not a bearer credential, and being readable is
// exactly what lets the page echo it in a header, which a cross-site page cannot
// do.

const CSRF_COOKIE = 'halimisoc_csrf'

/** Reads the double-submit CSRF token from the readable cookie. */
export function getCsrfToken(): string {
  if (typeof document === 'undefined') return ''
  const prefix = `${CSRF_COOKIE}=`
  for (const part of document.cookie.split('; ')) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length))
    }
  }
  return ''
}

/** Calls a mutating action through the BFF proxy. */
export async function mutate<T = unknown>(
  action: string,
  id: string,
  payload?: Record<string, unknown>,
): Promise<{ ok: true; data: T } | { ok: false; code: string; message: string }> {
  const response = await fetch('/api/proxy', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-halimisoc-csrf': getCsrfToken(),
    },
    body: JSON.stringify({ action, id, payload }),
  })

  const text = await response.text()
  let parsed: unknown = undefined
  try {
    parsed = text ? JSON.parse(text) : undefined
  } catch {
    parsed = undefined
  }

  if (!response.ok) {
    const envelope = parsed as { error?: { code?: string; message?: string } } | undefined
    return {
      ok: false,
      code: envelope?.error?.code ?? 'UNKNOWN',
      message: envelope?.error?.message ?? 'The request failed.',
    }
  }
  return { ok: true, data: parsed as T }
}
