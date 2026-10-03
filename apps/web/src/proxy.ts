import { NextRequest, NextResponse } from 'next/server'

// The Content Security Policy.
//
// The policy lives here rather than in `next.config.ts` because the one part of
// it that matters most — `script-src` — has to be different for every response.
//
// Why a nonce at all: the App Router serialises its flight data into inline
// `<script>` elements. A static `script-src 'self'` cannot admit those, so the
// browser refuses to run them, React never hydrates, and every client component
// — including the login form — stays inert. The app does not merely degrade in
// that state, it does not work. A nonce admits exactly the inline scripts this
// response emitted and no others, which is strictly stronger than the
// `'unsafe-inline'` that would otherwise be needed.
//
// `'strict-dynamic'` then lets the nonced runtime load its own chunks, so the
// allow-list does not have to enumerate paths Next is free to change.
//
// There is deliberately no `upgrade-insecure-requests`: this product is expected
// to run over plain HTTP on a trusted lab network as well as behind TLS, and
// that directive would break the former rather than protect it.
//
// Pages must be rendered dynamically for the nonce to be applied; every route
// under `src/app` declares `export const dynamic = 'force-dynamic'`.
export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64')
  const isDev = process.env.NODE_ENV === 'development'

  const cspHeader = [
    "default-src 'self'",
    // React uses eval for its debugging helpers, which exist only in development.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ''}`,
    // Style *attributes* — the `style={{...}}` used throughout the console — are
    // not eligible for a nonce, so this still needs 'unsafe-inline'. It is kept
    // separate from script-src because a lenient style policy costs nothing that
    // a lenient script policy would.
    "style-src 'self' 'unsafe-inline'",
    'img-src \'self\' data:',
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join('; ')

  const requestHeaders = new Headers(request.headers)
  // Next reads the nonce back out of this header while rendering and attaches it
  // to its own script tags automatically.
  requestHeaders.set('x-nonce', nonce)
  requestHeaders.set('Content-Security-Policy', cspHeader)

  const response = NextResponse.next({
    request: { headers: requestHeaders },
  })
  response.headers.set('Content-Security-Policy', cspHeader)

  return response
}

export const config = {
  matcher: [
    {
      source: '/((?!api|_next/static|_next/image|favicon.ico).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
}
