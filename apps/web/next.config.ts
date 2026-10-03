import type { NextConfig } from 'next'

// The dashboard is a same-origin BFF: the browser only ever talks to this app,
// and this app holds the API session server-side. Two consequences drive the
// configuration below.
//
// 1. The Go API never needs to be reachable from the browser, so it needs no
//    CORS policy and is never exposed to a cross-origin page.
// 2. Security headers can be strict, because nothing here is embedded elsewhere
//    and no third-party origin needs to load a resource.
const config: NextConfig = {
  reactStrictMode: true,

  // Emits `.next/standalone`, a self-contained server that does not need the
  // toolchain or the full node_modules at runtime. `deploy/docker/web.Dockerfile`
  // runs that directory directly; `next start` keeps working unchanged for local
  // development and for the end-to-end suite.
  output: 'standalone',

  poweredByHeader: false,

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
          // Content-Security-Policy is not set here: script-src carries a fresh
          // nonce per response and therefore has to be built while the request is
          // in flight. It lives in src/proxy.ts, which is the only layer that can
          // vary per request. Setting a second, static copy here would either be
          // discarded or silently win and break the nonce.
        ],
      },
    ]
  },
}

export default config
