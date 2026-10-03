# HalimiSOC console

The operator-facing dashboard. Next.js 16 (App Router) + React 19, TypeScript
with `strict`, vitest for unit tests, Playwright for end-to-end tests.

## What it is

A backend-for-frontend. The browser never talks to the Go API: it talks to this
app, which holds the operator session server-side and forwards requests to
`HALIMISOC_API_URL`. That is what removes the need for CORS, keeps the API
session out of JavaScript's reach, and leaves the API as the single
authorization enforcement point.

See `DESIGN.md` §10.6 for the design and `docs/security/configuration.md` for the
console's configuration and CSP.

## Commands

Run these from `apps/web`:

```bash
npm ci              # install
npm run dev         # dev server on :3000
npx tsc --noEmit    # typecheck
npx vitest run      # unit tests
npm run build       # production build
npx playwright test # end-to-end tests (needs HALIMISOC_TEST_DATABASE_URL)
```

Or from the repository root:

```bash
make web-install
make web-check      # typecheck, unit tests, production build
make web-e2e        # Playwright against a real API and PostgreSQL
```

## End-to-end tests

The suite starts the Go API itself (built from source) against
`HALIMISOC_TEST_DATABASE_URL`, then drives a production build of this app. The
database name must end in `_test`; setup refuses to truncate anything else.

It empties the application tables before starting the API, so the suite can run
in any order and after any other suite that shares the test database. Without
that reset the API would keep an administrator seeded with another suite's
password and every login here would fail for a reason that has nothing to do with
the code under test.

## Layout

```text
src/proxy.ts               per-response Content-Security-Policy and nonce
src/lib/                   config, session codec, CSRF, typed API client
src/app/api/auth/          login, session, logout
src/app/api/proxy/         closed allowlist of mutations against the API
src/app/api/stream/        SSE proxy
src/app/<page>/            one server component per console page
src/components/            shared UI, realtime provider
tests/unit/                vitest
tests/e2e/                 Playwright
```
