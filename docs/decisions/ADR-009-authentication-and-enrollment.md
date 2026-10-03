# ADR-009 — Password sessions for operators, hashed tokens for agents

**Status:** Accepted
**Date:** 2026-09-27

## Context

Two different principals authenticate to the same API: a human operator using a
browser, and an unattended agent using a credential it must store on disk.

## Decision

Operators authenticate with an Argon2id-hashed password and receive a
server-side session referenced by an `__Host-` prefixed `HttpOnly` cookie, with a
CSRF token required for state-changing requests. Agents enroll with a shared
enrollment secret and receive a per-agent random token, stored only as a SHA-256
hash.

## Alternatives considered

- **JWT sessions.** Rejected: a stateless token cannot be revoked before it
  expires, which is unacceptable for an administrative console.
- **Static admin API token.** Rejected as the only mechanism: it cannot be
  attributed to a person, cannot be revoked per-user, and has no session
  lifecycle.
- **Storing agent tokens in plaintext.** Rejected: a database disclosure would
  then yield directly usable credentials.
- **Argon2id for agent tokens.** Rejected as unnecessary: the token is
  full-entropy, so a fast hash is sufficient. Argon2id is required for passwords
  precisely because they are not.

## Consequences

- Revocation is immediate for both principals.
- Losing an agent token requires rotation; it cannot be recovered, by design.
- Login is rate limited per account and per source address, with progressive
  backoff rather than permanent lockout.

## Security impact

Separating the enrollment secret from operator credentials means a compromised
agent cannot be used to reach the console. Constant-time comparison is used for
every credential check, and failed logins are indistinguishable in both response
and timing whether or not the account exists.

## Revisit conditions

Revisit when OIDC/SSO or MFA is required, or when agents need per-request
authorization rather than a bearer token.
