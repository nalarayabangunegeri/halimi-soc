# ADR-015 — Passkeys (WebAuthn) for phishing-resistant sign-in

**Status:** Accepted (implemented)
**Date:** 2026-10-04

## Context

TOTP (ADR-014) kills password replay but stays phishable: a fake console can
relay a 6-digit code within its 30s window. Passkeys bind the credential to
the origin, so a phishing page on another origin cannot use it.

## Decision

- Minimal stdlib-only verifier in `internal/webauthn` (no new Go deps):
  COSE ES256 (P-256) only; attestation `none` + `packed` self-attestation;
  user verification REQUIRED; rpIdHash + exact origin allowlist on every
  ceremony; ASN.1 DER ECDSA; clone detection via sign-count.
- Rejected explicitly: RSA/OKP keys, CA attestation (`x5c`), TPM/Android/
  Apple formats, UV=false. Clear errors tell the operator what to change.
- Challenges: 32 random bytes, single-use, 5-minute TTL, in-memory bounded
  store (single-node MVP, same rationale as the login limiter).
- Table `passkeys` (migration `0005`): credential id UNIQUE, raw COSE public
  key, sign count, transports, owner FK CASCADE.
- Flows: registration is authenticated + CSRF; passwordless login is
  `begin(username)` -> `navigator.credentials.get` -> `complete` and mints a
  normal server-side session (same TTL/idle/CSRF/revocation as password login).
  A passkey login counts as its own MFA (possession + UV), so no TOTP is asked.
- QR for TOTP uses `react-qr-code` (SVG, no network): the otpauth URL never
  leaves the page; the secret is still shown once for manual entry.

## Alternatives considered

- External WebAuthn library (duo-labs style): fuller format coverage but a new
  attack surface + dependency for code paths we deliberately reject. Revisit
  if Apple/Android attestation becomes a requirement.
- Server-rendered QR PNG in Go: same new-dep cost on the backend plus caching
  questions; client SVG keeps the secret in one place.

## Consequences

- New env: `HALIMISOC_WEBAUTHN_RP_ID` (default `127.0.0.1`),
  `HALIMISOC_WEBAUTHN_RP_NAME`, `HALIMISOC_WEBAUTHN_ORIGINS` (default both
  loopback console origins). Production refuses cleartext non-loopback origins.
- Console gains `/settings` (TOTP + passkeys) and a passkey button on login.
- Loss of all authenticators recovers via admin password + MFA reset, then
  re-registration. Audit covers register/delete/login success/failure.
- RP ID must be a hostname: browsers reject IP literals as invalid RP IDs, a
  fact the Playwright suite (virtual authenticator over `localhost`) locks in.
