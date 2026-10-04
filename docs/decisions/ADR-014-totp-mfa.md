# ADR-014 — TOTP MFA for operators

**Status:** Accepted (implemented)
**Date:** 2026-10-04

## Context

Pentest finding H1: dashboard auth was password-only. A stolen password meant
full console takeover, including rule/agent/user management. Enterprise
SSO/MFA stays post-MVP, but operator TOTP is cheap with the standard library
and closes the highest-value gap.

## Decision

- TOTP RFC 6238/4226: 6-digit, 30s step, SHA1, ±1 step skew, 20-byte secret.
- No new Go dependencies. `internal/mfa` uses `crypto/hmac`, `crypto/sha1`,
  `encoding/base32`, `crypto/aes` (GCM) only.
- Secrets sealed at rest: `HALIMISOC_MFA_KEY` (base64 32B) -> AES-256-GCM
  `v1:nonce:ct`; empty key stores `plain:` (dev) with a production warning.
- Backup codes: 10x single-use 8-char, SHA-256 hashes only, consumed on use.
- Login stays one request: `{username,password,totp_code|backup_code}`.
  Correct password + missing/wrong code -> 401 (`MFA_REQUIRED` when missing).
- Enrollment is setup -> enable (verify) -> backup codes (once); disable
  needs password + code; admin can reset a lost authenticator.
- TOTP guessing reuses the login limiter (`mfa:user:`, `mfa:ip:`) with audit
  `MFA_LOGIN_FAILURE` and metrics `mfa_failure_total`.

## Alternatives considered

- WebAuthn/passkeys: stronger phishing resistance, but needs browser ceremony,
  attestation handling and a larger UI. Deferred; TOTP already kills password
  replay and credential stuffing.
- Separate two-step ticket flow: more round trips and a new token type to
  protect. Single-request with optional code is simpler and equally safe
  because the password is still verified first with identical timing.

## Consequences

- Migration `0004_mfa.sql` adds `totp_secret`, `totp_enabled`,
  `totp_enrolled_at`, `backup_codes` to `users`.
- New endpoints under `/auth/mfa/*` + admin reset; all mutations CSRF.
- Operators without MFA keep working; enabling is opt-in per account.
