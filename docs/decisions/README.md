# Architecture Decision Records

Each file records one decision: the context, the options considered, the
decision, its security impact, and the conditions under which it should be
revisited.

The point of these records is that a future contributor — human or agent — can
see *why* the system is shaped this way and can tell the difference between a
deliberate trade-off and an accident.

| ADR | Decision |
|-----|----------|
| [001](ADR-001-go-backend.md) | Go for the API and the agent |
| [002](ADR-002-postgresql-storage.md) | PostgreSQL as the system of record |
| [003](ADR-003-sse-realtime.md) | Server-Sent Events for realtime updates |
| [004](ADR-004-ai-advisory-only.md) | AI is advisory and outside the detection path |
| [005](ADR-005-ephemeral-detection-state.md) | Detection state is in-memory and ephemeral |
| [006](ADR-006-event-identity-and-idempotency.md) | Producer-generated ids and idempotent ingestion |
| [007](ADR-007-event-time-and-clock-skew.md) | Separate event time from receipt time |
| [008](ADR-008-rule-safe-loading.md) | Rules are data, loaded fail-closed |
| [009](ADR-009-authentication-and-enrollment.md) | Sessions for operators, hashed tokens for agents |
| [010](ADR-010-correlation-entity-model.md) | Correlation requires a shared concrete entity |
| [011](ADR-011-retention-and-raw-evidence.md) | Raw evidence expires before structured events |
| [012](ADR-012-canonical-event-shape.md) | Flat canonical event shape |
| [013](ADR-013-incident-lifecycle-superset.md) | Incident lifecycle is a superset of the PRD minimum |
| [014](ADR-014-totp-mfa.md) | TOTP second factor for operators |
| [015](ADR-015-passkey-webauthn.md) | Passkeys (WebAuthn) for phishing-resistant sign-in |

## Adding a decision

1. Copy an existing file and give it the next number.
2. State the context and the options that were genuinely considered, including
   the ones that were rejected and why.
3. State the security impact explicitly. If a decision has no security impact,
   say so rather than leaving it implicit.
4. State the conditions under which the decision should be revisited.

An ADR is never edited to reflect a change of mind. Write a new one that
supersedes it, and mark the old one as superseded.
