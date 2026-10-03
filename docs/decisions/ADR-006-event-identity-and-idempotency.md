# ADR-006 — Producer-generated event identity and idempotent ingestion

**Status:** Accepted
**Date:** 2026-09-27

## Context

An agent can fail to receive an acknowledgement and resend a batch. Disk-spool
replay after an outage resends everything the server may already have. Without a
stable identity, a resend either duplicates telemetry or, worse, re-runs
detection and fabricates an alert from events the attacker never sent.

## Decision

The producer generates a ULID-shaped, time-ordered event id. The server treats
that id as the idempotency key and enforces `UNIQUE(events.id)`. Detection runs
only for an event that was newly inserted.

## Alternatives considered

- **Server-assigned ids.** Rejected: the server cannot distinguish a resend from
  a genuinely new event, so it must either deduplicate on content (fragile) or
  accept duplicates.
- **Content hash as the id.** Rejected: two legitimately identical log lines
  (same second, same message) would collapse into one event, silently losing
  telemetry.
- **Check-then-insert in application code.** Rejected: it races under
  concurrency. `INSERT ... ON CONFLICT DO NOTHING` plus the affected-row count
  makes the decision atomic.

## Consequences

- Replay is safe by construction, not by convention.
- The id sorts lexicographically by creation time, which also gives pagination a
  stable tie-break with no extra column.
- The server must not silently rewrite a producer's id.

## Security impact

Re-running detection on a duplicate would inflate a sliding-window count, which
is a way to make the system raise an alert that the real event stream never
justified. Idempotency at the database level removes that.

## Revisit conditions

Revisit if multiple producers can legitimately generate the same id, which would
require a producer-scoped namespace.
