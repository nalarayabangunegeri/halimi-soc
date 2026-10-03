# ADR-011 — Raw evidence expires before structured events

**Status:** Accepted
**Date:** 2026-09-27

## Context

Raw log lines are the highest-fidelity evidence and the highest-risk data to
retain: they can contain credentials, tokens and personal data. The structured
event is what detection and correlation actually need.

## Decision

Store raw evidence on the event row with a shorter retention than the structured
event. Expiry nulls the raw column and sets a marker; the structured event, and
therefore every alert and incident that references it, remains valid.

## Alternatives considered

- **Store everything forever.** Rejected: unbounded growth of the most sensitive
  data is the worst combination.
- **Do not store raw evidence at all.** Rejected: without the source line,
  detection cannot be audited, which defeats the product's core claim.
- **Delete the whole event when raw expires.** Rejected: it would silently
  invalidate alert and incident evidence and break the investigation timeline.
- **Separate raw-evidence store.** Deferred: it is the right shape once volume
  justifies it, but it is an extra service for the MVP.

## Consequences

- The UI must show an expired raw line as unavailable rather than rendering an
  empty block that looks like an empty log line.
- Retention runs as a bounded periodic update, so it cannot lock the table.
- Retention is configurable, with raw retention constrained to not exceed event
  retention.

## Security impact

Minimising retention of the most sensitive field reduces the blast radius of a
database disclosure, while preserving the structured record needed to explain
what was detected.

## Revisit conditions

Revisit when raw evidence volume requires a separate store, or when a regulatory
requirement mandates a specific retention or deletion behaviour.
