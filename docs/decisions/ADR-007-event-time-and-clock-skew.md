# ADR-007 — Separate event time from receipt time; bound clock skew

**Status:** Accepted
**Date:** 2026-09-27

## Context

Sliding detection windows and incident timelines need a time. The only time the
server can trust is its own clock; the agent's clock can be wrong, or set
deliberately.

## Decision

Store `event_time` (source occurrence) and `received_at` (server receipt) as
separate columns. Reject an event whose `event_time` is more than a configurable
skew ahead of server time. Accept arbitrarily old timestamps, because backfilling
a rotated log is legitimate.

## Alternatives considered

- **Use receipt time for everything.** Rejected: a burst of events replayed from
  a spool would then appear as a burst happening now, which is exactly the
  pattern a brute-force rule looks for.
- **Use event time for everything.** Rejected: an agent with a badly wrong clock
  could place events outside any window and evade detection entirely.
- **Discard events with anomalous timestamps.** Rejected: discarding security
  telemetry because its clock is odd loses the evidence that matters most.

## Consequences

- Rules must state which time they window on. The current rules window on
  `event_time`.
- A record whose timestamp cannot be parsed falls back to the observation time
  and is marked `timestamp_source=observed`, so an analyst knows to distrust it.
- UI ordering is by event time with the event id as a stable tie-break.

## Security impact

Bounding the future skew prevents a forged timestamp from either evading a
window or triggering one. Not discarding old events prevents a clock anomaly
from being used to hide activity.

## Revisit conditions

Revisit if a source legitimately reports far-future events, or if per-host skew
tracking is needed for alerting on clock anomalies.
