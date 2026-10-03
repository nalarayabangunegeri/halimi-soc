# ADR-005 — Detection state is in-memory and ephemeral

**Status:** Accepted
**Date:** 2026-09-27

## Context

Threshold rules need to count events over a sliding window. The MVP runs on a
single node.

## Decision

Keep sliding-window and cooldown state in memory, bounded by key count and TTL,
and accept that a process restart resets it.

## Alternatives considered

- **Redis.** Rejected: it adds a service to operate and secure in exchange for
  surviving a restart that already interrupts the pipeline anyway.
- **Persisting counters in PostgreSQL.** Rejected: it would put a write on the
  hot path of every event and make detection latency a function of database
  latency.
- **Recomputing windows from stored events.** Rejected explicitly by the design:
  a full-table aggregation per event does not scale and makes detection cost
  proportional to retention.

## Consequences

- Detection state is lost on restart. A brute-force sequence straddling a
  restart may not alert. This is documented rather than hidden.
- State is keyed by event time, not wall-clock time, so a replay produces the
  same outcome as the original delivery.
- Eviction is deterministic, so two runs over the same input evict the same
  groups.

## Security impact

Bounded state means a hostile source cannot exhaust memory by generating
unlimited distinct grouping keys. Ephemeral state means an attacker who can
restart the process can also suppress a detection; that is an accepted MVP
limitation, mitigated by restart being an operator action and by it being
auditable.

## Revisit conditions

Revisit when detection must survive a restart without an alerting gap, or when
the deployment becomes multi-node.
