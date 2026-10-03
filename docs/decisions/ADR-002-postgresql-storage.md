# ADR-002 — PostgreSQL as the system of record

**Status:** Accepted
**Date:** 2026-09-27

## Context

The MVP must store canonical events, alerts, incidents, agents, credentials and
audit records, and answer filtered, paginated queries over them. It must remain
practical on a single VPS or homelab machine.

## Decision

Use PostgreSQL as the single system of record, with versioned SQL migrations
applied automatically at startup.

## Alternatives considered

- **SQLite.** Attractive for portability, but concurrent writers are serialised
  and the migration path to a networked database is a rewrite rather than a
  configuration change.
- **ClickHouse or another column store.** Rejected for the MVP: it optimises a
  query shape (aggregate scans over billions of rows) that a single-node
  deployment does not have, at the cost of an additional service to operate.
- **Embedded key-value store.** Rejected: the product's core value is relational
  correlation between events, alerts and incidents, which is exactly what a
  relational database provides.

## Consequences

- One service to operate, back up and secure.
- Indexes are chosen to match the actual read patterns (newest-first with a
  stable id tie-break).
- Retention is implemented as a bounded periodic update rather than as a
  partition-management problem.

## Security impact

Every query is parameterised; no filter value is ever concatenated into SQL.
Uniqueness constraints on `events.id` make ingestion idempotency a database
guarantee rather than an application convention.

## Revisit conditions

Revisit when a measured ingest rate or retention window exceeds what a single
PostgreSQL instance can serve, or when the operator needs horizontal read scale.
