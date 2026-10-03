# ADR-010 — Correlation requires a shared concrete entity

**Status:** Accepted
**Date:** 2026-09-27

## Context

Alerts that belong to one intrusion must become one incident. Alerts that merely
happened around the same time must not, because a wrongly merged incident sends
an analyst looking for a relationship that does not exist and hides the fact
that two separate events occurred.

## Decision

An alert joins an incident only when it shares a concrete entity value — host,
actor or source address — with that incident, within a bounded time window.
Candidate selection is deterministic: most shared entities first, then most
recent activity, then id.

## Alternatives considered

- **Merge on time proximity.** Rejected: co-occurrence is not evidence.
- **Merge on a shared source IP alone.** Rejected: one attacker hitting twenty
  unrelated hosts would produce a single incident that hides twenty separate
  compromises.
- **A graph database.** Rejected for the MVP: the entity model here is a small
  fixed tuple, not an open-ended graph, and the extra service is not justified.
- **Similarity scoring or clustering.** Rejected: it makes the merge decision
  non-reproducible, and an incident that cannot be explained cannot be trusted.

## Consequences

- Two alerts with no entity in common never merge, even if they are obviously
  related to a human reader. The analyst can link them manually.
- The correlation reason is recorded on the incident, so a reviewer can see why
  each alert joined.

## Security impact

Conservative merging bounds false positives, which is the failure mode that
destroys trust in a correlation engine fastest.

## Revisit conditions

Revisit when richer entity types (session id, process lineage) are available
from new parsers, which would allow stronger identities than host and IP.
