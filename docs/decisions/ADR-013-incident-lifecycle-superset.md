# ADR-013 — Incident lifecycle is a superset of the PRD minimum

**Status:** Accepted (amends PRD FR-11)
**Date:** 2026-09-27

## Context

PRD FR-11 defines the incident lifecycle as:

```text
NEW → ACKNOWLEDGED → INVESTIGATING → RESOLVED
                          (FALSE_POSITIVE optional)
```

Implementing it surfaced two gaps.

1. There is no state for "the immediate threat has been stopped, but the
   investigation is not finished". That is the most common real state during
   containment, and without it an operator must either leave the incident in
   INVESTIGATING — which hides that action was taken — or mark it RESOLVED, which
   claims more than is known.
2. RESOLVED is terminal in the draft, so there is no way to record that a resolved
   incident was closed out and the paperwork finished. Analysts need to distinguish
   "we understand it and acted" from "this is done".

## Decision

```text
NEW → ACKNOWLEDGED → INVESTIGATING → CONTAINED → RESOLVED → CLOSED
        ↘ FALSE_POSITIVE (reachable from any active state)
```

The set is a strict superset of the PRD minimum: every PRD state is present and
reachable. The transition graph is forward-only, and a terminal state
(`RESOLVED`, `CLOSED`, `FALSE_POSITIVE`) is never reopened.

## Alternatives considered

- **Implement exactly the PRD set.** Rejected: it would force an operator to
  misdescribe the state of an investigation, and a status field that does not match
  reality is worse than a slightly larger enum.
- **Use a free-text status.** Rejected outright: it makes the status unqueryable and
  unusable in an authorization decision.
- **Reopen a terminal incident when new activity arrives.** Rejected: it rewrites the
  timeline of a completed investigation. New activity creates a new incident instead,
  so each investigation's history stays immutable.
- **Drop ACKNOWLEDGED to keep the set small.** Rejected: it is a PRD state and it
  answers a real question ("has anyone picked this up yet").

## Consequences

- `0002_incident_lifecycle.sql` exists because the constraint was already applied.
  Editing `0001` would have left existing databases on the old vocabulary.
- Every allowed and every rejected transition is tested.
- A client cannot skip a stage or reopen a terminal incident; both return `409`.

## Security impact

None directly: the lifecycle is workflow, not authorization. It is still enforced
server-side, because a client that can set an arbitrary status can misrepresent the
state of an investigation, and the audit log would then record a false history.

## Revisit conditions

Revisit if the product needs a per-incident custom workflow, which would be a
different feature (a configurable state machine) rather than a larger fixed enum.
