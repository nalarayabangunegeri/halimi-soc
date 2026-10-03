# ADR-008 — Detection rules are data, loaded fail-closed

**Status:** Accepted
**Date:** 2026-09-27

## Context

Detection rules must be editable without recompiling, but a rule file that can
express arbitrary logic is a remote code execution surface, and a rule file that
is partially applied leaves the detector in an unknown state.

## Decision

Rules are YAML parsed into a strict schema with unknown fields rejected, then
validated into a restricted internal representation with a closed allowlist of
matchable fields and a hard maximum on every numeric bound. The whole directory
is validated before any rule becomes active.

## Alternatives considered

- **An expression language (CEL, JavaScript, Lua).** Rejected for the MVP: it
  trades a large increase in capability for a large increase in attack surface,
  and the current rule set needs only equality and counting.
- **Compiled Go rules.** Rejected: they require a rebuild and a redeploy to
  change a threshold, which is the wrong trade for the product's audience.
- **Partial application of valid rules.** Rejected: the detector would silently
  run a different rule set than the operator believes is deployed.

## Consequences

- An invalid rule file is a startup failure, not a warning.
- A rule cannot read raw evidence or arbitrary attributes; only the allowlisted
  entity fields are addressable.
- `requires` chaining references are resolved at load time, so a dangling
  reference cannot silently disable a rule.

## Security impact

No arbitrary code execution, no unbounded rule values, and no partially applied
configuration. A hostile rule file can at worst fail validation.

## Revisit conditions

Revisit if operators need rules that the restricted representation cannot
express, in which case the new capability must be added as a validated primitive
rather than as an evaluator.
