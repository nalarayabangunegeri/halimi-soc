# ADR-001 — Go for the API and the agent

**Status:** Accepted
**Date:** 2026-09-27
**Deciders:** HalimiSOC maintainers

## Context

HalimiSOC needs one language for the collection agent and the server. The agent
runs on the monitored host, where it must be a single binary with no runtime
dependency, survive log rotation, buffer to disk during an outage, and never
grow memory without bound. The server must parse untrusted log lines at line
rate and expose an HTTP API.

## Decision

Use Go for the API and the agent.

## Alternatives considered

- **Python or Node agent.** Rejected: either would add a runtime to every
  monitored host, increasing both attack surface and deployment friction for
  exactly the audience the product targets.
- **Rust.** Viable and would give stronger compile-time guarantees, but the
  team's existing fluency is Go, and the parts where memory safety is critical
  (parsing untrusted bytes) are covered by Go's bounds checking plus fuzzing.
- **A single monolith in a dynamic language.** Rejected: an unbounded parse loop
  on attacker-controlled input is a much easier mistake to make and much harder
  to bound.

## Consequences

- The agent is a static binary with no runtime dependency.
- `context.Context` threads cancellation and timeouts through every I/O path.
- Bounded goroutines and channels are the concurrency model, which makes
  backpressure explicit rather than implicit.

## Security impact

Go removes an entire class of memory-safety bugs from the parsing path, which is
the largest untrusted-input surface in the product. It does not remove the need
for bounds checking on line and field length; those are enforced explicitly.

## Revisit conditions

Revisit if the agent must run on a platform where Go cannot produce a practical
binary, or if a measured performance requirement cannot be met.
