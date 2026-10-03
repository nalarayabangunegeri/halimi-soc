# ADR-012 — Flat canonical event shape

**Status:** Accepted (supersedes the nested shape in DESIGN v1.2.0)
**Date:** 2026-09-27

## Context

The draft design described the canonical event as deeply nested:

```json
{
  "source":    { "type": "sshd", "host": "server-01" },
  "event":     { "category": "authentication", "action": "login_failed" },
  "principal": { "user": "root" },
  "network":   { "src_ip": "1.2.3.4" },
  "process":   { "pid": 1823, "name": "sshd" },
  "command":   { "line": null },
  "file":      { "path": null },
  "evidence":  { "raw_line": null, "raw_hash": null, "parser": "sshd" }
}
```

Three problems surfaced while implementing it.

1. **No defined mapping to storage.** The draft indexed `events(source_type)`,
   `events(event_category)`, `events(network_src_ip)` — flat columns — while the
   contract was nested. Every consumer would have had to guess the mapping, and two
   implementers would have guessed differently. This is the class of ambiguity the
   audit flagged as AUD-004.
2. **Two ways to say the same thing.** `source.type` and `evidence.parser` both
   named the parser; `event.category` + `event.action` overlapped with a rule's
   `match` block.
3. **Half-empty objects.** `process`, `command`, `file` and `evidence` were null for
   most sources, so the common case carried four empty objects.

## Decision

A flat event with one name per concept, a closed `type` enum, a `network` sub-object
for peer addressing, and an `attributes` map for type-specific detail.

```json
{
  "id": "evt_...",
  "schema_version": "1",
  "type": "auth.ssh.login_failed",
  "time": "...",
  "received_at": "...",
  "observed_at": "...",
  "host": "server-01",
  "agent_id": "agt_...",
  "source": "auth.log",
  "actor": "root",
  "target": "root",
  "network": { "src_ip": "1.2.3.4", "src_port": 53211 },
  "outcome": "failure",
  "severity": "medium",
  "attributes": { "parser": "sshd", "pid": "1823" },
  "message": "SSH authentication failed",
  "raw": "..."
}
```

`principal.user` becomes two fields, `actor` and `target`, because an authentication
event has both an acting and an acted-upon identity, and collapsing them loses the
distinction a rule needs.

## Alternatives considered

- **Keep the nested shape and store it as JSONB.** Rejected: it moves every filter
  into a JSON expression, which makes indexes harder to reason about and query plans
  harder to verify. It also means a field rename is a data migration rather than a
  schema change.
- **Keep the nested shape and map it to columns at the storage boundary.** Rejected:
  it creates two names for every concept, and the mapping itself becomes a thing that
  can drift.
- **Adopt an existing standard schema (OCSF, ECS).** Attractive in principle, but
  both are large enough that adopting one would mean adopting a vocabulary far wider
  than this product implements, and the parts this product needs are a small subset.
  Revisit if interoperability with an external SIEM becomes a requirement.

## Consequences

- One name per concept, and the name is the same in Go, JSON and SQL.
- A rule matches on `type`, `outcome` and `attributes` — all validated and bounded.
- `attributes` is a bounded, validated string map, so it cannot become an unbounded
  escape hatch.
- The `evidence` object is gone; the raw line is the `raw` field, and its expiry is
  tracked by `raw_expired`.

## Security impact

The nested shape had no rule about which level a rule could read, so a rule could
plausibly have addressed `evidence.raw_line`. The flat shape makes the addressable
surface explicit: `internal/detection/rules` allowlists five fields, and raw
evidence is not one of them. A rule cannot match on log content an attacker controls.

## Revisit conditions

Revisit if external interoperability requires an industry schema, or if a source
appears whose semantics genuinely need a nested structure the flat shape cannot
express with `attributes`.
