# The pipeline

```text
Raw telemetry
    |
    v
Reader              agent/reader.go      offsets, inode identity, rotation, truncation
    |
    v
Line assembler      events/parser        joins continuation lines, bounds record size
    |
    v
Parser              events/parser        classifies: VALID / MALFORMED / UNSUPPORTED /
    |                                       INCOMPLETE / NON_SECURITY_RELEVANT
    v
Normalizer          events/validation    canonical host, identity, IP, timestamps, bounds
    |
    v
Canonical event     events/model         the central cross-component contract
    |
    v
Idempotent ingest   events/ingest        INSERT ... ON CONFLICT DO NOTHING
    |
    v
Detection           detection/engine     threshold + chaining + cooldown, in-memory state
    |
    v
Alert               alerts               rule id, rule version, evidence event ids
    |
    v
Correlation         correlation          shared concrete entity + bounded window
    |
    v
Incident            incidents            severity = highest qualifying alert
    |
    v
Evidence selection  (AI, post-MVP)       bounded, redacted context
```

## Invariants

**AI is outside the pipeline.** Nothing above the AI line depends on a model
being reachable. Detection and correlation continue when no provider is
configured.

**Persistence precedes detection.** An event is stored before it is evaluated,
and detection runs only when the store reports a new insert. This ordering is
what makes replay safe: a duplicate returns the existing identity and never
re-enters the engine, so it cannot inflate a sliding-window count.

**Untrusted input is validated once, at one boundary.** Everything downstream of
`events/validation` operates on canonical values. A parser is never trusted to
have normalized anything.

**Every bound is explicit.** Line length, record length, field length, batch
size, page size, queue depth, spool size, window size, cooldown and state key
count all have a default and a maximum.

## Trust boundary

```text
        TRUSTED
  authenticated identity
  authorization state
  validated rule configuration
  application-generated metadata
  output schemas
  ---------------------------------
        UNTRUSTED
  raw log lines
  agent-supplied metadata
  event timestamps
  usernames, hostnames, paths, command lines
  external enrichment
  model output
```

## Where each guarantee is enforced

| Guarantee | Code |
|---|---|
| A parser cannot panic on hostile input | `internal/events/parser` (fuzz + adversarial tests) |
| A malformed event cannot fail its batch | `internal/events/ingest` |
| A replay cannot fabricate an alert | `internal/events/ingest` + `UNIQUE(events.id)` |
| Alert severity is the rule's severity | `internal/detection/engine` |
| A rule cannot read raw evidence | `internal/detection/rules` field allowlist |
| A weak entity cannot merge unrelated hosts | `internal/correlation` |
| An agent cannot forge another host's events | `internal/api/handlers_resources.go` |
| A revoked session cannot keep using the API | `internal/api` + `internal/auth` |
| CSRF is required on cookie-authenticated writes | `internal/api` |
