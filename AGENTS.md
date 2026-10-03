# HalimiSOC — Agent Development Guide

**Version:** 2.0.0
**Status:** Implemented (as-built)
**Normative documents:** `PRD.md` (what), `DESIGN.md` (how), `SPEC-AUDIT.md` (decision history)

> This file defines how AI coding agents and human contributors work on
> HalimiSOC. It does not redefine product requirements or technical contracts.

---

## 1. Mission

Build HalimiSOC as a security-first, deterministic, evidence-grounded, resilient,
bounded, observable, testable, portable and explainable security operations
platform.

Implementation priority:

```text
Security
→ Correctness
→ Contract compliance
→ End-to-end functionality
→ Reliability
→ Detection quality
→ Observability
→ Maintainability / DX
→ UI
→ Scalability
```

**Never weaken a security or correctness invariant to make a test, demo, benchmark
or visual result look better.**

---

## 2. Specification precedence

```text
1. Explicit security invariants
2. PRD.md product requirements
3. DESIGN.md technical decisions
4. AGENTS.md engineering conventions
5. Implementation preference
```

Rules:

- A security invariant may prevent an unsafe implementation even when a less-secure
  interpretation appears possible.
- Do not silently invent requirements.
- Do not silently override a product requirement with an implementation preference.
- If a genuine contradiction is found, document it rather than hiding it.
- `PRD.md` defines what the product must do, `DESIGN.md` how it is built, this file
  how contributors work, and `SPEC-AUDIT.md` records decisions already taken.
- **`SPEC-AUDIT.md` findings are historical.** Section 11 records which are
  resolved. Do not "fix" a finding that section 11 marks resolved without first
  checking the code.

---

## 3. Before coding

Inspect, in order:

1. The relevant `PRD.md` section.
2. The relevant `DESIGN.md` section.
3. This file's rules.
4. The existing implementation.
5. The relevant tests.
6. Migrations.
7. Configuration and limits.
8. Package manifests.
9. API and schema contracts.

For cross-cutting changes also inspect `tests/`, `packages/rules/`, `docs/decisions/`,
`deploy/` and `.github/`.

A change to a shared contract must be traced to every consumer:

```text
Agent → Parser → Normalizer → Validator → Ingestion
  → Storage → Detection → Correlation → AI context
  → API → SSE → UI → Fixtures → Tests
```

---

## 4. Repository structure

The canonical structure is in `DESIGN.md` §3. Do not restate it; reference it.

Hard rules:

- `apps/*` may import `internal/*`. `internal/*` must never import `apps/*`.
- `internal/storage/store.go` is the persistence contract. `internal/storage/postgres`
  and `internal/storage/memory` implement it. Domain code depends on the interface,
  never on pgx.
- Security-sensitive domain logic must not live only inside an HTTP handler.

---

## 5. Commands

```bash
make help           # list every target
make build          # both binaries into ./bin
make check          # gofmt check, go vet, unit tests
make test           # unit tests
make test-race      # unit tests with the race detector
make test-cover     # coverage summary
make test-e2e       # black-box agent + API test (needs a database)
make vuln           # govulncheck
make secrets        # gitleaks
make run            # run the API against the development database
make simulate       # run the synthetic scenario
make db-create      # create the development role and databases
```

`HALIMISOC_TEST_DATABASE_URL` must be set for `make test-e2e`. The end-to-end test
**truncates** the application tables and refuses to run unless the database name ends
in `_test`. Do not remove that guard.

---

## 6. Coding conventions

### 6.1 Go

- Standard library first. Justify every dependency in the pull request (see §12).
- `gofmt` clean. No exceptions.
- `go vet` clean. No exceptions.
- Wrap errors with context: `fmt.Errorf("ingest: persist event %s: %w", id, err)`.
- Define sentinel errors for conditions a caller must distinguish
  (`storage.ErrNotFound`, `validation.ErrClockSkew`). Never match on error strings.
- Use `context.Context` for cancellable work and honour its deadline.
- No global mutable state. Inject clocks and id generators so behaviour is
  testable — see `SetClock` and `SetIDGenerator` on the engine types.
- A field named `Raw`, `Detail` or `Message` is untrusted. Say so in its doc comment.

### 6.2 Comments explain *why*

A comment that restates the code is noise. Write the reason a reader cannot
reconstruct:

```go
// Bad: increments the counter
c++

// Good: the cooldown is checked before the threshold, so a burst that has already
// alerted does not re-run the (relatively expensive) window aggregation.
```

Every security-relevant decision gets the reason it was made, not just the fact.

### 6.3 Naming

- Identifiers carry a kind prefix: `evt_`, `alt_`, `inc_`, `agt_`, `tok_`, `usr_`,
  `sess_`, `aud_`. Use `id.New(id.KindX)`; never build an id by string concatenation.
- Event types are dotted and lowercase: `auth.ssh.login_failed`.
- Alert and incident statuses are uppercase; event-level enums (`severity`, `outcome`)
  are lowercase. This asymmetry is intentional and matches the contracts.
- Database columns are snake_case and match the JSON field names where both exist.

### 6.4 Language

- Code, comments, documentation and commits: **English**.
- Do not mix languages within a file.

---

## 7. Security rules

These are not guidelines. A change that violates one must be reverted.

### 7.1 Untrusted input

- Raw logs, agent payloads, timestamps, usernames, hostnames, paths, command lines,
  external enrichment and model output are untrusted.
- Untrusted input is validated at **one** boundary: `internal/events/validation`.
  Downstream code must not re-validate and must not assume validation happened.
- A parser must never panic on hostile input. Add an adversarial case to the test
  table for any new regex or index operation.
- **Never interpolate raw telemetry into an alert reason, an API response, a log
  line or a prompt.**

### 7.2 Credentials

- Passwords: Argon2id only. Never a fast hash.
- Tokens: store the SHA-256 hash only. The plaintext exists once, in the creating
  response, and is never persisted or logged.
- Compare every credential in constant time (`subtle.ConstantTimeCompare`).
- Never write a secret to disk, a log, an error message or a response.
- Redact before logging. `internal/secret` provides exact-value and pattern
  redaction; use them.

### 7.3 Query strings

Filters are only ever combined with `joinAnd` over a slice of small, **constant**
clauses built by the package's own `add` helper. The query string itself must be a
compile-time constant. If a change requires variable SQL text, the design is wrong.

### 7.4 Authorization

- Enforce server-side, per permission, in the handler. Hiding a UI control is not a
  control.
- The permission matrix is fail-closed. A new permission without a matrix entry
  denies for everyone.
- An agent credential is never an operator credential. An agent must not be able to
  read events, alerts or incidents.

### 7.5 CSRF

Every cookie-authenticated state-changing request requires the CSRF token. Bearer
token requests are exempt because a browser cannot set a custom header
cross-origin. Adding a mutating cookie-authenticated endpoint without
`requireCSRF` is a bug.

### 7.6 Rule files

- Rules are data. Never add an evaluator, a template engine or `exec`.
- Every numeric field needs a maximum.
- Unknown fields are rejected, not ignored.
- The whole set is validated before any rule is active.

---

## 8. Testing

### 8.1 Required per change

| Change | Required tests |
|---|---|
| New parser | valid, malformed, unsupported, missing field, oversized, adversarial (no panic) |
| New rule | positive, negative, threshold boundary, window boundary, duplicate, missing field, grouping, cooldown, version |
| New bound or limit | default is within maximum; a value above the maximum is clamped |
| New endpoint | authenticated, unauthenticated, unauthorized, invalid input, error shape |
| New state machine | every allowed transition and every rejected one |
| New AI behaviour | provider failure, malformed output, disabled mode, prompt injection |
| Migration | applied from empty, and applied over an existing database |

### 8.2 Test rules

- A test must fail if the control it covers is removed. Verify this by temporarily
  breaking the code before submitting.
- Table-driven tests with named cases.
- Name tests after the property, not the function.
- No sleeps for synchronisation except where a real timeout is the point.
- The black-box end-to-end test must remain deterministic and order-independent.
  If it needs shared state cleaned, use `resetDatabase`, which refuses to run unless
  the database name ends in `_test`.
- Do not assert on log output.
- A test that passes for the wrong reason is worse than no test. If an assertion
  feels loose, tighten it or delete it.

### 8.3 Coverage

Before submitting a security-critical package, run:

```bash
go test ./internal/<package>/ -cover
```

Existing coverage, which is the floor:

```text
metrics            89.8%      detection/engine 91.0%
detection/rules    87.0%      id               85.2%
detection/state    84.3%      parser           86.7%
validation         81.4%      correlation      83.6%
config             82.9%      auth             79.1%
ingest             82.1%      storage/memory   62.0%
notify             82.8%
```

Do not lower these to make a change easier to land.

---

## 9. End-to-end verification

The canonical flow:

```text
Agent fixture
   ↓
Authenticated ingestion
   ↓
PostgreSQL
   ↓
Detection
   ↓
Correlation
   ↓
Incident
   ↓
Authenticated API
   ↓
AI analysis (computed summary when no provider)
```

The path must also work with AI disabled all the way through incident creation.

Expected outcome of the shipped scenario, which is what `make test-e2e` asserts:

```text
10 events → 5 alerts (5 distinct rules) → 1 NEW critical incident, 5 ordered stages
```

Do not weaken an assertion to accommodate a change. If the outcome changed, either
the change is wrong or the expectation must be updated deliberately with a reason.

---

## 10. Migrations

- **An applied migration is immutable.** Change the schema with a new file. Editing
  an applied file leaves existing databases on the old schema while a fresh install
  gets the new one.
- One logical change per file. Name it `<number>_<description>.sql`.
- Migrate existing rows forward before adding a constraint that would reject them.
- Never drop a column or table in the same release that stops writing to it.
- Every foreign key states its delete behaviour explicitly.
- Every enum column has a `CHECK` constraint.
- Adding a column that a running binary will not tolerate requires the expand/contract
  pattern: add nullable, backfill, then constrain in a later migration.

---

## 11. Documentation

Update documentation in the same change as the code:

| Change | Update |
|---|---|
| Behaviour, contract, architecture | `DESIGN.md` |
| User-visible requirement | `PRD.md` |
| Process or convention | this file |
| Significant decision with alternatives | a new ADR in `docs/decisions/` |
| Endpoint or payload | `docs/api/` |
| Rule syntax or semantics | `docs/detection/` |
| Security property or limitation | `SECURITY.md` |
| Configuration | `.env.example` and `docs/security/configuration.md` |

An ADR is never edited to reflect a change of mind. Write a new one that supersedes
it and mark the old one superseded.

`README.md` must describe what the code actually does. Never state a capability that
is not implemented; list it under "Not built yet" instead.

---

## 12. Dependencies

Before adding one, answer:

```text
Does the standard library already solve this?
Does it add meaningful security or reliability value?
Does it introduce a new attack surface?
Does it increase maintenance cost?
Is it compatible with the single-node MVP?
```

Current dependency set, which is deliberately small:

```text
gopkg.in/yaml.v3          strict YAML decoding for rule files, including
                          KnownFields to reject unknown keys
github.com/jackc/pgx/v5   PostgreSQL driver and pool
golang.org/x/crypto       Argon2id, which is not in the standard library
```

Anything else needs a reason in the pull request. Avoid a dependency added only for
convenience.

---

## 13. Resource bounds

Every new bound is defined in `internal/config/limits.go` as a `Limit{Default, Max}`.

- The default is used when nothing is configured.
- A configured value above the maximum is clamped, not rejected.
- A negative or unparseable value falls back to the default.
- The bound is added to `Limits.Validate` and asserted in `TestDefaultLimitsAreBounded`.
- The bound is documented in `.env.example` and `docs/security/configuration.md`.

An unbounded buffer, queue, page, window or field is a bug.

---

## 14. Performance

The target is a small single node. Optimise for bounded work per event, not for peak
throughput.

- No query without a `LIMIT`.
- No loop whose iteration count comes from untrusted input.
- No lock held across I/O.
- Detection state is bounded on every axis.
- Parsing must be linear in input length: no regex with nested quantifiers.

Measure before optimising. Do not trade clarity for a speedup you have not measured.

---

## 15. Failure behaviour

| Component | Failure | Behaviour |
|---|---|---|
| Agent | server unreachable | spool, back off with jitter, keep collecting |
| Agent | credential rejected (401) | exit: spooled telemetry could never be delivered |
| Agent | spool full | drop oldest, count, report degraded |
| API | malformed event in a batch | reject that event, ingest the rest |
| API | correlation failure | record it, keep the alert ungrouped, still return 202 |
| API | AI provider failure | return the computed summary |
| API | database unreachable | fail the request; readiness reports not-ready |
| Detection | rule file invalid | refuse to start |

The general rule: a failure in an enrichment path must not fail the path it enriches,
and a failure that cannot be recovered from must be loud at startup rather than quiet
at runtime.

---

## 16. CI/CD

CI runs:

```text
gofmt check · go vet · race-enabled unit tests
coverage report · black-box end-to-end test against PostgreSQL
both binary builds · govulncheck · gitleaks · Docker builds
```

Do not suppress a security finding to produce a green build. Accepted risk is
documented in `SECURITY.md`.

---

## 17. Commit and review hygiene

- One logical change per commit.
- Commit message states the **why**, not the what: the what is in the diff.
- Never commit `.env`, a key, a token or spooled telemetry. `.gitignore` covers these;
  verify with `make secrets`.
- A pull request that changes a contract must update every consumer listed in §3.
- A pull request that fixes a bug adds the test that would have caught it.

---

## 18. Out of scope for the MVP

Do not add these without a decision that explicitly changes the MVP boundary:

```text
autonomous response · real response execution · multi-tenant SaaS
distributed detection · persistent detection state · graph correlation
custom ML · required Redis/NATS/Kafka/ClickHouse/Kubernetes
broad external integrations · arbitrary natural-language SQL generation
enterprise SSO/MFA
```

---

## 19. Final rule

> **HalimiSOC must tell a believable security story: from raw telemetry to immutable
> normalized events, deterministic detection, explainable incident correlation,
> evidence-grounded AI assistance, and safe human-understandable recommendations.**

The best implementation is not the one with the most technologies. It is the one
that makes the pipeline secure, correct, bounded, reliable, explainable, observable,
testable and portable — and that keeps AI firmly in the role of an analyst copilot
rather than a security authority.
