# HalimiSOC --- Specification Audit

**Document:** `SPEC-AUDIT.md`\
**Audit scope:** `PRD.md` + `DESIGN.md` + `AGENTS.md`\
**Audit status:** Draft --- Pre-Revision\
**Audit objective:** Identify contradictions, ambiguities, missing
contracts, security gaps, reliability gaps, and cross-document
inconsistencies before rewriting the three source documents.

------------------------------------------------------------------------

## 0. Executive Summary

HalimiSOC already has a strong architectural direction:

``` text
Telemetry
  ↓
Parse
  ↓
Normalize
  ↓
Validate
  ↓
Detect
  ↓
Correlate
  ↓
Incident
  ↓
AI Assistance
```

The documents consistently establish deterministic detection as the
security source of truth, AI as an advisory copilot, bounded resource
usage, explicit authorization, and a lightweight single-node MVP.

The main problem is no longer missing product ideas. The main problem is
**specification precision**.

Several important behaviors are described conceptually but are not yet
contractual enough for two independent engineers or AI coding agents to
implement the same behavior.

### Current audit assessment

  Area                         Status
  ---------------------------- ------------------------------------
  Product vision               🟢 Strong
  MVP direction                🟢 Strong
  Security principles          🟢 Strong
  Architecture direction       🟢 Strong
  AI trust boundary            🟢 Strong
  Event contract               🟡 Needs hardening
  Agent lifecycle              🟡 Needs hardening
  Detection semantics          🟡 Needs hardening
  Correlation semantics        🟡 Ambiguous
  Severity authority           🟡 Ambiguous
  Retention/deletion           🟡 Incomplete
  Resource limits              🟡 Incomplete
  API contracts                🟡 Incomplete
  Cross-document consistency   🔴 Needs revision
  AI-agent instructions        🟡 Needs stronger precedence rules

**Conclusion:** Do not rewrite `PRD.md`, `DESIGN.md`, or `AGENTS.md`
independently yet. Resolve the P0 decisions in this document first, then
rewrite the three documents from those decisions.

------------------------------------------------------------------------

# 1. Audit Method

This audit compares the three documents across:

1.  Product scope
2.  MVP boundaries
3.  Functional requirements
4.  Data contracts
5.  API contracts
6.  Agent lifecycle
7.  Detection behavior
8.  Correlation behavior
9.  Incident lifecycle
10. Authentication and authorization
11. AI trust boundaries
12. Response automation
13. Retention and deletion
14. Resource limits
15. Observability
16. Testing
17. Deployment
18. Repository structure
19. Terminology
20. Requirement precedence

Severity levels:

-   **P0 --- Blocking:** Must be resolved before serious implementation.
-   **P1 --- Important:** Should be resolved before feature completion.
-   **P2 --- Cleanup:** Documentation/consistency issue that should be
    fixed during rewrite.

Finding types:

-   **CONTRADICTION:** Two documents or sections define incompatible
    behavior.
-   **AMBIGUITY:** Multiple reasonable implementations are possible.
-   **MISSING:** A required contract/behavior is not defined.
-   **WEAK CONTRACT:** Intent exists but is not precise enough to test.
-   **CLEANUP:** Minor documentation quality issue.

------------------------------------------------------------------------

# 2. P0 --- Blocking Findings

## AUD-001 --- RBAC Is Simultaneously MVP and V2

**Type:** CONTRADICTION\
**Priority:** P0

### Evidence

`PRD.md` defines three MVP roles:

``` text
ADMIN
ANALYST
READONLY
```

and explicitly places them under MVP authentication/authorization.

However, the future roadmap later lists:

``` text
V2
- RBAC
```

`DESIGN.md` and `AGENTS.md` also already describe RBAC conceptually.

### Problem

An implementation agent can reasonably interpret this in two
incompatible ways:

-   MVP requires RBAC.
-   RBAC is deferred to V2.

### Recommended decision

**MVP includes simple RBAC.**

V2 should instead mean:

-   fine-grained permissions;
-   enterprise identity;
-   OIDC/SSO;
-   MFA;
-   richer policy controls.

### Required rewrite

Replace the V2 roadmap item `RBAC` with something such as:

``` text
Fine-grained authorization / enterprise RBAC
```

------------------------------------------------------------------------

## AUD-002 --- Safe Response Actions Have Conflicting MVP Scope

**Type:** CONTRADICTION\
**Priority:** P0

### Evidence

`PRD.md` says response actions are:

``` text
Post-MVP
```

but also says:

``` text
Response actions must require explicit user approval in the initial implementation.
```

`DESIGN.md` and `AGENTS.md` define a complete human-approved response
flow.

### Problem

It is unclear whether MVP implements:

1.  recommendations only, or
2.  actual infrastructure-changing actions behind approval.

### Recommended decision

For MVP:

``` text
AI → Recommendation only
```

No infrastructure-changing execution.

Post-MVP:

``` text
Recommendation
→ Human Review
→ Explicit Approval
→ Independent Authorization
→ Controlled Backend Action
→ Audit Log
```

### Rationale

This keeps the MVP aligned with the stated non-goal of not becoming a
SOAR/autonomous response platform while preserving the security
architecture for future controlled response.

------------------------------------------------------------------------

## AUD-003 --- Event ID Ownership Is Undefined

**Type:** AMBIGUITY / MISSING\
**Priority:** P0

### Evidence

The documents require unique/stable event IDs and duplicate-safe
ingestion, but do not explicitly define who creates the ID.

### Problem

Possible implementations include:

``` text
Agent-generated
Server-generated
Parser-generated
Database-generated
```

These have different idempotency semantics.

### Recommended decision

For MVP:

``` text
Agent/parser creates immutable event.id.
Server treats event.id as the idempotency key.
Database enforces uniqueness.
```

Recommended invariant:

``` text
UNIQUE(event.id)
```

Duplicate submission must not create a second canonical event.

### Required tests

-   same event submitted twice;
-   same event replayed after outage;
-   batch containing duplicates;
-   duplicate event arriving after detection already occurred.

------------------------------------------------------------------------

## AUD-004 --- Event Timestamp Semantics Are Incomplete

**Type:** MISSING\
**Priority:** P0

### Evidence

The documents require UTC timestamps and explicitly say client-provided
timestamps must not simply be trusted.

However, the canonical event model contains only:

``` text
timestamp
```

### Problem

Detection and correlation depend on time windows. There is no
distinction between:

``` text
event occurrence time
ingestion time
```

An agent clock can be wrong or maliciously manipulated.

### Recommended decision

The canonical model should distinguish at least:

``` text
event_time
ingested_at
```

Rules:

-   `event_time` describes when the source claims the event happened.
-   `ingested_at` is assigned by the trusted server.
-   Detection/correlation policies must explicitly state which clock
    they use.
-   Suspicious clock skew should be observable rather than silently
    destroying the event.

------------------------------------------------------------------------

## AUD-005 --- Clock Skew Policy Is Missing

**Type:** MISSING\
**Priority:** P0

### Problem

Two agents may have different clocks. A timestamp outside the expected
range can distort:

-   sliding windows;
-   correlation;
-   incident ordering;
-   dashboard timelines.

### Recommended decision

Define a configurable skew tolerance, for example:

``` text
accepted event_time skew: configurable
```

Events outside the tolerance should remain ingestible where safe but
carry timestamp-anomaly metadata/metrics.

Do not silently discard security telemetry solely because its timestamp
is unusual.

------------------------------------------------------------------------

## AUD-006 --- Detection State Restart Semantics Are Undefined

**Type:** AMBIGUITY\
**Priority:** P0

### Evidence

The MVP intentionally uses in-memory TTL detection state. `DESIGN.md`
explicitly lists persistent state as future functionality.

### Problem

If the server restarts halfway through a brute-force window, counters
disappear.

Example:

``` text
4 failed attempts
↓
server restart
↓
1 failed attempt
```

Does the system detect five attempts or only one?

### Recommended decision

For MVP:

``` text
Detection state is ephemeral.
Process restart resets in-memory sliding-window state.
```

This is acceptable if explicitly documented.

Future persistent/distributed detection state can be introduced when
required.

### Required test

Verify restart behavior so it is intentional rather than accidental.

------------------------------------------------------------------------

## AUD-007 --- Correlation Matching Semantics Are Too Vague

**Type:** AMBIGUITY\
**Priority:** P0

### Evidence

Correlation uses:

-   source IP;
-   destination IP;
-   host;
-   user;
-   service;
-   session;
-   stage windows.

The documents repeatedly say correlation must be conservative, but do
not define the actual matching policy.

### Problem

For example:

``` text
Alert A:
src_ip=1.2.3.4
host=server-01

Alert B:
src_ip=1.2.3.4
host=server-02
```

Should these be one incident?

Different implementations will answer differently.

### Recommended decision

Define correlation criteria explicitly.

For example:

``` text
Strong identity:
session_id

Strong host context:
host + user

Network context:
host + src_ip

Weak context:
src_ip only
```

Correlation rules should specify required and optional entities instead
of relying on generic "entity resolution."

Every correlation decision should record a machine-readable reason.

------------------------------------------------------------------------

## AUD-008 --- Severity Authority Is Not Explicitly Defined

**Type:** AMBIGUITY\
**Priority:** P0

### Problem

There are at least three severity concepts:

``` text
event severity
alert severity
incident severity
```

The documents state that client-provided severity cannot be trusted and
that incident severity must be evidence-driven, but they do not
explicitly define the authority chain.

### Recommended decision

Use:

``` text
Event severity
  = informational source metadata only

Alert severity
  = deterministic rule output

Incident severity
  = deterministic correlation/incident policy
```

AI output must never change severity.

Recommended invariant:

``` text
AI cannot promote, downgrade, or authorize severity.
```

------------------------------------------------------------------------

## AUD-009 --- AI Confidence Has Unsafe Semantic Ambiguity

**Type:** WEAK CONTRACT\
**Priority:** P0

### Evidence

The AI output example includes:

``` json
"confidence": 0.91
```

but the documents do not define what that number means.

### Problem

Users may interpret:

``` text
91%
```

as a calibrated probability that an attack occurred.

An LLM confidence value is not automatically a calibrated security
probability.

### Recommended decision

Either:

1.  remove `confidence` from MVP, or
2.  rename/document it as informational model self-assessment only.

It must never be used for:

-   detection;
-   severity;
-   incident promotion;
-   authorization;
-   response execution.

------------------------------------------------------------------------

## AUD-010 --- AI Evidence Grounding Needs a Hard Invariant

**Type:** WEAK CONTRACT\
**Priority:** P0

### Evidence

AI output contains `evidence_ids`, and the documents require evidence
mapping.

### Missing invariant

The system does not explicitly require factual claims about observed
telemetry to be traceable to evidence.

### Recommended decision

For observed telemetry claims:

``` text
claim
→ evidence_id(s)
→ canonical event/alert/incident
```

If no evidence supports a factual claim:

``` text
AI must state insufficient evidence
```

The AI must distinguish:

``` text
Observed
Inferred
Unknown
```

------------------------------------------------------------------------

## AUD-011 --- Agent Enrollment Lifecycle Is Underspecified

**Type:** MISSING\
**Priority:** P0

### Evidence

The PRD exposes:

``` text
POST /api/v1/agents/register
```

and requires per-agent authentication tokens.

### Problem

The bootstrap trust process is not defined.

A secure system needs to answer:

``` text
How does a new agent obtain its first credential?
How long is bootstrap authority valid?
When is the final token issued?
Can an enrollment token be reused?
```

### Recommended decision

Use a short-lived enrollment flow:

``` text
Admin creates enrollment credential
        ↓
Agent enrolls
        ↓
Server validates enrollment credential
        ↓
Server creates agent identity
        ↓
Server issues long-lived/rotatable agent credential
        ↓
Enrollment credential becomes unusable
```

Exact implementation can be decided in `DESIGN.md`, but lifecycle
invariants must live in the specification.

------------------------------------------------------------------------

## AUD-012 --- Agent Token Storage Semantics Are Missing

**Type:** MISSING\
**Priority:** P0

### Problem

Token rotation and revocation are required, but the documents do not
state whether server-side storage contains plaintext tokens.

### Recommended decision

Prefer:

``` text
Generated token
    ↓
shown/stored securely by operator once
    ↓
server stores verifier/hash
```

The database should not require plaintext agent tokens for normal
authentication.

Also define:

-   token status;
-   created_at;
-   revoked_at;
-   rotated_at;
-   last_used_at where useful;
-   optional expiration.

------------------------------------------------------------------------

## AUD-013 --- Ingestion Idempotency Is Mentioned but Not Fully Contracted

**Type:** WEAK CONTRACT\
**Priority:** P0

### Evidence

Duplicate handling is required by PRD and AGENTS.

### Missing behavior

No exact response semantics exist for duplicate events.

### Recommended decision

Define:

``` text
First submission:
create canonical event

Repeated submission with same event.id:
return idempotent success / existing identity
do not create duplicate event
do not create duplicate detection side effects
```

Detection must also be duplicate-safe.

------------------------------------------------------------------------

## AUD-014 --- API Resource Limits Are Not Concrete Enough

**Type:** MISSING\
**Priority:** P0

### Evidence

The documents require:

-   request size limits;
-   batch size limits;
-   field limits;
-   pagination/query limits;
-   bounded query results.

### Problem

No normative defaults/maxima are defined.

### Required contract categories

Define limits for:

``` text
HTTP request body
event batch count
individual field length
raw line length
multiline buffer
AI context size
query result size
page size
SSE connections
concurrent AI requests
```

Exact numbers can be configuration defaults, but the specification must
require both:

``` text
default
maximum
```

------------------------------------------------------------------------

## AUD-015 --- Retention and Deletion Semantics Are Incomplete

**Type:** MISSING\
**Priority:** P0

### Evidence

The design distinguishes structured event retention from shorter raw
evidence retention.

### Missing

What happens when raw evidence expires?

### Recommended decision

Structured events remain queryable after raw evidence expires.

For example:

``` text
Structured event
  ↓
longer retention

Raw evidence
  ↓
shorter retention
```

Incident references must remain valid even if the raw line is no longer
available.

The UI should explicitly indicate:

``` text
Raw evidence expired / unavailable
```

rather than pretending it exists.

------------------------------------------------------------------------

## AUD-016 --- Spool Overflow Policy Is Not Finalized

**Type:** MISSING\
**Priority:** P0

### Evidence

`DESIGN.md` explicitly says oldest/newest policy must be documented, but
the actual policy is not selected.

### Problem

When the disk spool is full, the system must choose what to sacrifice.

### Recommended decision

Define:

-   maximum spool size;
-   overflow behavior;
-   event-loss accounting;
-   metric emitted;
-   operator visibility.

Never silently drop security telemetry.

At minimum, any loss must be observable through:

``` text
events_dropped_total
```

plus a reason.

------------------------------------------------------------------------

## AUD-017 --- Database Integrity Constraints Need to Be Contractual

**Type:** MISSING\
**Priority:** P0

### Evidence

The documents define conceptual entities but not enough relational
invariants.

### Recommended minimum constraints

``` text
events.id UNIQUE

agent_tokens verifier uniqueness as appropriate

alerts.id PRIMARY KEY
incidents.id PRIMARY KEY

foreign keys:
event → agent/asset
alert → rule
alert → event evidence
incident → alerts
incident → events
AI analysis → incident
audit log → actor/resource where applicable
```

Also define deletion behavior intentionally.

Security telemetry should not disappear accidentally because a parent
row was deleted.

------------------------------------------------------------------------

# 3. P1 --- Important Findings

## AUD-018 --- API Error Contract Is Not Standardized

Every API endpoint is required to have a structured error response, but
the shared error schema is not defined.

### Recommended

Create a common contract such as:

``` json
{
  "error": {
    "code": "EVENT_SCHEMA_INVALID",
    "message": "Event payload is invalid.",
    "request_id": "req_..."
  }
}
```

Do not expose:

-   stack traces;
-   SQL;
-   internal filesystem paths;
-   provider secrets.

------------------------------------------------------------------------

## AUD-019 --- Authentication/RBAC Matrix Is Missing

Roles exist, but exact permissions are not.

Create a matrix:

  Operation                   ADMIN          ANALYST   READONLY
  ------------------------- ------- ---------------- ----------
  View events                     ✓                ✓          ✓
  View incidents                  ✓                ✓          ✓
  Run AI analysis                 ✓                ✓   optional
  Modify incident status          ✓                ✓          ✗
  Modify rules                    ✓     ✗/controlled          ✗
  Manage agents                   ✓     ✗/controlled          ✗
  Manage users                    ✓                ✗          ✗
  Approve future response         ✓   policy-defined          ✗

The exact matrix should be finalized during PRD revision.

------------------------------------------------------------------------

## AUD-020 --- SSE Revocation Lifecycle Needs an Explicit Mechanism

The documents require an SSE connection to terminate after session
revocation.

### Missing

How is an already-open stream notified?

### Recommended design contract

``` text
session revoked
    ↓
active SSE connection becomes invalid
    ↓
connection terminated
```

The exact implementation can use connection registries, periodic
authorization checks, or another mechanism.

The behavior is what must be contractual.

------------------------------------------------------------------------

## AUD-021 --- Trusted Proxy / Forwarded Header Policy Is Missing

The product is expected to run behind reverse proxies in many
deployments.

The specification should define:

-   whether `X-Forwarded-For` is trusted;
-   which proxy addresses are trusted;
-   how client IP is derived;
-   how rate limiting uses client IP;
-   how audit logs record source IP.

Never trust arbitrary forwarded headers from untrusted clients.

------------------------------------------------------------------------

## AUD-022 --- Attack Simulator Needs Stronger Isolation Guarantees

The simulator is described as synthetic and safe, but the security
boundary should be explicit.

### Recommended invariant

Simulator must not:

-   execute arbitrary shell commands;
-   scan external hosts;
-   modify real SSH configuration;
-   modify real firewall rules;
-   modify real `authorized_keys`;
-   contact attacker-controlled/external targets.

Simulation should inject synthetic events into the same safe pipeline.

Simulation events should be clearly marked as test/demo data.

------------------------------------------------------------------------

## AUD-023 --- Simulation Metadata Needs a Contract

`DESIGN.md` says simulation events should carry explicit demo/test
metadata, but no field is defined.

### Recommended

Add a stable field such as:

``` text
event.context.origin = "simulation"
```

or equivalent.

The UI must clearly distinguish:

``` text
REAL
SIMULATED
```

without changing the detection semantics.

------------------------------------------------------------------------

## AUD-024 --- Event Ordering Semantics Are Missing

Events can arrive out of order because of:

-   network delay;
-   disk spool replay;
-   agent clock differences.

The documents define timestamps but not ordering.

### Recommended

Use:

``` text
event_time
ingested_at
```

and define that UI timelines are sorted by event time with deterministic
tie-breaking.

Never assume ingestion order equals occurrence order.

------------------------------------------------------------------------

## AUD-025 --- Detection Cooldown/Deduplication Needs Exact Semantics

`AGENTS.md` includes cooldown/deduplication in the rule model, but the
PRD does not define how it works.

### Questions to resolve

-   Does cooldown suppress alert creation?
-   Does it suppress only duplicate alerts?
-   Does it reset the counter?
-   Does an event during cooldown still contribute to incident
    correlation?
-   Is cooldown per rule, per key, or global?

This should become an explicit rule contract.

------------------------------------------------------------------------

## AUD-026 --- Alert and Incident Lifecycle Definitions Differ

`PRD.md` alert statuses:

``` text
OPEN
ACKNOWLEDGED
RESOLVED
DISMISSED
```

`DESIGN.md` incident lifecycle:

``` text
NEW
ACKNOWLEDGED
INVESTIGATING
RESOLVED
FALSE_POSITIVE
```

### Problem

The two lifecycle models are not aligned, and mutation permissions are
not fully defined.

### Recommended

Keep alert and incident lifecycle intentionally separate, but define:

-   valid states;
-   valid transitions;
-   actor permissions;
-   audit requirements;
-   whether terminal states can reopen.

------------------------------------------------------------------------

## AUD-027 --- Incident Severity Update Semantics Are Missing

If an incident starts as:

``` text
HIGH
```

and later receives a critical alert, does it become:

``` text
CRITICAL
```

Likely yes, but this should be explicit.

### Recommended

Define a deterministic incident severity policy.

For example:

``` text
incident severity = highest severity of qualifying correlated evidence
```

or another documented policy.

AI must not participate in the calculation.

------------------------------------------------------------------------

## AUD-028 --- Rule Versioning Semantics Are Incomplete

Rules have:

``` text
id
version
```

but it is not defined whether historical alerts preserve the exact rule
version that triggered them.

### Recommended

An alert must store:

``` text
rule_id
rule_version
```

so historical detection remains explainable after a rule changes.

------------------------------------------------------------------------

## AUD-029 --- Rule Reload Semantics Are Missing

The documents define safe rule loading but do not define runtime reload
behavior.

Questions:

-   Are rules loaded only at startup?
-   Can an administrator modify them live?
-   What happens to an invalid update?
-   Does the previous valid version remain active?

### Recommended MVP

Rules are loaded at startup and/or through an explicitly transactional
reload mechanism.

Invalid updates must not replace the last known-good configuration.

------------------------------------------------------------------------

## AUD-030 --- AI Provider Failure Behavior Needs Explicit Product Behavior

AI is optional, but the UX behavior when the provider fails is not fully
specified.

### Recommended

If AI is unavailable:

``` text
Detection continues.
Correlation continues.
Incident creation continues.
Dashboard remains functional.
AI panel reports unavailable/error state.
```

No security workflow should depend on AI availability.

------------------------------------------------------------------------

## AUD-031 --- AI Concurrency and Cost Controls Need Normative Limits

The documents mention bounded AI requests and budget controls but do not
define:

-   max concurrent requests;
-   timeout;
-   retry count;
-   maximum context size;
-   per-user/request rate limit.

These should become configuration-backed limits.

------------------------------------------------------------------------

## AUD-032 --- AI Output Validation Needs More Detail

Structured output is required, but malformed model output behavior is
not fully defined.

### Recommended

Pipeline:

``` text
LLM response
 ↓
size limit
 ↓
strict schema validation
 ↓
semantic validation
 ↓
evidence ID validation
 ↓
persist
```

Invalid model output must never be treated as trusted domain data.

------------------------------------------------------------------------

## AUD-033 --- Audit Log Scope Needs Broader Coverage

The documents include many privileged operations, but the exact
mandatory audit events should be normalized.

At minimum include:

-   login success/failure where appropriate;
-   session revocation;
-   agent enrollment;
-   token creation/revocation/rotation;
-   rule changes;
-   incident status changes;
-   alert status changes;
-   AI analysis request where security-relevant;
-   future response approval/execution.

Do not log secrets.

------------------------------------------------------------------------

## AUD-034 --- Audit Log Integrity Expectations Need Explicit Scope

The documents correctly avoid claiming tamper-proof storage.

Still define:

``` text
MVP:
ordinary protected audit log

Future:
tamper-resistant / append-only / external evidence storage
```

This prevents accidental claims in README/demo material.

------------------------------------------------------------------------

## AUD-035 --- Query Pagination Strategy Is Not Defined

The dashboard requires event/incident filtering, but no pagination
strategy is selected.

### Recommended

For event-heavy views, prefer cursor pagination based on a stable
ordering key.

Define:

``` text
default page size
maximum page size
sort field
sort direction
cursor semantics
maximum query window
```

------------------------------------------------------------------------

## AUD-036 --- Data Access Authorization Scope Is Not Fully Defined

"Authorization required" is present, but it is not always clear whether
all authenticated analysts can view all assets/events.

This matters for future multi-user environments.

### Recommended MVP

Explicitly state:

``` text
single-organization/single-tenant authorization scope
```

or define asset-level authorization if actually needed.

Do not accidentally imply multi-tenant isolation in the MVP.

------------------------------------------------------------------------

# 4. P2 --- Documentation and Consistency Findings

## AUD-037 --- Risk Numbering Error

`PRD.md` contains:

``` text
Risk 6 — Agent Reliability
...
Risk 9 — Unsafe Rules-as-Data
Risk 6 — Unsafe Response Automation
```

The final response risk should receive its own number.

------------------------------------------------------------------------

## AUD-038 --- `FR-14` Is Labeled "Future MVP+" Inside Functional Requirements

`FR-14 — Natural Language Investigation` is explicitly described as a
future MVP+ feature.

This should be moved into a clearly labeled future section or explicitly
tagged:

``` text
Status: POST-MVP
```

Otherwise an AI coding agent may implement it as MVP scope.

------------------------------------------------------------------------

## AUD-039 --- "Should" vs "Must" Is Inconsistent

Examples include:

``` text
should support
should provide
where useful
where practical
```

For security-critical behavior, normative language must be explicit.

Recommended vocabulary:

``` text
MUST
SHOULD
MAY
```

Use `MUST` for security invariants and acceptance criteria.

------------------------------------------------------------------------

## AUD-040 --- Repository Structures Differ Slightly

`AGENTS.md`, `PRD.md`, and `DESIGN.md` describe slightly different
repository layouts.

Examples:

-   `DESIGN.md` includes `docs/architecture/`, `docs/api/`,
    `docs/detection/`, `docs/security/`, `docs/decisions/`.
-   `PRD.md` uses flatter documentation files.

### Recommended

Choose one canonical repository structure in `DESIGN.md`.

`AGENTS.md` should reference it rather than duplicating the full tree
unless necessary.

------------------------------------------------------------------------

## AUD-041 --- Threat Model Section Numbering Is Incorrect

`PRD.md` labels the section:

``` text
## 19. Security Threat Model — MVP
```

but subsections begin:

``` text
### 18.1 Assets
```

This is a documentation bug and should be corrected during rewrite.

------------------------------------------------------------------------

## AUD-042 --- "Product Source of Truth" and "Requirement Precedence" Need Explicit Rules

`AGENTS.md` says:

``` text
PRD = product source of truth
DESIGN = technical/design reference
```

But it does not define what happens when:

``` text
PRD ↔ DESIGN conflict
PRD ↔ AGENTS conflict
DESIGN ↔ AGENTS conflict
```

### Recommended precedence

``` text
1. Explicit security invariants
2. PRD product requirements
3. DESIGN technical decisions
4. AGENTS engineering conventions
5. Implementation preference
```

A conflict should not be silently resolved by the coding agent.

------------------------------------------------------------------------

# 5. Cross-Document Contract Matrix

The following should become the canonical relationship between
documents:

  -------------------------------------------------------------------------------
  Contract         PRD            DESIGN           AGENTS         Test
  ---------------- -------------- ---------------- -------------- ---------------
  Event schema     Requirement    Implementation   Change rule    Schema tests

  Event            Requirement    DB/API behavior  MUST preserve  Ingestion tests
  ID/idempotency                                                  

  Agent lifecycle  Requirement    Enrollment       Security rules Agent tests
                                  design                          

  Detection rules  Product        Engine design    Coding rules   Rule tests
                   behavior                                       

  Correlation      Product        Matching         Safety rules   Correlation
                   outcome        algorithm                       tests

  Severity         Product        Calculation      MUST not trust Severity tests
                   semantics                       client/AI      

  Auth             Requirement    Session design   Security rules Auth tests

  RBAC             MVP scope      Authorization    Server-side    RBAC tests
                                  model            enforcement    

  SSE              UX requirement Stream design    Security rules SSE tests

  AI               Product        Context/output   Trust boundary AI tests
                   capability     design                          

  Response         Future         Security flow    Approval rule  Future action
                   capability                                     tests

  Retention        Product policy Storage          DB rules       Retention tests
                                  implementation                  

  Observability    Product        Metrics design   Logging rules  Health/metric
                   requirement                                    tests
  -------------------------------------------------------------------------------

------------------------------------------------------------------------

# 6. Proposed Canonical Decisions

These are **recommended decisions**, not yet accepted requirements.

They should be reviewed and accepted before the three source documents
are rewritten.

## DEC-001 --- MVP RBAC

``` text
MVP supports ADMIN, ANALYST, READONLY.
```

Enterprise/fine-grained authorization is future scope.

## DEC-002 --- MVP Response Scope

``` text
MVP = recommendations only.
No infrastructure-changing response execution.
```

## DEC-003 --- Event Identity

``` text
event.id is producer-generated, immutable, globally unique within the product,
and used as the ingestion idempotency key.
```

## DEC-004 --- Event Time

``` text
event_time = source occurrence timestamp
ingested_at = server receipt timestamp
```

## DEC-005 --- Detection State

``` text
MVP detection state is in-memory and ephemeral.
Restart resets state.
```

## DEC-006 --- Severity

``` text
Event severity = source metadata.
Alert severity = deterministic rule.
Incident severity = deterministic correlation/incident policy.
AI cannot change severity.
```

## DEC-007 --- AI Grounding

``` text
Observed telemetry claims require evidence references.
Unsupported factual claims must be marked unknown/insufficient evidence.
```

## DEC-008 --- AI Confidence

``` text
Confidence is informational only, or removed from MVP.
Never used for detection, severity, authorization, or response.
```

## DEC-009 --- Agent Credentials

``` text
Enrollment credential → agent identity → rotatable agent credential.
Server does not require plaintext long-lived tokens for normal verification.
```

## DEC-010 --- Duplicate Ingestion

``` text
Duplicate event IDs are idempotent.
Repeated submission must not create duplicate canonical events or duplicate detection side effects.
```

## DEC-011 --- Retention

``` text
Structured events outlive raw evidence.
Expired raw evidence must be represented as unavailable, not silently fabricated.
```

## DEC-012 --- Simulator

``` text
Simulation is synthetic and isolated.
It never executes real-world attack actions.
Simulation metadata is explicit.
```

------------------------------------------------------------------------

# 7. Required Rewrite Order

Do not rewrite all three files simultaneously.

Use this sequence:

``` text
SPEC-AUDIT.md
     ↓
Accept/reject DEC-* decisions
     ↓
Rewrite PRD.md
     ↓
Rewrite DESIGN.md
     ↓
Rewrite AGENTS.md
     ↓
Cross-document audit
     ↓
Traceability matrix
     ↓
Implementation
```

### PRD responsibility

Define:

``` text
WHAT
WHY
MVP / POST-MVP
USER VISIBLE BEHAVIOR
ACCEPTANCE CRITERIA
```

### DESIGN responsibility

Define:

``` text
HOW
COMPONENTS
DATA FLOW
DATA MODEL
API CONTRACTS
FAILURE MODES
SECURITY BOUNDARIES
```

### AGENTS responsibility

Define:

``` text
HOW CONTRIBUTORS/AI AGENTS MUST WORK
CODING RULES
SECURITY INVARIANTS
TESTING RULES
CHANGE DISCIPLINE
```

------------------------------------------------------------------------

# 8. Proposed Final Traceability Model

Every important MVP requirement should eventually have:

``` text
Requirement
    ↓
PRD ID
    ↓
DESIGN section
    ↓
AGENTS rule
    ↓
Implementation
    ↓
Automated test
```

Example:

``` text
FR-05 Event Ingestion
        ↓
DESIGN — Event Ingestion
        ↓
AGENTS — API + Idempotency Rules
        ↓
apps/api/events/*
        ↓
ingestion_idempotency_test
        ↓
E2E duplicate replay test
```

If a requirement has no testable behavior, it should be reviewed for
ambiguity.

------------------------------------------------------------------------

# 9. Definition of Audit Complete

The specification audit is considered complete only when:

-   [ ] All P0 contradictions are resolved.
-   [ ] All P0 ambiguities have explicit decisions.
-   [ ] Event identity is contractual.
-   [ ] Event timestamp semantics are contractual.
-   [ ] Agent enrollment lifecycle is contractual.
-   [ ] Agent token lifecycle is contractual.
-   [ ] Detection restart semantics are contractual.
-   [ ] Correlation matching semantics are contractual.
-   [ ] Severity authority is contractual.
-   [ ] AI evidence grounding is contractual.
-   [ ] API limits have explicit policy.
-   [ ] Retention/deletion behavior is contractual.
-   [ ] Spool overflow behavior is contractual.
-   [ ] Database integrity rules are contractual.
-   [ ] RBAC scope is unambiguous.
-   [ ] Response execution scope is unambiguous.
-   [ ] MVP/Post-MVP boundaries are unambiguous.
-   [ ] Requirement precedence is explicit.
-   [ ] Repository structure has one canonical definition.
-   [ ] Terminology is consistent.
-   [ ] Every critical requirement can map to a test.

------------------------------------------------------------------------

# 10. Final Audit Position

HalimiSOC does **not** need a bigger feature set right now.

It needs a tighter contract.

The strongest parts of the current specification are:

``` text
Security-first
Deterministic detection
Evidence-linked incidents
AI as copilot
Untrusted telemetry boundary
Bounded resource usage
Resilient agent
Single-node MVP
Observable pipeline
Safe synthetic simulation
```

The highest-risk remaining issue is specification ambiguity around:

``` text
identity
time
correlation
severity
credentials
retention
resource limits
MVP boundaries
```

The goal of the next revision is therefore not to make HalimiSOC "more
sophisticated."

The goal is:

> **Make the intended behavior precise enough that a competent
> engineer---or an AI coding agent---cannot reasonably implement two
> different systems from the same documents.**

Only after the P0 decisions are accepted should `PRD.md`, `DESIGN.md`,
and `AGENTS.md` be rewritten.

------------------------------------------------------------------------

# 11. Resolution Record

**Audited document versions:** `PRD.md` v0.3.0, `DESIGN.md` v1.2.0,
`AGENTS.md` v1.2.0.

This section records which findings above are now resolved and which remain
open. It exists because the findings in sections 2–4 were written against
earlier drafts, and an agent reading a stale finding as open would "fix"
something that is already correct.

Nothing above this line has been edited. Where a finding turned out to be
already addressed, that is recorded here rather than by rewriting the finding.

## 11.1 Accepted decisions

All `DEC-*` decisions in section 6 are accepted. They are implemented, and each
one is backed by an ADR under `docs/decisions/`.

| Decision | Status | Implemented in | ADR |
|---|---|---|---|
| DEC-001 MVP RBAC (ADMIN/ANALYST/READONLY) | Resolved | `internal/authorization` | 009 |
| DEC-002 MVP is recommendation-only, no response execution | Resolved | no response endpoint exists | 004 |
| DEC-003 `event.id` is producer-generated and the idempotency key | Resolved | `internal/events/model`, `internal/id` | 006 |
| DEC-004 `event_time` vs `ingested_at` (`received_at`) | Resolved | `internal/events/model`, migration `0001_init.sql` | 007 |
| DEC-005 detection state is in-memory and ephemeral | Resolved | `internal/detection/state` | 005 |
| DEC-006 severity authority chain | Resolved | `internal/detection/engine`, `internal/correlation` | 004 |
| DEC-007 observed claims require evidence references | Resolved | `internal/ai` carries `EvidenceItem`s and the analyze endpoint returns them | 004 |
| DEC-008 `confidence` is informational or removed | Resolved by omission | no `confidence` field exists | 004 |
| DEC-009 enrollment credential → agent identity → rotatable token | Resolved | `internal/api/handlers_agents.go`, `internal/auth` | 009 |
| DEC-010 duplicate event ids are idempotent | Resolved | `internal/events/ingest`, `UNIQUE(events.id)` | 006 |
| DEC-011 structured events outlive raw evidence | Resolved | `PurgeRawEvidence`, migration `0001_init.sql` | 011 |
| DEC-012 simulation is synthetic and isolated | Resolved | `apps/agent/producer.go` | 004 |

## 11.2 P0 findings

| Finding | Status | Notes |
|---|---|---|
| AUD-001 RBAC both MVP and V2 | Resolved | PRD v0.3.0 already restricts V2 to fine-grained/enterprise authorization. RBAC is implemented as MVP scope. |
| AUD-002 response actions scope conflict | Resolved | MVP performs no response action. No endpoint can execute one. |
| AUD-003 event ID ownership undefined | Resolved | Producer-generated ULID; server binds host and agent identity from the credential. |
| AUD-004 timestamp semantics incomplete | Resolved | `event_time`, `received_at`, `observed_at` are separate fields. |
| AUD-005 clock skew policy missing | Resolved | `HALIMISOC_CLOCK_SKEW` (default 5m) bounds future timestamps; old timestamps are accepted for backfill. |
| AUD-006 detection restart semantics undefined | Resolved | Documented and tested: restart resets state. |
| AUD-007 correlation matching vague | Resolved | Shared concrete entity (host/actor/source IP) plus bounded window; weak entity alone cannot merge hosts. |
| AUD-008 severity authority not explicit | Resolved | Event severity is source metadata; alert severity is the rule's; incident severity is the highest qualifying alert. |
| AUD-009 AI confidence ambiguity | Resolved by omission | No confidence field is produced or consumed. |
| AUD-010 AI evidence grounding invariant | Resolved | Evidence is quoted, bounded and cited in `internal/ai`; the invariant is recorded in ADR-004. |
| AUD-011 enrollment lifecycle underspecified | Resolved | Enrollment secret → agent identity → per-agent token, with rotation and revocation. |
| AUD-012 agent token storage semantics | Resolved | SHA-256 hash only; plaintext returned once and never stored. |
| AUD-013 ingestion idempotency not contracted | Resolved | `INSERT ... ON CONFLICT DO NOTHING`; detection runs only on a new insert. |
| AUD-014 resource limits not concrete | Resolved | `internal/config/limits.go` defines default and maximum for every category. |
| AUD-015 retention/deletion semantics | Resolved | Raw expiry nulls the raw column and marks it; the structured event survives. |
| AUD-016 spool overflow policy | Resolved | Oldest-first eviction under a hard byte cap, with a dropped counter and a degraded heartbeat. |
| AUD-017 database integrity constraints | Resolved | `UNIQUE(events.id)`, `UNIQUE(agents.host)`, `UNIQUE(agent_tokens.token_hash)`, case-insensitive `UNIQUE` on usernames, explicit foreign keys. |

## 11.3 P1 findings

| Finding | Status |
|---|---|
| AUD-018 API error contract not standardised | Resolved: single envelope with stable codes. |
| AUD-019 RBAC matrix missing | Resolved: `internal/authorization` with a total matrix. |
| AUD-020 SSE revocation lifecycle | Resolved: re-authorization per event and per keepalive in `internal/events/stream` (ADR-003). |
| AUD-021 trusted proxy / forwarded header policy | Resolved by refusal: forwarded headers are never trusted. |
| AUD-022 simulator isolation | Resolved: the simulator emits log lines through the real parser. |
| AUD-023 simulation metadata contract | Resolved: `attributes.parser` plus the `simulation` source path identify synthetic events. |
| AUD-024 event ordering semantics | Resolved: event time descending with the event id as a stable tie-break. |
| AUD-025 cooldown/deduplication semantics | Resolved: per rule, per group, deterministic expiry; persistence is never suppressed. |
| AUD-026 alert vs incident lifecycle differ | Resolved: they are intentionally separate state machines, both forward-only and tested. |
| AUD-027 incident severity update semantics | Resolved: `MaxSeverity` over qualifying alerts. |
| AUD-028 rule versioning on alerts | Resolved: `rule_id` and `rule_version` are stored on every alert. |
| AUD-029 rule reload semantics | Resolved: rules load at startup; an invalid set is fatal and never partially applied. |
| AUD-030 AI provider failure behaviour | Deferred with AI. |
| AUD-031 AI concurrency and cost limits | Deferred with AI; bounds are defined in config. |
| AUD-032 AI output validation detail | Deferred with AI. |
| AUD-033 audit log scope | Resolved: login, logout, enrollment, token rotation/revocation, alert and incident status changes, bootstrap. |
| AUD-034 audit integrity expectations | Resolved: `SECURITY.md` states plainly that the audit log is not tamper-proof. |
| AUD-035 pagination strategy | Resolved: cursor pagination on a stable key, with clamped page sizes. |
| AUD-036 data access authorization scope | Resolved: single-tenant; stated in `SECURITY.md`. |

## 11.4 P2 findings

| Finding | Status |
|---|---|
| AUD-037 risk numbering | Resolved in PRD v0.3.0. |
| AUD-038 FR-14 mislabelled as future | Resolved: FR-14 is SSE; natural-language query is POST-MVP. |
| AUD-039 MUST/SHOULD inconsistency | Partially resolved: the implementation uses `MUST` in normative documents and enforces behaviour in code. |
| AUD-040 repository structures differ | Resolved: `DESIGN.md` is canonical; the implementation follows it. |
| AUD-041 threat model numbering | Resolved in PRD v0.3.0. |
| AUD-042 requirement precedence | Resolved: identical precedence block in all three documents. |

## 11.5 Findings that remain open

These are the only items that still require a decision before the corresponding
feature is built.

| Item | Blocks | Owner decision needed |
|---|---|---|
| Additional parsers (nginx, Docker, generic syslog) | Coverage breadth | Each parser needs its own fuzz and regression tests. |
| License selection | Distribution | `README.md` records it as TBD. |

The SSE stream, the web dashboard and the AI analyst that appeared in this table
earlier are now implemented; §12.3 records their status.

> Superseded in part: the nginx parser and the license selection left this table
> when they shipped; §12.3 records the resolutions. Docker and generic syslog
> parsers remain open.

## 11.6 Definition of audit complete

Reassessed against section 9:

- [x] All P0 contradictions resolved.
- [x] All P0 ambiguities have explicit decisions.
- [x] Event identity is contractual.
- [x] Event timestamp semantics are contractual.
- [x] Agent enrollment lifecycle is contractual.
- [x] Agent token lifecycle is contractual.
- [x] Detection restart semantics are contractual.
- [x] Correlation matching semantics are contractual.
- [x] Severity authority is contractual.
- [x] AI evidence grounding is contractual (ADR-004; implemented and covered by
  prompt-injection fixtures in `internal/ai`).
- [x] API limits have explicit policy with defaults and maxima.
- [x] Retention/deletion behaviour is contractual.
- [x] Spool overflow behaviour is contractual.
- [x] Database integrity rules are contractual.
- [x] RBAC scope is unambiguous.
- [x] Response execution scope is unambiguous.
- [x] MVP/Post-MVP boundaries are unambiguous.
- [x] Requirement precedence is explicit.
- [x] Repository structure has one canonical definition.
- [x] Terminology is consistent.
- [x] Every critical requirement maps to a test.

The specification audit is complete. The remaining work is implementation, not
clarification.

------------------------------------------------------------------------

# 12. Post-Implementation Reconciliation

**Reconciled document versions:** `PRD.md` v0.4.0, `DESIGN.md` v2.0.0,
`AGENTS.md` v2.0.0.

Implementing the specification surfaced three classes of issue that an audit of
documents alone could not find. They are recorded here because each one is evidence
about the specification, not merely about the code.

## 12.1 Contradictions that only appeared during implementation

| Finding | What happened | Resolution |
|---|---|---|
| IMP-01 The event contract was nested while the index guidance was flat. | There was no defined mapping from `event.category` to a column. Every query would have had to invent one. | The event shape is flat with one name per concept; `ADR-012`. |
| IMP-02 The PRD API surface used `/api/v1/health` while the code exposed `/healthz`. | Exactly the drift class AUD-018 described, but on the operational endpoints rather than the error shape. | Versioned paths, with the bare names kept as aliases; PRD amendment A6. |
| IMP-03 A heartbeat addressed without an agent id cannot be authorized against a credential. | Any agent could report liveness for any other agent. | `POST /api/v1/agents/{id}/heartbeat` validates the id against the credential; PRD amendment A7. |
| IMP-04 The PRD lifecycle had no containment state. | An operator had to either hide that containment action was taken or claim the incident resolved. | `CONTAINED` and `CLOSED` added; PRD amendment A3, `ADR-013`. |
| IMP-05 The PRD defines an HTTP authentication-failure-spike rule but no HTTP parser. | The rule could never fire. Shipping it would be a requirement that cannot be satisfied. | Deferred with the nginx parser; PRD amendment A4. |
| IMP-06 Severity casing was inconsistent between `HIGH` and `high` in examples. | Two implementations would disagree about what a valid value is. | Lowercase on the wire, strict parse; PRD amendment A5. |
| IMP-07 Correlation failure was wired as an ingestion failure. | A correlation outage would make the agent retry a batch whose events were already stored; the retry would be suppressed as a duplicate, so the incident would still be missing while the caller saw a spurious error. | Correlation failure is a recorded degradation; the alert stays visible ungrouped. `DESIGN.md` §8. |
| IMP-08 An applied migration was edited to change a constraint. | A fresh database would get the new schema while an existing one kept the old, which is an unreproducible deployment. | `0002` carries the change; `AGENTS.md` §10 makes an applied migration immutable. |

## 12.2 Audit items reclassified

- **AUD-042 requirement precedence** is fully resolved: all three documents carry an
  identical precedence block, and it is enforced by this file's resolution record.
- **AUD-039 MUST/SHOULD inconsistency** is resolved for the implemented surface: the
  normative phrasing is `MUST`, and `DESIGN.md` states the enforced behaviour for
  each.
- **AUD-020 SSE revocation** is no longer deferred in principle: `ADR-003` specifies
  re-authorization per event so a revoked session terminates an open stream. The
  implementation has landed in `internal/events/stream`, which re-authorizes on
  every event and on every keepalive tick.

## 12.3 Remaining open items

| Item | Blocks | Note |
|---|---|---|
| Generic syslog parsers (cron, systemd, non-UFW firewall drivers) | Broader coverage | Each parser needs its own fuzz and regression suite, per `AGENTS.md` §8. A catch-all parser is deliberately out of scope: an event per syslog line would turn system chatter into stored telemetry. |
| AI provider hardening beyond the OpenAI-compatible shape | Provider choice | The adapter is one wire format by design; a second format would need an ADR. |

Resolved since this section was written:

| Item | Resolution |
|---|---|
| nginx parser and FR-06 Rule E | Shipped: `internal/events/parser/nginx.go` with table tests and a 950k-execution clean fuzz run, `packages/rules/http-auth-failure-spike.yaml` with engine tests, PRD amendment A9. |
| License selection | MIT; `LICENSE` at the repository root, `README.md` updated. |
| RBAC user management (`manage_users` had no endpoint) | Shipped: `GET/POST /api/v1/users` and `PATCH /api/v1/users/{id}/status` with handler tests; disabling revokes sessions and the last active admin is protected. |
| Rule management (`manage_rules` was read-only) | Shipped: transactional `POST /api/v1/rules/reload` with handler tests. |
| Correlation ignoring source addresses | Fixed: incidents track `source_ips` (migration `0003`), with the conservative policy kept — an address alone never merges different hosts. |
| Docker json-file logs and UFW firewall coverage | Shipped: envelope parser delegating to the host registry (`container.log` source) and UFW BLOCK parser (`network.firewall.block`) with the `firewall-port-scan` rule; table tests plus adversarial cases per `AGENTS.md` §8. |
| Console asset and audit views | Shipped: `apps/web` `/assets` and `/audit` pages, overview volume chart and detection-health card. |
| Incident notifications | Shipped: `internal/notify` webhook on creation only, scope-only payload, bounded async delivery with metrics. |
| Rule authoring UI | Shipped: console `/rules/new` and edit pages plus validate/save/delete/reload API; saves are atomic, activation stays an explicit reload, last-rule delete refused. |

Completed since this section was written, each with the tests `AGENTS.md` §8
requires: the web dashboard (PRD §16 Milestone 5 — `apps/web`, 17 end-to-end
tests), the SSE stream (`internal/events/stream`, contract fixed by `ADR-003`),
and the AI analyst (`internal/ai`, advisory mode per `ADR-004`).

## 12.4 Conclusion

The specification is now precise enough to implement from, and it has been
implemented from. Every P0 decision is realized in code with a test that fails if
the control is removed.

The remaining risk is no longer specification ambiguity. It is execution risk:
the additional parsers are an unbuilt feature with an unambiguous contract, which
is the state a backlog should be in. The UI and the SSE stream it was waiting on
have since been built.
