# Detection rules

Rules live in `packages/rules/*.yaml` and are loaded at startup. A file that
fails validation stops the process: the detector is never left running a
partially applied rule set. An admin can reload the set from disk without a
restart via `POST /api/v1/rules/reload`; the reload is transactional, so an
invalid file leaves the previous known-good set active.

## Rule contract

```yaml
id: ssh-bruteforce          # lowercase alphanumeric with dashes, unique per version
version: 1                  # positive; alerts record the exact version that fired
name: SSH Brute Force
description: Repeated failed SSH authentication from one source address
severity: high              # low | medium | high | critical

match:
  types:                    # closed set of canonical event types
    - auth.ssh.login_failed
  outcomes:                 # optional
    - failure
  attributes:               # optional exact-match on normalized attributes
    invalid_user: "true"

threshold:
  count: 5                  # 1..100000
  window: 60s               # > 0 and <= 24h

group_by:                   # allowlisted entity fields only
  - network.src_ip

# Optional deterministic chaining: fire only when another rule fired recently
# for the same value of match_on.
requires:
  rule_id: ssh-bruteforce
  window: 10m
  match_on: network.src_ip

cooldown: 5m                # required; bounds alert volume
```

## Allowlisted fields

Only these are addressable by a rule: `host`, `actor`, `target`,
`network.source_ip`, `network.dest_ip`.

Raw evidence, message text and arbitrary attributes are deliberately not
addressable. A rule that could match on raw log content would let an attacker who
controls a log line control detection.

## Shipped rules

| id | severity | Fires when |
|---|---|---|
| `ssh-bruteforce` | high | 5 failed SSH authentications from one source within 60s |
| `ssh-login-after-bruteforce` | critical | A successful SSH login from a source that just triggered `ssh-bruteforce` |
| `sudo-after-suspicious-login` | high | A privileged sudo command by an account that just logged in after a brute force |
| `ssh-authorized-keys-modified` | critical | `authorized_keys` changed by an account that just logged in after a brute force |
| `sudo-auth-failure-burst` | high | 3 failed sudo authentications for one account within 60s |
| `privileged-command-after-remote-login` | medium | A privileged command on a host that recently saw a brute force |
| `http-auth-failure-spike` | medium | 10 HTTP 401/403 responses to one source address within 60s |
| `firewall-port-scan` | medium | 10 firewall-blocked packets from one source address within 5m |

The HTTP rule is fed by the nginx access-log parser (`http.access` source).
Only 401/403 responses become events: emitting an event per successful request
would turn normal traffic into a self-inflicted load spike.

The firewall rule is fed by the UFW kernel-log parser (`network.firewall.block`
events). Only BLOCK records become events; ALLOW records describe permitted
traffic. Container stdout/stderr from the Docker json-file driver is unwrapped
by the Docker envelope parser and classified by the same registry as host
telemetry, so the SSH, sudo and HTTP rules apply inside containers with
`container.log` as the source.

The last four are chained rules. This is what makes them deterministic rather
than noisy: a successful login is only critical if it followed a brute force from
the same address.

## Authoring rules

Rules are files first and API objects second. The supported flow is:

```text
write YAML → POST /api/v1/rules/validate → PUT /api/v1/rules/{id}
→ POST /api/v1/rules/reload
```

Validation is a dry run: it reports the first contract violation and changes
nothing. Saving writes the file atomically (temporary file plus rename) but
does not activate it. Reload validates the whole directory before swapping, so
an invalid save leaves the previous known-good set running. The console
exposes this flow on `/rules/new` and per-row Edit/Delete controls; all three
are admin-only.

Deleting the last rule file is refused: detection with zero rules would
silently stop detecting while still accepting telemetry, which is worse than
refusing the delete.

## Semantics

**Event time, not receipt time.** Windows are evaluated on `event_time`, so a
spool replay reproduces the original detection outcome rather than appearing as
a burst happening now.

**Cooldown suppresses the alert, not the evidence.** A qualifying event received
during a cooldown still persists and still contributes to correlation. Event
persistence, alert suppression and incident correlation are separate concerns.

**State is ephemeral.** A process restart resets sliding windows. A brute-force
sequence straddling a restart may not alert. This is a documented MVP limitation
(ADR-005), not an oversight.

**Grouping requires every field.** An event missing a `group_by` field is not
counted, because counting it would attribute activity to a key that does not
identify anyone.

## Known detection gaps

Stated here so nobody mistakes them for bugs. Each is a deliberate
determinism-over-recall trade-off with a test that locks it in.

- **Low-and-slow evasion.** A spray that stays under threshold (4 failures per
  60s against a count-5 rule) never alerts, and a stolen credential used
  without a preceding brute force never satisfies a chained rule. Catching
  those would mean alerting on single logins, which is noise, not detection.
  (`TestLowAndSlowSprayDoesNotAlert`, `TestChainingRequiresPrerequisite`)
- **Infrastructure rotation splits incidents.** An attacker who brute-forces
  one host from one address and logs into another host from another address
  shares no concrete entity with the first incident, so correlation honestly
  opens a second one. Merging on time proximity alone would manufacture attack
  chains out of coincidence. (`TestRotatedInfrastructureStartsNewIncident`,
  `TestWeakEntityAloneDoesNotMergeDifferentHosts`)
- **Cooldown hides the second burst as an alert, not as evidence.** A burst
  inside an active cooldown is counted in
  `detection_cooldown_suppressed_total` and still correlates, but emits no new
  alert. (`TestCooldownSuppressionIsCounted`)

## Testing a rule

Every production rule must have: a positive case, a negative case, a threshold
boundary, a time-window boundary, a duplicate, a missing-field case, a grouping
case, a cooldown case and a rule-version case. The engine tests in
`internal/detection/engine/engine_test.go` demonstrate the pattern.
