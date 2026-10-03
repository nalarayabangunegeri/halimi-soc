package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

const validRule = `
id: test-rule
version: 1
name: Test Rule
description: A rule used by tests
severity: high
match:
  types:
    - auth.ssh.login_failed
  outcomes:
    - failure
threshold:
  count: 3
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`

func TestParseValidRule(t *testing.T) {
	got, err := ParseDocuments([]byte(validRule))
	if err != nil {
		t.Fatalf("ParseDocuments() = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rules, want 1", len(got))
	}
	r := got[0]
	if r.Key() != "test-rule@1" {
		t.Errorf("key = %q", r.Key())
	}
	if r.Severity != model.SeverityHigh {
		t.Errorf("severity = %q", r.Severity)
	}
	if r.Threshold.Count != 3 || r.Threshold.Window != 60*time.Second {
		t.Errorf("threshold = %+v", r.Threshold)
	}
	if r.Cooldown != 5*time.Minute {
		t.Errorf("cooldown = %s", r.Cooldown)
	}
}

func TestParseMultipleDocuments(t *testing.T) {
	second := strings.ReplaceAll(validRule, "test-rule", "test-rule-two")
	got, err := ParseDocuments([]byte(validRule + "\n---\n" + second))
	if err != nil {
		t.Fatalf("ParseDocuments() = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2", len(got))
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	// A rule whose author expects an unimplemented field must fail closed,
	// otherwise the rule silently does something other than what it says.
	in := validRule + "\nsuppression: something\n"
	if _, err := ParseDocuments([]byte(in)); err == nil {
		t.Fatal("ParseDocuments accepted an unknown field")
	}
}

func TestParseRejectsInvalidRules(t *testing.T) {
	cases := map[string]string{
		"missing id":             strings.Replace(validRule, "id: test-rule", "id: \"\"", 1),
		"bad id characters":      strings.Replace(validRule, "id: test-rule", "id: Test Rule!", 1),
		"zero version":           strings.Replace(validRule, "version: 1", "version: 0", 1),
		"missing name":           strings.Replace(validRule, "name: Test Rule", "name: \"\"", 1),
		"uppercase severity":     strings.Replace(validRule, "severity: high", "severity: HIGH", 1),
		"unknown severity":       strings.Replace(validRule, "severity: high", "severity: urgent", 1),
		"no match types":         strings.Replace(validRule, "    - auth.ssh.login_failed\n", "", 1),
		"unknown event type":     strings.Replace(validRule, "auth.ssh.login_failed", "auth.ssh.explode", 1),
		"unknown outcome":        strings.Replace(validRule, "    - failure", "    - maybe", 1),
		"no group_by":            strings.Replace(validRule, "group_by:\n  - network.src_ip\n", "group_by: []\n", 1),
		"unknown group_by field": strings.Replace(validRule, "network.src_ip", "raw", 1),
		"zero threshold":         strings.Replace(validRule, "count: 3", "count: 0", 1),
		"excessive threshold":    strings.Replace(validRule, "count: 3", "count: 999999", 1),
		"missing window":         strings.Replace(validRule, "window: 60s", "window: \"\"", 1),
		"excessive window":       strings.Replace(validRule, "window: 60s", "window: 100h", 1),
		"zero cooldown":          strings.Replace(validRule, "cooldown: 5m", "cooldown: \"\"", 1),
		"excessive cooldown":     strings.Replace(validRule, "cooldown: 5m", "cooldown: 48h", 1),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if in == validRule {
				t.Skip("fixture replacement did not apply")
			}
			if _, err := ParseDocuments([]byte(in)); err == nil {
				t.Fatal("ParseDocuments accepted an invalid rule")
			}
		})
	}
}

func TestParseRejectsDuplicateGroupByField(t *testing.T) {
	in := strings.Replace(validRule, "group_by:\n  - network.src_ip", "group_by:\n  - host\n  - host", 1)
	if _, err := ParseDocuments([]byte(in)); err == nil {
		t.Fatal("expected duplicate group_by to be rejected")
	}
}

func TestRequiresMustResolve(t *testing.T) {
	chained := validRule + `
---
id: chained
version: 1
name: Chained
severity: critical
match:
  types:
    - auth.sudo.command
threshold:
  count: 1
  window: 5m
group_by:
  - actor
requires:
  rule_id: does-not-exist
  window: 5m
  match_on: actor
cooldown: 5m
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(chained), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected a dangling requires reference to be rejected")
	}
}

func TestLoadDirLoadsPackagedRules(t *testing.T) {
	set, err := LoadDir(filepath.Join("..", "..", "..", "packages", "rules"))
	if err != nil {
		t.Fatalf("LoadDir(packages/rules) = %v", err)
	}
	if set.Len() < 4 {
		t.Fatalf("loaded %d rules, want at least the 4 shipped rules", set.Len())
	}
	for _, r := range set.Rules() {
		if r.Cooldown <= 0 {
			t.Errorf("rule %s has no cooldown, alert volume would be unbounded", r.Key())
		}
	}
}

func TestLoadDirFailsOnEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("expected ErrNoRules for an empty directory")
	}
}

func TestLoadDirIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"b.yaml", "a.yaml", "c.yaml"} {
		body := strings.ReplaceAll(validRule, "test-rule", "rule-"+strings.TrimSuffix(name, ".yaml"))
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	first, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	f, s := first.Rules(), second.Rules()
	if len(f) != len(s) {
		t.Fatalf("rule count differs between loads: %d vs %d", len(f), len(s))
	}
	for i := range f {
		if f[i].Key() != s[i].Key() {
			t.Fatalf("rule order differs at %d: %s vs %s", i, f[i].Key(), s[i].Key())
		}
	}
	if f[0].ID != "rule-a" {
		t.Errorf("first rule = %s, want rule-a (sorted by filename)", f[0].ID)
	}
}

func TestRuleMatches(t *testing.T) {
	set, err := ParseDocuments([]byte(validRule))
	if err != nil {
		t.Fatal(err)
	}
	r := set[0]

	e := &model.Event{
		Type:       model.TypeSSHLoginFailed,
		Outcome:    model.OutcomeFailure,
		Host:       "web-01",
		Network:    model.Network{SourceIP: "203.0.113.7"},
		Attributes: map[string]string{},
	}
	if !r.Matches(e) {
		t.Fatal("expected match")
	}

	e.Outcome = model.OutcomeSuccess
	if r.Matches(e) {
		t.Error("outcome filter was not applied")
	}

	e.Outcome = model.OutcomeFailure
	e.Type = model.TypeSSHLoginSuccess
	if r.Matches(e) {
		t.Error("type filter was not applied")
	}
}

func TestRuleGroupKeyRequiresAllFields(t *testing.T) {
	set, err := ParseDocuments([]byte(validRule))
	if err != nil {
		t.Fatal(err)
	}
	r := set[0]

	e := &model.Event{Network: model.Network{SourceIP: "203.0.113.7"}}
	key, ok := r.GroupKey(e)
	if !ok || key == "" {
		t.Fatal("expected a group key")
	}

	e.Network.SourceIP = ""
	if _, ok := r.GroupKey(e); ok {
		t.Fatal("an event missing a grouping field must not be grouped")
	}
}

func TestRuleGroupKeyIsOrderIndependent(t *testing.T) {
	bodyA := strings.Replace(validRule, "group_by:\n  - network.src_ip", "group_by:\n  - host\n  - actor", 1)
	bodyB := strings.Replace(validRule, "group_by:\n  - network.src_ip", "group_by:\n  - actor\n  - host", 1)

	setA, err := ParseDocuments([]byte(bodyA))
	if err != nil {
		t.Fatal(err)
	}
	setB, err := ParseDocuments([]byte(bodyB))
	if err != nil {
		t.Fatal(err)
	}

	e := &model.Event{Host: "web-01", Actor: "root"}
	ka, _ := setA[0].GroupKey(e)
	kb, _ := setB[0].GroupKey(e)
	if ka != kb {
		t.Fatalf("group key depends on field order: %q vs %q", ka, kb)
	}
}

func TestFieldAllowlist(t *testing.T) {
	if Field("raw").Valid() {
		t.Fatal("raw evidence must not be addressable by a rule")
	}
	if Field("attributes.command").Valid() {
		t.Fatal("attribute values must not be addressable by a rule")
	}
	for _, f := range FieldSet {
		if !f.Valid() {
			t.Errorf("allowlisted field %q reported invalid", f)
		}
	}
}
