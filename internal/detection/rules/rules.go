// Package rules defines the detection rule contract and its safe loader.
//
// Rules are data, never code (DESIGN.md §11.2). The loader accepts a strict
// schema, rejects unknown fields, and compiles into a restricted internal
// representation. There is deliberately no expression evaluator: an operator
// cannot write a rule that executes arbitrary logic, because that would turn a
// configuration file into a remote code execution surface.
package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// Field is a group-by / chaining field. Only these fields are addressable by a
// rule; the allowlist prevents a rule from reading arbitrary event internals.
type Field string

const (
	FieldHost     Field = "host"
	FieldActor    Field = "actor"
	FieldTarget   Field = "target"
	FieldSourceIP Field = "network.src_ip"
	FieldDestIP   Field = "network.dst_ip"
)

// FieldSet is the closed allowlist of addressable fields.
var FieldSet = []Field{FieldHost, FieldActor, FieldTarget, FieldSourceIP, FieldDestIP}

// Valid reports whether f is addressable.
func (f Field) Valid() bool {
	for _, v := range FieldSet {
		if v == f {
			return true
		}
	}
	return false
}

// Value reads the field from an event. It returns "" when the event does not
// carry the field, which callers treat as "not groupable".
func (f Field) Value(e *model.Event) string {
	switch f {
	case FieldHost:
		return e.Host
	case FieldActor:
		return e.Actor
	case FieldTarget:
		return e.Target
	case FieldSourceIP:
		return e.Network.SourceIP
	case FieldDestIP:
		return e.Network.DestIP
	}
	return ""
}

// Match selects the events a rule considers.
type Match struct {
	// Types is the set of event types that qualify. At least one is required.
	Types []model.EventType `yaml:"types"`

	// Outcomes optionally restricts by outcome.
	Outcomes []model.Outcome `yaml:"outcomes"`

	// Attributes optionally requires exact attribute equality. Attribute values
	// are compared as strings, never evaluated.
	Attributes map[string]string `yaml:"attributes"`
}

// Requires expresses deterministic rule chaining: the rule only fires when a
// named rule has already fired recently for the same chaining key.
type Requires struct {
	// RuleID is the rule that must have fired previously.
	RuleID string `yaml:"rule_id"`

	// Window bounds how long ago that firing may have occurred.
	Window time.Duration `yaml:"window"`

	// MatchOn is the field compared between the previous firing and the current
	// event.
	MatchOn Field `yaml:"match_on"`
}

// Threshold is a bounded sliding-window count.
type Threshold struct {
	Count  int           `yaml:"count"`
	Window time.Duration `yaml:"window"`
}

// Rule is the restricted internal representation of a detection rule.
type Rule struct {
	ID          string         `yaml:"id"`
	Version     int            `yaml:"version"`
	Name        string         `yaml:"name"`
	Description string         `yaml:"description"`
	Severity    model.Severity `yaml:"severity"`
	Match       Match          `yaml:"match"`
	GroupBy     []Field        `yaml:"group_by"`
	Threshold   Threshold      `yaml:"threshold"`
	Requires    *Requires      `yaml:"requires"`
	Cooldown    time.Duration  `yaml:"cooldown"`
}

// Key is the rule identity used for uniqueness and state isolation.
func (r *Rule) Key() string {
	return fmt.Sprintf("%s@%d", r.ID, r.Version)
}

// Matches reports whether the event satisfies the rule's match block.
func (r *Rule) Matches(e *model.Event) bool {
	if !containsType(r.Match.Types, e.Type) {
		return false
	}
	if len(r.Match.Outcomes) > 0 && !containsOutcome(r.Match.Outcomes, e.Outcome) {
		return false
	}
	for k, v := range r.Match.Attributes {
		if e.Attributes[k] != v {
			return false
		}
	}
	return true
}

// GroupKey builds the deterministic grouping key for an event.
//
// It returns ok=false when any grouping field is empty. An event that cannot be
// fully grouped is not counted, because counting it would attribute activity to
// a key that does not identify the actor, host or peer involved.
func (r *Rule) GroupKey(e *model.Event) (string, bool) {
	parts := make([]string, 0, len(r.GroupBy))
	for _, f := range r.GroupBy {
		v := f.Value(e)
		if v == "" {
			return "", false
		}
		parts = append(parts, string(f)+"="+v)
	}
	if len(parts) == 0 {
		return "", false
	}
	return joinKey(parts), true
}

// ChainingValue returns the value of the field used to match a prior firing.
func (r *Rule) ChainingValue(e *model.Event) string {
	if r.Requires == nil {
		return ""
	}
	return r.Requires.MatchOn.Value(e)
}

// validate enforces the rule contract. It returns the first violation.
func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule id is required")
	}
	if !validID(r.ID) {
		return fmt.Errorf("rule id %q must be lowercase alphanumeric with dashes", r.ID)
	}
	if r.Version <= 0 {
		return fmt.Errorf("rule %s: version must be positive", r.ID)
	}
	if r.Name == "" {
		return fmt.Errorf("rule %s: name is required", r.ID)
	}
	if model.SeverityRank(r.Severity) == 0 {
		return fmt.Errorf("rule %s: severity %q is not canonical", r.ID, r.Severity)
	}
	if len(r.Match.Types) == 0 {
		return fmt.Errorf("rule %s: match.types must not be empty", r.ID)
	}
	for _, t := range r.Match.Types {
		if !t.Valid() {
			return fmt.Errorf("rule %s: unknown event type %q", r.ID, t)
		}
	}
	for _, o := range r.Match.Outcomes {
		if !o.Valid() {
			return fmt.Errorf("rule %s: unknown outcome %q", r.ID, o)
		}
	}
	for k := range r.Match.Attributes {
		if k == "" {
			return fmt.Errorf("rule %s: attribute key must not be empty", r.ID)
		}
	}
	if len(r.GroupBy) == 0 {
		return fmt.Errorf("rule %s: group_by must not be empty", r.ID)
	}
	seen := map[Field]bool{}
	for _, f := range r.GroupBy {
		if !f.Valid() {
			return fmt.Errorf("rule %s: unknown group_by field %q", r.ID, f)
		}
		if seen[f] {
			return fmt.Errorf("rule %s: duplicate group_by field %q", r.ID, f)
		}
		seen[f] = true
	}
	if r.Threshold.Count < 1 {
		return fmt.Errorf("rule %s: threshold.count must be at least 1", r.ID)
	}
	if r.Threshold.Count > maxThresholdCount {
		return fmt.Errorf("rule %s: threshold.count %d exceeds maximum %d", r.ID, r.Threshold.Count, maxThresholdCount)
	}
	if r.Threshold.Window <= 0 {
		return fmt.Errorf("rule %s: threshold.window must be positive", r.ID)
	}
	if r.Threshold.Window > maxWindow {
		return fmt.Errorf("rule %s: threshold.window %s exceeds maximum %s", r.ID, r.Threshold.Window, maxWindow)
	}
	if r.Cooldown <= 0 {
		return fmt.Errorf("rule %s: cooldown must be positive so alert volume is bounded", r.ID)
	}
	if r.Cooldown > maxCooldown {
		return fmt.Errorf("rule %s: cooldown %s exceeds maximum %s", r.ID, r.Cooldown, maxCooldown)
	}
	if r.Requires != nil {
		if r.Requires.RuleID == "" {
			return fmt.Errorf("rule %s: requires.rule_id must not be empty", r.ID)
		}
		if r.Requires.Window <= 0 || r.Requires.Window > maxWindow {
			return fmt.Errorf("rule %s: requires.window must be within (0, %s]", r.ID, maxWindow)
		}
		if !r.Requires.MatchOn.Valid() {
			return fmt.Errorf("rule %s: requires.match_on %q is not addressable", r.ID, r.Requires.MatchOn)
		}
	}
	return nil
}

// Bounds. These keep a malicious or careless rule file from creating unbounded
// state or an effectively unbounded alert stream.
const (
	maxThresholdCount = 100_000
	maxWindow         = 24 * time.Hour
	maxCooldown       = 24 * time.Hour
)

func containsType(list []model.EventType, v model.EventType) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func containsOutcome(list []model.Outcome, v model.Outcome) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

func joinKey(parts []string) string {
	sort.Strings(parts)
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "\x1f"
		}
		out += p
	}
	return out
}

// ValidID reports whether s is a legal rule id.
//
// It is exported so the API can validate a rule id from a URL path before
// turning it into a filename: the same character set that is safe for rule
// identity is safe for a filename, and nothing else is accepted.
func ValidID(s string) bool { return validID(s) }
