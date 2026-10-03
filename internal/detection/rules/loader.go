package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/halimi/halimisoc/internal/events/model"
)

// ErrNoRules means a rule directory contained no usable rules. It is fatal:
// running detection with zero rules would silently stop detecting anything.
var ErrNoRules = errors.New("no detection rules loaded")

// Set is an immutable, validated collection of rules.
//
// A Set is only ever constructed from a fully valid input. Callers that reload
// rules must keep the previous Set when loading fails, so the detector is never
// left with a partially applied rule file.
type Set struct {
	byKey map[string]*Rule
	order []string
}

// Rules returns the rules in stable load order.
func (s *Set) Rules() []*Rule {
	out := make([]*Rule, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.byKey[k])
	}
	return out
}

// Lookup returns the rule with the given key ("id@version"), or nil.
func (s *Set) Lookup(key string) *Rule {
	return s.byKey[key]
}

// Len returns the number of loaded rules.
func (s *Set) Len() int { return len(s.byKey) }

// LoadDir reads every *.yaml and *.yml file in dir and builds a validated Set.
//
// Files are processed in sorted order so a given directory always produces the
// same rule order, which keeps detection deterministic across restarts.
func LoadDir(dir string) (*Set, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)

	set := &Set{byKey: map[string]*Rule{}}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		parsed, err := ParseDocuments(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, r := range parsed {
			if err := set.add(r); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
		}
	}
	if set.Len() == 0 {
		return nil, ErrNoRules
	}
	if err := set.checkRequires(); err != nil {
		return nil, err
	}
	return set, nil
}

// ParseDocuments parses one or more YAML documents into validated rules.
//
// Unknown fields are rejected rather than ignored. A rule file that contains a
// field the engine does not understand is a rule file whose author expected
// behaviour that will not happen; failing closed is the only safe response.
func ParseDocuments(data []byte) ([]*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var out []*Rule
	for doc := 0; ; doc++ {
		var yr yamlRule
		err := dec.Decode(&yr)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", doc, err)
		}
		if yr.isZero() {
			continue
		}
		r := yr.toRule()
		if err := r.validate(); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no rules found in document")
	}
	return out, nil
}

func (s *Set) add(r *Rule) error {
	key := r.Key()
	if _, dup := s.byKey[key]; dup {
		return fmt.Errorf("duplicate rule %s", key)
	}
	s.byKey[key] = r
	s.order = append(s.order, key)
	return nil
}

// checkRequires verifies that every chaining reference resolves to a loaded
// rule. A dangling reference would silently disable a rule, so it is fatal.
func (s *Set) checkRequires() error {
	for _, r := range s.Rules() {
		if r.Requires == nil {
			continue
		}
		found := false
		for _, other := range s.Rules() {
			if other.ID == r.Requires.RuleID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("rule %s: requires unknown rule %q", r.Key(), r.Requires.RuleID)
		}
	}
	return nil
}

// yamlRule is the wire representation. Duration fields are strings such as
// "60s" and are parsed explicitly; yaml.v3 does not decode time.Duration.
type yamlRule struct {
	ID          string        `yaml:"id"`
	Version     int           `yaml:"version"`
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Severity    string        `yaml:"severity"`
	Match       yamlMatch     `yaml:"match"`
	GroupBy     []string      `yaml:"group_by"`
	Threshold   yamlThreshold `yaml:"threshold"`
	Requires    *yamlRequires `yaml:"requires"`
	Cooldown    string        `yaml:"cooldown"`
}

type yamlMatch struct {
	Types      []string          `yaml:"types"`
	Outcomes   []string          `yaml:"outcomes"`
	Attributes map[string]string `yaml:"attributes"`
}

type yamlThreshold struct {
	Count  int    `yaml:"count"`
	Window string `yaml:"window"`
}

type yamlRequires struct {
	RuleID  string `yaml:"rule_id"`
	Window  string `yaml:"window"`
	MatchOn string `yaml:"match_on"`
}

func (y yamlRule) isZero() bool {
	return y.ID == "" && y.Name == "" && y.Version == 0 &&
		len(y.Match.Types) == 0 && y.Threshold.Count == 0
}

func (y yamlRule) toRule() *Rule {
	r := &Rule{
		ID:          strings.TrimSpace(y.ID),
		Version:     y.Version,
		Name:        strings.TrimSpace(y.Name),
		Description: strings.TrimSpace(y.Description),
		Severity:    model.Severity(strings.TrimSpace(y.Severity)),
		Match: Match{
			Attributes: y.Match.Attributes,
		},
		Threshold: Threshold{Count: y.Threshold.Count},
	}
	for _, t := range y.Match.Types {
		r.Match.Types = append(r.Match.Types, model.EventType(strings.TrimSpace(t)))
	}
	for _, o := range y.Match.Outcomes {
		r.Match.Outcomes = append(r.Match.Outcomes, model.Outcome(strings.TrimSpace(o)))
	}
	for _, g := range y.GroupBy {
		r.GroupBy = append(r.GroupBy, Field(strings.TrimSpace(g)))
	}
	r.Threshold.Window = mustDuration(y.Threshold.Window)
	r.Cooldown = mustDuration(y.Cooldown)
	if y.Requires != nil {
		r.Requires = &Requires{
			RuleID:  strings.TrimSpace(y.Requires.RuleID),
			Window:  mustDuration(y.Requires.Window),
			MatchOn: Field(strings.TrimSpace(y.Requires.MatchOn)),
		}
	}
	return r
}

// mustDuration parses a duration string, returning 0 on failure so that
// validate() reports the resulting zero as a contract violation.
func mustDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
