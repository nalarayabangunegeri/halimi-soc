// Package state holds the bounded, ephemeral detection state.
//
// DESIGN.md §11.3: MVP detection uses in-memory TTL state. State is
// intentionally lost on restart, and every structure here is bounded so a
// hostile or broken source cannot exhaust memory through unique grouping keys.
//
// State is keyed by event time, not wall-clock time, so replaying the same
// events produces the same detection outcome.
package state

import (
	"sort"
	"sync"
	"time"

	"github.com/halimi/halimisoc/internal/detection/rules"
)

// Observation is a single qualifying event recorded against a group.
type Observation struct {
	At      time.Time
	EventID string
}

// Firing records that a rule produced an alert, so a later rule can chain on it.
type Firing struct {
	At   time.Time
	Keys map[rules.Field]string
}

// Options bound the state.
type Options struct {
	// MaxGroups is the maximum number of (rule, group) windows retained.
	MaxGroups int

	// MaxPerGroup is the maximum observations retained per group.
	MaxPerGroup int

	// MaxFiringsPerRule is the maximum chained firings retained per rule.
	MaxFiringsPerRule int

	// MaxFiringAge bounds how long a firing is retained for chaining.
	MaxFiringAge time.Duration
}

// DefaultOptions returns conservative bounds.
func DefaultOptions() Options {
	return Options{
		MaxGroups:         50_000,
		MaxPerGroup:       1_000,
		MaxFiringsPerRule: 10_000,
		MaxFiringAge:      24 * time.Hour,
	}
}

// State is a concurrency-safe bounded window store.
type State struct {
	mu    sync.Mutex
	opts  Options
	win   map[string]map[string][]Observation
	fired map[string]time.Time
	chain map[string][]Firing
}

// New returns an empty state store.
func New(opts Options) *State {
	if opts.MaxGroups <= 0 {
		opts.MaxGroups = DefaultOptions().MaxGroups
	}
	if opts.MaxPerGroup <= 0 {
		opts.MaxPerGroup = DefaultOptions().MaxPerGroup
	}
	if opts.MaxFiringsPerRule <= 0 {
		opts.MaxFiringsPerRule = DefaultOptions().MaxFiringsPerRule
	}
	if opts.MaxFiringAge <= 0 {
		opts.MaxFiringAge = DefaultOptions().MaxFiringAge
	}
	return &State{
		opts:  opts,
		win:   map[string]map[string][]Observation{},
		fired: map[string]time.Time{},
		chain: map[string][]Firing{},
	}
}

// Observe records a qualifying event and returns the number of events in the
// window ending at obs.At.
//
// Events strictly older than the window are discarded first, so the returned
// count reflects only the sliding window and never the whole process lifetime.
func (s *State) Observe(ruleKey, groupKey string, obs Observation, window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, ok := s.win[ruleKey]
	if !ok {
		groups = map[string][]Observation{}
		s.win[ruleKey] = groups
	}

	cutoff := obs.At.Add(-window)
	kept := groups[groupKey][:0]
	for _, o := range groups[groupKey] {
		if !o.At.Before(cutoff) {
			kept = append(kept, o)
		}
	}
	kept = append(kept, obs)
	if len(kept) > s.opts.MaxPerGroup {
		kept = kept[len(kept)-s.opts.MaxPerGroup:]
	}
	groups[groupKey] = kept

	s.enforceGroupBound()
	return len(kept)
}

// Evidence returns the event IDs currently in the group's window.
func (s *State) Evidence(ruleKey, groupKey string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups := s.win[ruleKey]
	if groups == nil {
		return nil
	}
	obs := groups[groupKey]
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.EventID)
	}
	return out
}

// WindowStart returns the earliest observation time in the group window.
func (s *State) WindowStart(ruleKey, groupKey string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	groups := s.win[ruleKey]
	if groups == nil || len(groups[groupKey]) == 0 {
		return time.Time{}
	}
	return groups[groupKey][0].At
}

// CooldownActive reports whether the (rule, group) pair is still cooling down.
func (s *State) CooldownActive(ruleKey, groupKey string, cooldown time.Duration, at time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	last, ok := s.fired[ruleKey+"\x1f"+groupKey]
	if !ok {
		return false
	}
	return at.Sub(last) < cooldown
}

// MarkFired records an alert emission for cooldown and chaining purposes.
func (s *State) MarkFired(ruleKey, groupKey, ruleID string, at time.Time, keys map[rules.Field]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.fired[ruleKey+"\x1f"+groupKey] = at

	list := s.chain[ruleID]
	list = append(list, Firing{At: at, Keys: keys})
	if len(list) > s.opts.MaxFiringsPerRule {
		list = list[len(list)-s.opts.MaxFiringsPerRule:]
	}
	s.chain[ruleID] = list
}

// HasRecentFiring reports whether ruleID fired within window for the same
// value of matchOn.
//
// The comparison is exact string equality on a validated field value, so
// chaining cannot be influenced by an attacker-controlled substring.
func (s *State) HasRecentFiring(ruleID string, matchOn rules.Field, value string, window time.Duration, at time.Time) bool {
	if value == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := at.Add(-window)
	for _, f := range s.chain[ruleID] {
		if f.At.Before(cutoff) {
			continue
		}
		if f.Keys[matchOn] == value {
			return true
		}
	}
	return false
}

// Prune removes entries older than the given age. It is called periodically so
// that idle groups do not hold memory indefinitely.
func (s *State) Prune(now time.Time, age time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-age)
	for ruleKey, groups := range s.win {
		for groupKey, obs := range groups {
			kept := obs[:0]
			for _, o := range obs {
				if !o.At.Before(cutoff) {
					kept = append(kept, o)
				}
			}
			if len(kept) == 0 {
				delete(groups, groupKey)
				continue
			}
			groups[groupKey] = kept
		}
		if len(groups) == 0 {
			delete(s.win, ruleKey)
		}
	}

	for k, at := range s.fired {
		if at.Before(cutoff) {
			delete(s.fired, k)
		}
	}

	for ruleID, list := range s.chain {
		kept := list[:0]
		for _, f := range list {
			if !f.At.Before(cutoff) {
				kept = append(kept, f)
			}
		}
		if len(kept) == 0 {
			delete(s.chain, ruleID)
			continue
		}
		s.chain[ruleID] = kept
	}
}

// Size returns the number of tracked (rule, group) windows.
func (s *State) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, groups := range s.win {
		n += len(groups)
	}
	return n
}

// Reset clears all state. Used by tests and by an explicit operator reset.
func (s *State) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.win = map[string]map[string][]Observation{}
	s.fired = map[string]time.Time{}
	s.chain = map[string][]Firing{}
}

// enforceGroupBound evicts the least recently active group when the total
// number of groups exceeds the bound.
//
// Eviction is deterministic: the group with the oldest most-recent observation
// goes first, and ties are broken by key so two runs with the same input evict
// the same group. Callers must hold s.mu.
func (s *State) enforceGroupBound() {
	total := 0
	for _, groups := range s.win {
		total += len(groups)
	}
	if total <= s.opts.MaxGroups {
		return
	}

	type candidate struct {
		ruleKey, groupKey string
		last              time.Time
	}
	var all []candidate
	for ruleKey, groups := range s.win {
		for groupKey, obs := range groups {
			var last time.Time
			if len(obs) > 0 {
				last = obs[len(obs)-1].At
			}
			all = append(all, candidate{ruleKey: ruleKey, groupKey: groupKey, last: last})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].last.Equal(all[j].last) {
			return all[i].last.Before(all[j].last)
		}
		if all[i].ruleKey != all[j].ruleKey {
			return all[i].ruleKey < all[j].ruleKey
		}
		return all[i].groupKey < all[j].groupKey
	})

	for i := 0; i < len(all) && total > s.opts.MaxGroups; i++ {
		groups := s.win[all[i].ruleKey]
		if groups == nil {
			continue
		}
		if _, ok := groups[all[i].groupKey]; ok {
			delete(groups, all[i].groupKey)
			total--
		}
		if len(groups) == 0 {
			delete(s.win, all[i].ruleKey)
		}
	}
}
