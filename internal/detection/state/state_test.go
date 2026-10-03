package state_test

import (
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
)

func TestObserveCountsWithinWindow(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	for i := 0; i < 3; i++ {
		got := s.Observe("r@1", "ip=1.2.3.4", state.Observation{
			At:      base.Add(time.Duration(i) * time.Second),
			EventID: "e",
		}, time.Minute)
		if got != i+1 {
			t.Fatalf("count = %d, want %d", got, i+1)
		}
	}
}

func TestObserveEvictsExpiredObservations(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	s.Observe("r@1", "g", state.Observation{At: base, EventID: "e1"}, time.Minute)
	s.Observe("r@1", "g", state.Observation{At: base.Add(2 * time.Second), EventID: "e2"}, time.Minute)

	// Two minutes later the first observation is outside the 60s window.
	got := s.Observe("r@1", "g", state.Observation{At: base.Add(2 * time.Minute), EventID: "e3"}, time.Minute)
	if got != 1 {
		t.Fatalf("count = %d, want 1 (only the newest observation is in window)", got)
	}

	evidence := s.Evidence("r@1", "g")
	if len(evidence) != 1 || evidence[0] != "e3" {
		t.Fatalf("evidence = %v, want [e3]", evidence)
	}
}

func TestGroupsAreIsolated(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	for i := 0; i < 5; i++ {
		s.Observe("r@1", "ip=a", state.Observation{At: base, EventID: "a"}, time.Minute)
	}
	if got := s.Observe("r@1", "ip=b", state.Observation{At: base, EventID: "b"}, time.Minute); got != 1 {
		t.Fatalf("a new group counted %d events, want 1", got)
	}
}

func TestCooldown(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()
	keys := map[rules.Field]string{rules.FieldSourceIP: "1.2.3.4"}

	if s.CooldownActive("r@1", "g", time.Minute, base) {
		t.Fatal("cooldown active before any firing")
	}
	s.MarkFired("r@1", "g", "r", base, keys)

	if !s.CooldownActive("r@1", "g", time.Minute, base.Add(30*time.Second)) {
		t.Fatal("cooldown not active during the cooldown window")
	}
	if s.CooldownActive("r@1", "g", time.Minute, base.Add(2*time.Minute)) {
		t.Fatal("cooldown still active after it expired")
	}
	// A different group is unaffected.
	if s.CooldownActive("r@1", "other", time.Minute, base) {
		t.Fatal("cooldown leaked across groups")
	}
}

func TestChaining(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	s.MarkFired("prereq@1", "g", "prereq", base, map[rules.Field]string{
		rules.FieldSourceIP: "1.2.3.4",
	})

	if !s.HasRecentFiring("prereq", rules.FieldSourceIP, "1.2.3.4", 5*time.Minute, base.Add(time.Minute)) {
		t.Fatal("recent firing not found")
	}
	if s.HasRecentFiring("prereq", rules.FieldSourceIP, "9.9.9.9", 5*time.Minute, base.Add(time.Minute)) {
		t.Fatal("chaining matched a different entity")
	}
	if s.HasRecentFiring("prereq", rules.FieldSourceIP, "1.2.3.4", 5*time.Minute, base.Add(10*time.Minute)) {
		t.Fatal("chaining matched outside the window")
	}
	// An empty value must never match, or an event missing its entity would
	// chain onto anything.
	if s.HasRecentFiring("prereq", rules.FieldSourceIP, "", 5*time.Minute, base) {
		t.Fatal("chaining matched an empty value")
	}
}

func TestPruneRemovesOldState(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	s.Observe("r@1", "g", state.Observation{At: base, EventID: "e"}, time.Minute)
	s.MarkFired("r@1", "g", "r", base, nil)

	s.Prune(base.Add(time.Hour), time.Minute)

	if s.Size() != 0 {
		t.Fatalf("size = %d after prune, want 0", s.Size())
	}
}

func TestGroupBoundIsEnforcedDeterministically(t *testing.T) {
	opts := state.DefaultOptions()
	opts.MaxGroups = 10
	s := state.New(opts)

	base := time.Now().UTC()
	for i := 0; i < 100; i++ {
		s.Observe("r@1", string(rune('a'+i%26))+string(rune('0'+i/26)), state.Observation{
			At:      base.Add(time.Duration(i) * time.Second),
			EventID: "e",
		}, time.Minute)
	}
	if s.Size() > opts.MaxGroups {
		t.Fatalf("tracked groups = %d, want <= %d", s.Size(), opts.MaxGroups)
	}
}

func TestPerGroupBoundIsEnforced(t *testing.T) {
	opts := state.DefaultOptions()
	opts.MaxPerGroup = 5
	s := state.New(opts)

	base := time.Now().UTC()
	for i := 0; i < 50; i++ {
		s.Observe("r@1", "g", state.Observation{
			At:      base.Add(time.Duration(i) * time.Millisecond),
			EventID: "e",
		}, time.Hour)
	}
	if got := len(s.Evidence("r@1", "g")); got > opts.MaxPerGroup {
		t.Fatalf("retained observations = %d, want <= %d", got, opts.MaxPerGroup)
	}
}

func TestReset(t *testing.T) {
	s := state.New(state.DefaultOptions())
	s.Observe("r@1", "g", state.Observation{At: time.Now().UTC(), EventID: "e"}, time.Minute)
	s.Reset()
	if s.Size() != 0 {
		t.Fatal("Reset did not clear the state")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	s := state.New(state.DefaultOptions())
	base := time.Now().UTC()

	done := make(chan struct{})
	for w := 0; w < 8; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				s.Observe("r@1", "g", state.Observation{At: base, EventID: "e"}, time.Minute)
				s.CooldownActive("r@1", "g", time.Minute, base)
				s.MarkFired("r@1", "g", "r", base, nil)
				s.HasRecentFiring("r", rules.FieldSourceIP, "v", time.Minute, base)
			}
		}(w)
	}
	for w := 0; w < 8; w++ {
		<-done
	}
}
