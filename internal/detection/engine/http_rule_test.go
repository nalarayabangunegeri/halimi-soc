package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

const httpSpikeRule = `
id: http-auth-failure-spike
version: 1
name: HTTP Authentication Failure Spike
severity: medium
match:
  types:
    - http.auth.failed
  outcomes:
    - failure
threshold:
  count: 10
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`

func httpFailed(id, ip string, at time.Time) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeHTTPAuthFailed,
		Time:       at,
		ReceivedAt: at,
		Host:       "web-01",
		Outcome:    model.OutcomeFailure,
		Severity:   model.SeverityLow,
		Network:    model.Network{SourceIP: ip},
		Attributes: map[string]string{"http_status": "401"},
	}
}

func feedHTTP(t *testing.T, eng *Engine, ip string, n int, base time.Time, step time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		at := base.Add(time.Duration(i) * step)
		if _, err := eng.Process(context.Background(), httpFailed(fmt.Sprintf("evt_http_%s_%d", ip, i), ip, at)); err != nil {
			t.Fatalf("Process() = %v", err)
		}
	}
}

func TestHTTPAuthSpikePositive(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	feedHTTP(t, eng, "203.0.113.7", 10, *now, time.Second)
	alerts := sink.alerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "http-auth-failure-spike" || a.RuleVersion != 1 {
		t.Errorf("rule identity = %s@%d, want http-auth-failure-spike@1", a.RuleID, a.RuleVersion)
	}
	if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %s, want medium", a.Severity)
	}
	if a.SourceIP != "203.0.113.7" {
		t.Errorf("src_ip = %q, want attacker address", a.SourceIP)
	}
}

func TestHTTPAuthSpikeThresholdBoundary(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	feedHTTP(t, eng, "203.0.113.7", 9, *now, time.Second)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts below threshold = %d, want 0", got)
	}
	if _, err := eng.Process(context.Background(), httpFailed("evt_http_tenth", "203.0.113.7", now.Add(9*time.Second))); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts at threshold = %d, want 1", got)
	}
}

func TestHTTPAuthSpikeWindowBoundary(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	// Ten failures spread over 90s never have ten inside any 60s window.
	feedHTTP(t, eng, "203.0.113.7", 10, *now, 10*time.Second)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts outside window = %d, want 0", got)
	}
}

func TestHTTPAuthSpikeGroupingIsolatesSources(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	feedHTTP(t, eng, "203.0.113.7", 5, *now, time.Second)
	feedHTTP(t, eng, "198.51.100.9", 5, *now, time.Second)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts across groups = %d, want 0", got)
	}
}

func TestHTTPAuthSpikeMissingIPNotCounted(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	for i := 0; i < 10; i++ {
		e := httpFailed(fmt.Sprintf("evt_http_noip_%d", i), "", now.Add(time.Duration(i)*time.Second))
		if _, err := eng.Process(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts without group key = %d, want 0", got)
	}
}

func TestHTTPAuthSpikeCooldown(t *testing.T) {
	eng, sink, _, nowPtr := newEngine(t, httpSpikeRule)
	base := *nowPtr
	feedHTTP(t, eng, "203.0.113.7", 10, base, time.Second)
	// A second burst inside the 5m cooldown is suppressed, not re-alerted.
	*nowPtr = base.Add(61 * time.Second)
	feedHTTP(t, eng, "203.0.113.7", 10, *nowPtr, time.Second)
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts during cooldown = %d, want 1", got)
	}
}

func TestHTTPAuthSpikeNegativeOutcome(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)
	for i := 0; i < 10; i++ {
		e := httpFailed(fmt.Sprintf("evt_http_ok_%d", i), "203.0.113.7", now.Add(time.Duration(i)*time.Second))
		e.Type = model.TypeHTTPAuthSuccess
		e.Outcome = model.OutcomeSuccess
		if _, err := eng.Process(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts for success outcome = %d, want 0", got)
	}
}

func TestReloadSwapsRuleSetAtomically(t *testing.T) {
	eng, sink, _, now := newEngine(t, httpSpikeRule)

	// Nil is a no-op: the active set must survive a bad call.
	eng.Reload(nil)
	feedHTTP(t, eng, "203.0.113.7", 10, *now, time.Second)
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts after nil reload = %d, want 1", got)
	}

	// A stricter set replaces the old one: the same burst no longer fires.
	strict := `
id: http-auth-failure-spike
version: 2
name: HTTP Authentication Failure Spike
severity: medium
match:
  types:
    - http.auth.failed
threshold:
  count: 100
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`
	eng.Reload(mustSet(t, strict))
	feedHTTP(t, eng, "198.51.100.9", 10, now.Add(time.Hour), time.Second)
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts after stricter reload = %d, want still 1", got)
	}
	if got := eng.Rules().Len(); got != 1 {
		t.Fatalf("reloaded set size = %d, want 1", got)
	}
}
