package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

const firewallScanRule = `
id: firewall-port-scan
version: 1
name: Firewall Port Scan
severity: medium
match:
  types:
    - network.firewall.block
threshold:
  count: 10
  window: 5m
group_by:
  - network.src_ip
cooldown: 15m
`

func firewallBlock(id, ip string, at time.Time, dport int) *model.Event {
	return &model.Event{
		ID:         id,
		Type:       model.TypeFirewallBlock,
		Time:       at,
		ReceivedAt: at,
		Host:       "web-01",
		Outcome:    model.OutcomeUnknown,
		Severity:   model.SeverityLow,
		Network:    model.Network{SourceIP: ip, DestIP: "10.0.0.5", DestPort: dport, Protocol: "tcp"},
		Attributes: map[string]string{"firewall_action": "block"},
	}
}

func feedFirewall(t *testing.T, eng *Engine, ip string, n int, base time.Time, step time.Duration) {
	t.Helper()
	for i := 0; i < n; i++ {
		at := base.Add(time.Duration(i) * step)
		if _, err := eng.Process(context.Background(), firewallBlock(fmt.Sprintf("evt_fw_%s_%d", ip, i), ip, at, 20+i)); err != nil {
			t.Fatalf("Process() = %v", err)
		}
	}
}

func TestFirewallScanPositive(t *testing.T) {
	eng, sink, _, now := newEngine(t, firewallScanRule)
	feedFirewall(t, eng, "203.0.113.7", 10, *now, 5*time.Second)
	alerts := sink.alerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	a := alerts[0]
	if a.RuleID != "firewall-port-scan" || a.RuleVersion != 1 {
		t.Errorf("rule identity = %s@%d, want firewall-port-scan@1", a.RuleID, a.RuleVersion)
	}
	if a.Severity != model.SeverityMedium {
		t.Errorf("severity = %s, want medium", a.Severity)
	}
}

func TestFirewallScanThresholdBoundary(t *testing.T) {
	eng, sink, _, now := newEngine(t, firewallScanRule)
	feedFirewall(t, eng, "203.0.113.7", 9, *now, 5*time.Second)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts below threshold = %d, want 0", got)
	}
	if _, err := eng.Process(context.Background(), firewallBlock("evt_fw_tenth", "203.0.113.7", now.Add(45*time.Second), 8080)); err != nil {
		t.Fatal(err)
	}
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts at threshold = %d, want 1", got)
	}
}

func TestFirewallScanWindowBoundary(t *testing.T) {
	eng, sink, _, now := newEngine(t, firewallScanRule)
	// Ten blocks spread over 10 minutes never have ten inside any 5m window.
	feedFirewall(t, eng, "203.0.113.7", 10, *now, time.Minute)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts outside window = %d, want 0", got)
	}
}

func TestFirewallScanGroupingIsolatesSources(t *testing.T) {
	eng, sink, _, now := newEngine(t, firewallScanRule)
	feedFirewall(t, eng, "203.0.113.7", 5, *now, 5*time.Second)
	feedFirewall(t, eng, "198.51.100.9", 5, *now, 5*time.Second)
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts across groups = %d, want 0", got)
	}
}

func TestFirewallScanMissingIPNotCounted(t *testing.T) {
	eng, sink, _, now := newEngine(t, firewallScanRule)
	for i := 0; i < 10; i++ {
		e := firewallBlock(fmt.Sprintf("evt_fw_noip_%d", i), "", now.Add(time.Duration(i)*5*time.Second), 22)
		if _, err := eng.Process(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(sink.alerts()); got != 0 {
		t.Fatalf("alerts without group key = %d, want 0", got)
	}
}

func TestFirewallScanCooldown(t *testing.T) {
	eng, sink, _, nowPtr := newEngine(t, firewallScanRule)
	base := *nowPtr
	feedFirewall(t, eng, "203.0.113.7", 10, base, 5*time.Second)
	// A second burst inside the 15m cooldown is suppressed, not re-alerted.
	*nowPtr = base.Add(6 * time.Minute)
	feedFirewall(t, eng, "203.0.113.7", 10, *nowPtr, 5*time.Second)
	if got := len(sink.alerts()); got != 1 {
		t.Fatalf("alerts during cooldown = %d, want 1", got)
	}
}
