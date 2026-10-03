package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/notify"
)

func testIncident() *incidents.Incident {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	return &incidents.Incident{
		ID: "inc_01", Title: "SSH Brute Force on web-01", Summary: "s",
		Severity: model.SeverityCritical, Status: incidents.StatusNew,
		Hosts: []string{"web-01"}, Actors: []string{"root"}, SourceIPs: []string{"203.0.113.7"},
		AlertIDs: []string{"alt_1", "alt_2"}, EventIDs: []string{"evt_1"},
		FirstSeen: now, LastSeen: now, CreatedAt: now, UpdatedAt: now,
	}
}

func TestValidate(t *testing.T) {
	if err := (notify.Options{}).Validate(); err != nil {
		t.Fatalf("empty options = %v, want nil (disabled)", err)
	}
	for _, tc := range []struct {
		name string
		opts notify.Options
	}{
		{"ftp scheme", notify.Options{URL: "ftp://example.test/hook", Timeout: time.Second, QueueSize: 1}},
		{"credentials in url", notify.Options{URL: "https://user:pass@example.test/hook", Timeout: time.Second, QueueSize: 1}},
		{"non-positive timeout", notify.Options{URL: "https://example.test/hook", QueueSize: 1}},
		{"non-positive queue", notify.Options{URL: "https://example.test/hook", Timeout: time.Second}},
	} {
		if err := tc.opts.Validate(); err == nil {
			t.Errorf("%s accepted, want rejection", tc.name)
		}
	}
	if err := (notify.Options{URL: "https://example.test/hook", Timeout: time.Second, QueueSize: 1}).Validate(); err != nil {
		t.Fatalf("valid options = %v, want nil", err)
	}
}

func TestDelivery(t *testing.T) {
	var got []byte
	var contentType, userAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		userAgent = r.Header.Get("User-Agent")
		var err error
		got, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reg := metrics.New()
	n := notify.New(notify.Options{URL: srv.URL, Timeout: 5 * time.Second, QueueSize: 8, Registry: reg})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.NotifyIncident(testIncident())

	deadline := time.Now().Add(5 * time.Second)
	for reg.Counter(metrics.WebhookSentTotal) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if reg.Counter(metrics.WebhookSentTotal) != 1 {
		t.Fatal("webhook was not delivered")
	}
	if contentType != "application/json" {
		t.Errorf("content type = %q", contentType)
	}
	if userAgent == "" {
		t.Error("user agent is empty")
	}

	var payload struct {
		Event    string `json:"event"`
		Incident struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Severity string   `json:"severity"`
			Status   string   `json:"status"`
			Hosts    []string `json:"hosts"`
			Alerts   int      `json:"alerts"`
		} `json:"incident"`
	}
	if err := json.Unmarshal(got, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if payload.Event != "incident.created" {
		t.Errorf("event = %q", payload.Event)
	}
	if payload.Incident.ID != "inc_01" || payload.Incident.Alerts != 2 {
		t.Errorf("incident projection = %+v", payload.Incident)
	}
	// Raw evidence must never leave the platform on a webhook: assert the
	// absence of the exact keys rather than substring-matching, so a title
	// that happens to contain those letters cannot fail the test.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw", "attributes", "evidence", "events"} {
		if _, ok := envelope[forbidden]; ok {
			t.Errorf("payload carries forbidden top-level key %q", forbidden)
		}
	}
	var incidentKeys map[string]json.RawMessage
	if err := json.Unmarshal(envelope["incident"], &incidentKeys); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"raw", "attributes", "evidence", "event_ids"} {
		if _, ok := incidentKeys[forbidden]; ok {
			t.Errorf("incident projection carries forbidden key %q", forbidden)
		}
	}
}

func TestNon2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	reg := metrics.New()
	n := notify.New(notify.Options{URL: srv.URL, Timeout: 5 * time.Second, QueueSize: 8, Registry: reg})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.NotifyIncident(testIncident())

	deadline := time.Now().Add(5 * time.Second)
	for reg.Counter(metrics.WebhookErrorTotal) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if reg.Counter(metrics.WebhookErrorTotal) != 1 {
		t.Fatal("non-2xx response was not counted as an error")
	}
}

func TestUnreachableEndpointIsAnError(t *testing.T) {
	reg := metrics.New()
	n := notify.New(notify.Options{URL: "http://127.0.0.1:1/hook", Timeout: time.Second, QueueSize: 8, Registry: reg})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.NotifyIncident(testIncident())

	deadline := time.Now().Add(5 * time.Second)
	for reg.Counter(metrics.WebhookErrorTotal) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if reg.Counter(metrics.WebhookErrorTotal) != 1 {
		t.Fatal("unreachable endpoint was not counted as an error")
	}
}

func TestDisabledNotifierIsNoOp(t *testing.T) {
	n := notify.New(notify.Options{})
	if n.Enabled() {
		t.Fatal("empty URL must disable delivery")
	}
	// Must not panic with no worker running and no registry attached.
	n.NotifyIncident(testIncident())
	n.NotifyIncident(nil)

	var nilNotifier *notify.Notifier
	if nilNotifier.Enabled() {
		t.Fatal("nil notifier must report disabled")
	}
	nilNotifier.NotifyIncident(testIncident())
}
