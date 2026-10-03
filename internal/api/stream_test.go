package api_test

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/id"
)

// sseFrame is one parsed server-sent event.
type sseFrame struct {
	Event string
	Data  string
}

// openStream connects to the SSE endpoint and returns frames as they arrive.
//
// The stream is consumed on its own goroutine because a server-sent event
// connection is long-lived: a test that read synchronously would block until the
// server closed it, which is never.
func openStream(t *testing.T, h *harness, do func() (*http.Response, error)) (<-chan sseFrame, func()) {
	t.Helper()

	resp, err := do()
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		resp.Body.Close()
		t.Fatalf("content type = %q, want text/event-stream", ct)
	}

	frames := make(chan sseFrame, 32)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer close(frames)
		scanner := bufio.NewScanner(resp.Body)
		var current sseFrame
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				current.Event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				current.Data = strings.TrimPrefix(line, "data: ")
			case line == "":
				if current.Event != "" || current.Data != "" {
					select {
					case frames <- current:
					case <-ctx.Done():
						return
					}
					current = sseFrame{}
				}
			}
		}
	}()

	cleanup := func() {
		cancel()
		resp.Body.Close()
	}
	t.Cleanup(cleanup)
	return frames, cleanup
}

// awaitFrame waits for a frame whose event name matches, ignoring comments and
// unrelated events.
func awaitFrame(t *testing.T, frames <-chan sseFrame, want string, timeout time.Duration) sseFrame {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("stream closed while waiting for %q", want)
			}
			if f.Event == want {
				return f
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q", want)
		}
	}
}

func TestStreamRequiresAuthentication(t *testing.T) {
	h := newHarness(t)

	resp, err := http.Get(h.server.URL + "/api/v1/stream") //nolint:noctx // bounded by the client timeout
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestStreamRejectsAgentCredential(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/api/v1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+h.agentTok)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// An agent is not an operator, so it must not open an operator feed.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestStreamDeliversAlertCreated(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	frames, _ := openStream(t, h, func() (*http.Response, error) {
		return h.client.Get(h.server.URL + "/api/v1/stream")
	})

	base := time.Now().UTC().Add(-time.Minute)
	batch := map[string]any{"events": []*model.Event{
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
		sshFailure(id.NewEvent(), "203.0.113.7", base),
	}}
	if resp := h.do(http.MethodPost, "/api/v1/events", batch, h.agentHeaders()); resp.StatusCode != http.StatusAccepted {
		resp.Body.Close()
		t.Fatalf("ingest status = %d", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	alert := awaitFrame(t, frames, "alert.created", 5*time.Second)

	// The payload is a projection. It must not carry raw evidence, and it must
	// identify the rule that fired.
	if !strings.Contains(alert.Data, "ssh-bruteforce") {
		t.Errorf("alert frame does not identify the rule: %s", alert.Data)
	}
	for _, forbidden := range []string{"raw", "Failed password", "event_ids"} {
		if strings.Contains(alert.Data, forbidden) {
			t.Errorf("alert frame leaked %q: %s", forbidden, alert.Data)
		}
	}

	// The incident follows.
	incident := awaitFrame(t, frames, "incident.created", 5*time.Second)
	if !strings.Contains(incident.Data, `"status":"NEW"`) {
		t.Errorf("incident frame does not report the new lifecycle state: %s", incident.Data)
	}
}

func TestStreamIsNotDeliveredToInsufficientRole(t *testing.T) {
	h := newHarness(t)

	hash, err := auth.HashPassword("nosy-password-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "nosy",
		PasswordHash: hash,
		Role:         authorization.RoleReadonly,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	if _, status := h.login("nosy", "nosy-password-value"); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	frames, _ := openStream(t, h, func() (*http.Response, error) {
		return h.client.Get(h.server.URL + "/api/v1/stream")
	})

	// An audit event requires view_audit, which a readonly operator does not
	// hold. It must be filtered out at the hub, not merely hidden by the UI.
	h.hub.Publish(stream.Event{
		Type:       "audit.created",
		Data:       map[string]string{"action": "LOGIN_SUCCESS"},
		Permission: authorization.PermViewAudit,
	})

	select {
	case f := <-frames:
		t.Fatalf("a readonly subscriber received %s: %s", f.Event, f.Data)
	case <-time.After(300 * time.Millisecond):
		// Expected: nothing arrived.
	}

	// A permitted event on the same connection does arrive, which proves the
	// stream is live and the previous silence was filtering, not a dead socket.
	h.hub.Publish(stream.Event{
		Type:       stream.EventAlertCreated,
		Data:       map[string]string{"id": "alt_permitted"},
		Permission: authorization.PermViewAlerts,
	})
	frame := awaitFrame(t, frames, "alert.created", 2*time.Second)
	if !strings.Contains(frame.Data, "alt_permitted") {
		t.Errorf("permitted event payload = %s", frame.Data)
	}
}

func TestStreamTerminatesOnLogout(t *testing.T) {
	h := newHarness(t)

	csrf, status := h.login("admin", adminPassword)
	if status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	frames, _ := openStream(t, h, func() (*http.Response, error) {
		return h.client.Get(h.server.URL + "/api/v1/stream")
	})

	// Revoking the session must end the stream promptly, not at the next
	// scheduled revalidation. This is the property ADR-003 calls "revocation is
	// immediate".
	resp := h.do(http.MethodPost, "/api/v1/auth/logout", nil, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	frame := awaitFrame(t, frames, "session.revoked", 5*time.Second)
	if !strings.Contains(frame.Data, "no longer valid") {
		t.Errorf("revocation frame does not explain itself: %s", frame.Data)
	}
}

func TestStreamRejectsWhenAtConnectionCap(t *testing.T) {
	// The harness hub allows 16 subscribers. Exhausting it must produce a clear
	// refusal rather than an accepted connection that never receives anything.
	h := newHarness(t)
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login status = %d", status)
	}

	held := make([]*stream.Subscriber, 0, 16)
	for i := 0; i < 16; i++ {
		sub, err := h.hub.Subscribe("sess_holder", "usr", authorization.RoleAdmin)
		if err != nil {
			t.Fatalf("subscriber %d: %v", i, err)
		}
		held = append(held, sub)
	}
	defer func() {
		for _, sub := range held {
			h.hub.Unsubscribe(sub)
		}
	}()

	resp, err := h.client.Get(h.server.URL + "/api/v1/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 at the connection cap", resp.StatusCode)
	}
}
