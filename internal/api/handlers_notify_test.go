package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/notify"
)

func TestIncidentCreationFiresWebhook(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	var mu sync.Mutex
	var bodies [][]byte
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, raw)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	n := notify.New(notify.Options{URL: hook.URL, Timeout: 5 * time.Second, QueueSize: 8})
	h.api.SetNotifier(n)
	ctx := t.Context()
	go n.Run(ctx)

	// The shipped ssh-bruteforce rule fires at 5 failures from one source,
	// which through the chained rules becomes an incident.
	base := time.Now().UTC().Add(-time.Minute)
	var batch []*model.Event
	for i := 0; i < 5; i++ {
		e := sshFailure(fmt.Sprintf("evt_hook_%d", i), "203.0.113.77", base.Add(time.Duration(i)*time.Second))
		batch = append(batch, e)
	}
	resp := h.do(http.MethodPost, "/api/v1/events", map[string]any{"events": batch}, h.agentHeaders())
	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("ingest = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(bodies)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) == 0 {
		t.Fatal("no webhook was delivered for the created incident")
	}
	var payload struct {
		Event    string `json:"event"`
		Incident struct {
			ID     string   `json:"id"`
			Hosts  []string `json:"hosts"`
			Alerts int      `json:"alerts"`
		} `json:"incident"`
	}
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatalf("webhook body is not JSON: %v", err)
	}
	if payload.Event != "incident.created" {
		t.Errorf("event = %q", payload.Event)
	}
	if len(payload.Incident.Hosts) == 0 || payload.Incident.Alerts == 0 {
		t.Errorf("incident projection is empty: %+v", payload.Incident)
	}
}

func TestMergeDoesNotRefireWebhook(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()

	var mu sync.Mutex
	count := 0
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	n := notify.New(notify.Options{URL: hook.URL, Timeout: 5 * time.Second, QueueSize: 32})
	h.api.SetNotifier(n)
	go n.Run(t.Context())

	// Two bursts inside one cooldown: the first creates the incident, the
	// second merges into it. Only creation notifies.
	base := time.Now().UTC().Add(-2 * time.Minute)
	post := func(start int) {
		var batch []*model.Event
		for i := 0; i < 5; i++ {
			batch = append(batch, sshFailure(
				fmt.Sprintf("evt_merge_%d", start+i), "203.0.113.78",
				base.Add(time.Duration(start+i)*time.Second)))
		}
		resp := h.do(http.MethodPost, "/api/v1/events", map[string]any{"events": batch}, h.agentHeaders())
		resp.Body.Close()
	}
	post(0)
	post(5)

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		c := count
		mu.Unlock()
		if c > 0 {
			// Give a merge a chance to (incorrectly) fire before asserting.
			time.Sleep(500 * time.Millisecond)
			mu.Lock()
			c = count
			mu.Unlock()
			if c != 1 {
				t.Fatalf("webhooks delivered = %d, want exactly 1 (creation only)", c)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no webhook was delivered at all")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
