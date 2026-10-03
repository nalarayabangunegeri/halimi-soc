package stream_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/stream"
)

func TestPublishDeliversToEligibleSubscribers(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	sub, err := h.Subscribe("sess_1", "usr_1", authorization.RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Unsubscribe(sub)

	h.Publish(stream.Event{
		Type:       stream.EventAlertCreated,
		Data:       map[string]string{"id": "alt_1"},
		Permission: authorization.PermViewAlerts,
	})

	select {
	case ev := <-sub.Events():
		if ev.Type != stream.EventAlertCreated {
			t.Fatalf("type = %s", ev.Type)
		}
		if ev.At.IsZero() {
			t.Error("the hub must timestamp an event that arrives without one")
		}
	case <-time.After(time.Second):
		t.Fatal("event was not delivered")
	}
}

func TestPermissionFilteringIsFailClosed(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	readonly, err := h.Subscribe("sess_ro", "usr_ro", authorization.RoleReadonly)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Unsubscribe(readonly)

	// A readonly subscriber may view alerts, so this event reaches it.
	h.Publish(stream.Event{Type: stream.EventAlertCreated, Permission: authorization.PermViewAlerts})
	select {
	case <-readonly.Events():
	case <-time.After(time.Second):
		t.Fatal("a permitted event was filtered out")
	}

	// It may not view audit, so this one must not.
	h.Publish(stream.Event{Type: "audit.created", Permission: authorization.PermViewAudit})
	select {
	case ev := <-readonly.Events():
		t.Fatalf("an event requiring a permission the subscriber lacks was delivered: %s", ev.Type)
	case <-time.After(100 * time.Millisecond):
	}

	// An event with an unknown permission must reach nobody: an unset requirement
	// that silently defaulted to allowed would be a data leak.
	h.Publish(stream.Event{Type: "mystery", Permission: authorization.Permission("not_a_permission")})
	select {
	case ev := <-readonly.Events():
		t.Fatalf("an event with an unknown permission was delivered: %s", ev.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTargetedControlEventReachesOnlyItsTarget(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	a, _ := h.Subscribe("sess_a", "usr_a", authorization.RoleAdmin)
	b, _ := h.Subscribe("sess_b", "usr_b", authorization.RoleAdmin)
	defer h.Unsubscribe(a)
	defer h.Unsubscribe(b)

	h.RevokeSession("sess_a")

	select {
	case ev := <-a.Events():
		if ev.Type != stream.EventSessionRevoked {
			t.Fatalf("type = %s", ev.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("the target did not receive its revocation")
	}

	select {
	case ev := <-b.Events():
		t.Fatalf("an unrelated session received %s", ev.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRevokeUserSessionsTargetsAllOfOneUser(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	one, _ := h.Subscribe("sess_1", "usr_target", authorization.RoleAdmin)
	two, _ := h.Subscribe("sess_2", "usr_target", authorization.RoleAdmin)
	other, _ := h.Subscribe("sess_3", "usr_other", authorization.RoleAdmin)
	defer h.Unsubscribe(one)
	defer h.Unsubscribe(two)
	defer h.Unsubscribe(other)

	h.RevokeUserSessions("usr_target")

	for i, sub := range []*stream.Subscriber{one, two} {
		select {
		case <-sub.Events():
		case <-time.After(time.Second):
			t.Fatalf("session %d did not receive the user revocation", i+1)
		}
	}
	select {
	case ev := <-other.Events():
		t.Fatalf("another user received %s", ev.Type)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSubscriberCapIsEnforced(t *testing.T) {
	h := stream.NewHub(stream.Options{MaxSubscribers: 2, Buffer: 4})
	defer h.Close()

	first, err := h.Subscribe("a", "u", authorization.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.Subscribe("b", "u", authorization.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	// The third must be refused, not silently accepted and starved.
	if _, err := h.Subscribe("c", "u", authorization.RoleAdmin); err == nil {
		t.Fatal("a subscription beyond the cap was accepted")
	}
	if h.Rejected() != 1 {
		t.Errorf("rejected = %d, want 1", h.Rejected())
	}

	h.Unsubscribe(first)
	h.Unsubscribe(second)
	if h.Count() != 0 {
		t.Errorf("count = %d after unsubscribe, want 0", h.Count())
	}
}

func TestSlowSubscriberIsDisconnectedNotBlocking(t *testing.T) {
	// A subscriber that never reads must not be able to block the publisher or
	// grow memory. It is disconnected instead.
	h := stream.NewHub(stream.Options{MaxSubscribers: 4, Buffer: 2})
	defer h.Close()

	slow, err := h.Subscribe("slow", "u", authorization.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Unsubscribe(slow)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			h.Publish(stream.Event{Type: stream.EventAlertCreated})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publishing blocked on a slow subscriber")
	}

	select {
	case <-slow.Done():
		// Expected: the hub disconnected it.
	case <-time.After(time.Second):
		t.Fatal("the slow subscriber was not disconnected")
	}
	if h.Dropped() == 0 {
		t.Error("dropped count is zero, so the overflow was not accounted for")
	}
}

func TestUnsubscribeIsIdempotent(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	sub, err := h.Subscribe("s", "u", authorization.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	h.Unsubscribe(sub)
	h.Unsubscribe(sub)
	h.Unsubscribe(nil)

	select {
	case <-sub.Done():
	default:
		t.Fatal("Done was not closed by Unsubscribe")
	}
}

func TestCloseDisconnectsEveryone(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())

	a, _ := h.Subscribe("a", "u", authorization.RoleAdmin)
	b, _ := h.Subscribe("b", "u", authorization.RoleAdmin)

	h.Close()

	for i, sub := range []*stream.Subscriber{a, b} {
		select {
		case <-sub.Done():
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d was not released by Close", i)
		}
	}
	if _, err := h.Subscribe("c", "u", authorization.RoleAdmin); err == nil {
		t.Error("Subscribe succeeded after Close")
	}
	h.Close() // must be idempotent
}

func TestConcurrentPublishAndSubscribe(t *testing.T) {
	h := stream.NewHub(stream.Options{MaxSubscribers: 64, Buffer: 16})
	defer h.Close()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				h.Publish(stream.Event{Type: stream.EventAlertCreated})
				if sub, err := h.Subscribe("s", "u", authorization.RoleAnalyst); err == nil {
					select {
					case <-sub.Events():
					default:
					}
					h.Unsubscribe(sub)
				}
			}
		}()
	}
	wg.Wait()
}

func TestRunKeepalivePublishesSnapshotAndRevalidates(t *testing.T) {
	h := stream.NewHub(stream.DefaultOptions())
	defer h.Close()

	sub, err := h.Subscribe("sess_keep", "usr", authorization.RoleAnalyst)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Both variables are written by the keepalive goroutine and read by this one
	// while it is still running, so they must be atomic: the previous `revalidated`
	// was an int32 guarded by nothing, and `invalid` was a plain bool written here
	// and read on every tick. The race only surfaced when a second tick landed
	// between the first snapshot and the assertion, which made it flaky rather than
	// absent.
	var revalidated int32
	var invalid atomic.Bool
	go h.RunKeepalive(ctx, 20*time.Millisecond,
		func() map[string]any { return map[string]any{"agents_online": 1} },
		func(s *stream.Subscriber) bool {
			atomic.AddInt32(&revalidated, 1)
			return !invalid.Load()
		})

	// The snapshot arrives as a permitted metric event.
	deadline := time.After(time.Second)
	for {
		select {
		case ev := <-sub.Events():
			if ev.Type == stream.EventPlatformMetric {
				goto validated
			}
		case <-deadline:
			t.Fatal("no keepalive snapshot was published")
		}
	}

validated:
	if atomic.LoadInt32(&revalidated) == 0 {
		t.Fatal("revalidation was never invoked")
	}

	// Once revalidation says the session is gone, the subscriber is removed.
	invalid.Store(true)
	deadline = time.After(2 * time.Second)
	for {
		select {
		case <-sub.Done():
			return
		case <-deadline:
			t.Fatal("an invalid subscriber was not disconnected by revalidation")
		}
	}
}

func TestMarshalData(t *testing.T) {
	got, err := stream.MarshalData(nil)
	if err != nil || string(got) != "{}" {
		t.Fatalf("MarshalData(nil) = %s, %v", got, err)
	}
	got, err = stream.MarshalData(map[string]int{"a": 1})
	if err != nil || string(got) != `{"a":1}` {
		t.Fatalf("MarshalData = %s, %v", got, err)
	}
}
