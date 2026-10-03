// Package stream is the in-process realtime event bus behind the SSE endpoint.
//
// DESIGN.md §10.4 and ADR-003 define the contract. Two properties shape the
// implementation:
//
//  1. A subscriber can never block the publisher. Publishing is non-blocking, and
//     a subscriber whose buffer is full is disconnected rather than allowed to
//     slow down ingestion. A realtime feed is an observer of the pipeline, never a
//     participant in it.
//  2. Every subscriber is bounded. Both the number of subscribers and the depth of
//     each subscriber's buffer are capped, so a client that stops reading cannot
//     grow memory without limit.
//
// The payload of an event is a projection, never a full record: a stream must not
// become a bulk data-export path, and it must not carry a field that the REST API
// would have required a permission to read.
package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/halimi/halimisoc/internal/authorization"
)

// EventType is the SSE event name.
type EventType string

const (
	// EventAlertCreated is emitted when a rule produces an alert.
	EventAlertCreated EventType = "alert.created"

	// EventIncidentCreated is emitted when correlation opens a new incident.
	EventIncidentCreated EventType = "incident.created"

	// EventIncidentUpdated is emitted when an alert joins an existing incident.
	EventIncidentUpdated EventType = "incident.updated"

	// EventAgentStatus is emitted when an agent's liveness state changes.
	EventAgentStatus EventType = "agent.status_changed"

	// EventPlatformMetric is a periodic summary for the dashboard header.
	EventPlatformMetric EventType = "platform.metric"

	// EventSessionRevoked is a control event, not a data event. It carries no
	// record; it tells a stream to terminate because its session is gone.
	EventSessionRevoked EventType = "session.revoked"
)

// Event is one message delivered to subscribers.
type Event struct {
	Type EventType
	Data any

	// Permission is the permission a subscriber must hold to receive this event.
	// Filtering by permission rather than by role means a new role does not
	// require a change here.
	Permission authorization.Permission

	// SessionID, when set, restricts delivery to that session. Used by the
	// revocation control event so one session's revocation does not wake every
	// stream.
	SessionID string

	// UserID, when set, restricts delivery to sessions of that user.
	UserID string

	At time.Time
}

// Subscriber is one connected stream.
type Subscriber struct {
	// ID is the session id, used to target control events.
	ID string

	// UserID is the authenticated user, used to target user-scoped control events.
	UserID string

	// Role is the subscriber's role, used for permission filtering.
	Role authorization.Role

	ch     chan Event
	closed chan struct{}
	once   sync.Once
}

// Events returns the receive side of the subscriber's buffer.
func (s *Subscriber) Events() <-chan Event { return s.ch }

// Done is closed when the subscriber is disconnected by the hub.
func (s *Subscriber) Done() <-chan struct{} { return s.closed }

// Close disconnects the subscriber. It is safe to call more than once.
func (s *Subscriber) Close() {
	s.once.Do(func() { close(s.closed) })
}

// Options bound the hub.
type Options struct {
	// MaxSubscribers caps concurrent streams across the process.
	MaxSubscribers int

	// Buffer is the per-subscriber queue depth.
	Buffer int
}

// DefaultOptions returns conservative bounds.
func DefaultOptions() Options {
	return Options{MaxSubscribers: 100, Buffer: 64}
}

// Hub fans events out to subscribers.
type Hub struct {
	mu     sync.RWMutex
	opts   Options
	subs   map[*Subscriber]struct{}
	closed bool

	// dropped counts events not delivered because a subscriber's buffer was
	// full. It is exposed as a metric so silent loss is impossible.
	dropped uint64

	// rejected counts connection attempts refused because the cap was reached.
	rejected uint64
}

// NewHub builds a hub.
func NewHub(opts Options) *Hub {
	def := DefaultOptions()
	if opts.MaxSubscribers <= 0 {
		opts.MaxSubscribers = def.MaxSubscribers
	}
	if opts.Buffer <= 0 {
		opts.Buffer = def.Buffer
	}
	return &Hub{opts: opts, subs: map[*Subscriber]struct{}{}}
}

// Subscribe registers a stream.
//
// It returns an error rather than blocking or silently succeeding when the cap is
// reached: a caller that cannot stream should tell the client, not hold an open
// connection that will never receive anything.
func (h *Hub) Subscribe(id, userID string, role authorization.Role) (*Subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil, fmt.Errorf("stream: hub is closed")
	}
	if len(h.subs) >= h.opts.MaxSubscribers {
		h.rejected++
		return nil, fmt.Errorf("stream: subscriber limit %d reached", h.opts.MaxSubscribers)
	}

	s := &Subscriber{
		ID:     id,
		UserID: userID,
		Role:   role,
		ch:     make(chan Event, h.opts.Buffer),
		closed: make(chan struct{}),
	}
	h.subs[s] = struct{}{}
	return s, nil
}

// Unsubscribe removes a stream and closes it.
func (h *Hub) Unsubscribe(s *Subscriber) {
	if s == nil {
		return
	}
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
	s.Close()
}

// Publish delivers an event to every eligible subscriber.
//
// Delivery is non-blocking. A subscriber whose buffer is full is disconnected,
// because the alternative is either blocking ingestion on a slow browser or
// dropping the event silently. Disconnecting is honest: the client reconnects and
// re-reads current state, whereas a silent gap would leave it showing stale data
// while believing it is live.
func (h *Hub) Publish(ev Event) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}

	h.mu.Lock()
	targets := make([]*Subscriber, 0, len(h.subs))
	var overflowed []*Subscriber

	for s := range h.subs {
		if !eligible(s, ev) {
			continue
		}
		select {
		case s.ch <- ev:
			targets = append(targets, s)
		default:
			overflowed = append(overflowed, s)
			h.dropped++
		}
	}

	for _, s := range overflowed {
		delete(h.subs, s)
	}
	h.mu.Unlock()

	// Closing outside the lock: Close is idempotent, and holding the lock while
	// waking a goroutine that may call Unsubscribe would deadlock.
	for _, s := range overflowed {
		s.Close()
	}
}

// eligible applies the permission and targeting rules for an event.
func eligible(s *Subscriber, ev Event) bool {
	// A targeted control event reaches only its target.
	if ev.SessionID != "" && ev.SessionID != s.ID {
		return false
	}
	if ev.UserID != "" && ev.UserID != s.UserID {
		return false
	}
	// A permission-scoped event requires that permission. An unknown permission
	// denies, matching the fail-closed rule used everywhere else.
	if ev.Permission != "" && !authorization.Allowed(s.Role, ev.Permission) {
		return false
	}
	return true
}

// RevokeSession tells every stream belonging to a session to terminate.
//
// This is what makes revocation immediate rather than eventually consistent. The
// stream also revalidates periodically as a backstop, so a missed control event
// cannot leave a revoked session streaming indefinitely.
func (h *Hub) RevokeSession(sessionID string) {
	h.Publish(Event{
		Type:      EventSessionRevoked,
		SessionID: sessionID,
	})
}

// RevokeUserSessions terminates every stream belonging to a user.
func (h *Hub) RevokeUserSessions(userID string) {
	h.Publish(Event{
		Type:   EventSessionRevoked,
		UserID: userID,
	})
}

// Count returns the number of active subscribers.
func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Dropped returns the number of events not delivered because a buffer was full.
func (h *Hub) Dropped() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.dropped
}

// Rejected returns the number of connection attempts refused at the cap.
func (h *Hub) Rejected() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.rejected
}

// Close disconnects every subscriber and refuses further subscriptions.
func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	subs := make([]*Subscriber, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.subs = map[*Subscriber]struct{}{}
	h.mu.Unlock()

	for _, s := range subs {
		s.Close()
	}
}

// RunKeepalive publishes a periodic platform metric and revalidates every stream.
//
// The metric gives the dashboard header a heartbeat so an operator can tell a quiet
// system from a broken connection. The revalidation is the backstop for revocation:
// it runs even if a control event was lost.
func (h *Hub) RunKeepalive(ctx context.Context, interval time.Duration, snapshot func() map[string]any, revalidate func(s *Subscriber) bool) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if snapshot != nil {
				h.Publish(Event{
					Type:       EventPlatformMetric,
					Data:       snapshot(),
					Permission: authorization.PermViewEvents,
				})
			}
			if revalidate != nil {
				h.revalidateAll(revalidate)
			}
		}
	}
}

func (h *Hub) revalidateAll(revalidate func(s *Subscriber) bool) {
	h.mu.RLock()
	subs := make([]*Subscriber, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.RUnlock()

	for _, s := range subs {
		if !revalidate(s) {
			h.Unsubscribe(s)
		}
	}
}

// MarshalData renders an event payload as JSON for the wire.
func MarshalData(v any) ([]byte, error) {
	if v == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(v)
}
