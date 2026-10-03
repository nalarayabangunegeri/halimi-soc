package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
	"github.com/halimi/halimisoc/internal/storage"
)

// streamKeepalive is how often a comment frame is written.
//
// An idle SSE connection is indistinguishable from a dead one, and intermediaries
// close idle connections. A periodic comment keeps the connection demonstrably
// alive without inventing a data event.
const streamKeepalive = 15 * time.Second

// streamRevalidateEvery bounds how often a stream re-checks its session against
// the store. It is the backstop for the revocation control event: if that event
// were ever missed, a revoked session still terminates within this window.
const streamRevalidateEvery = 30 * time.Second

// handleStream serves the realtime event feed.
//
// Contract, from DESIGN.md §10.4 and ADR-003:
//
//   - authenticated by the session cookie, and authorization is revalidated while
//     the connection is open, not only at connect time;
//   - a revoked session terminates its stream;
//   - only permitted fields are emitted, and never raw evidence;
//   - concurrent connections are bounded;
//   - there is no full-dataset replay: a client that wants history calls the REST
//     endpoints, which enforce their own permissions and pagination.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if s.hub == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "realtime updates are unavailable")
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, CodeInternal, "streaming is not supported")
		return
	}

	sub, err := s.hub.Subscribe(p.Session.ID, p.User.ID, p.Role)
	if err != nil {
		// The cap is a real limit, not a transient error, so it is reported as
		// such rather than as a server fault.
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"too many concurrent realtime connections")
		return
	}
	defer s.hub.Unsubscribe(sub)

	// The write deadline must be lifted for the life of the stream, because an
	// idle-but-healthy stream would otherwise be closed by the server timeout that
	// protects ordinary requests.
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Belt and braces against a proxy buffering the stream into uselessness.
	h.Set("X-Accel-Buffering", "no")

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	s.reg.Set(metrics.SSEActiveConnections, float64(s.hub.Count()))
	defer s.reg.Set(metrics.SSEActiveConnections, float64(s.hub.Count()))

	keepalive := time.NewTicker(streamKeepalive)
	defer keepalive.Stop()

	revalidate := time.NewTicker(streamRevalidateEvery)
	defer revalidate.Stop()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			// The client disconnected or the server is shutting down.
			return

		case <-sub.Done():
			// The hub disconnected us: either our buffer overflowed or our
			// session was revoked. Tell the client why before closing so it can
			// distinguish "reconnect" from "log in again".
			writeSSE(w, "stream.closed", map[string]string{
				"reason": "this connection was closed; reload to continue",
			})
			flusher.Flush()
			return

		case ev := <-sub.Events():
			if ev.Type == stream.EventSessionRevoked {
				writeSSE(w, "session.revoked", map[string]string{
					"reason": "your session is no longer valid",
				})
				flusher.Flush()
				return
			}
			// Re-check the session on every data event. This is cheap (an
			// in-process store read in tests, an indexed primary-key read in
			// production) and it means a revoked session cannot receive even one
			// more event.
			if !s.sessionStillUsable(ctx, p.Session.ID, p.User.ID) {
				writeSSE(w, "session.revoked", map[string]string{
					"reason": "your session is no longer valid",
				})
				flusher.Flush()
				return
			}
			if err := writeSSEEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()

		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()

		case <-revalidate.C:
			if !s.sessionStillUsable(ctx, p.Session.ID, p.User.ID) {
				writeSSE(w, "session.revoked", map[string]string{
					"reason": "your session is no longer valid",
				})
				flusher.Flush()
				return
			}
		}
	}
}

// sessionStillUsable reports whether a session may keep streaming.
//
// It re-reads both the session and the user, because a session can be revoked and
// an account can be disabled, and either condition must end the stream.
//
// The browser's cookie is deliberately not re-read: the stream authenticated once
// at connect time, and re-presenting the secret on every event would mean holding
// the plaintext token in memory for the life of the connection. Validity is
// therefore decided from the stored record's own state.
//
// A store error is treated as "not usable". Failing open on an unreadable session
// would keep a possibly-revoked stream alive, which is the wrong direction for an
// authorization check.
func (s *Server) sessionStillUsable(ctx context.Context, sessionID, userID string) bool {
	now := s.now()

	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return false
	}
	if !sess.Usable(now) {
		return false
	}

	user, err := s.store.GetUser(ctx, userID)
	if err != nil || !user.Active() {
		return false
	}
	return true
}

// writeSSEEvent renders one event frame.
func writeSSEEvent(w http.ResponseWriter, ev stream.Event) error {
	data, err := stream.MarshalData(ev.Data)
	if err != nil {
		// A payload that cannot be encoded is dropped rather than sent as a
		// broken frame, which would desynchronise the client's parser.
		return err
	}
	return writeSSE(w, string(ev.Type), json.RawMessage(data))
}

// writeSSE writes one SSE frame.
//
// The payload is JSON, and a JSON encoder never emits a bare newline, so a
// `data:` line cannot be broken by its content. This is why the payload is not
// allowed to be a pre-formatted string.
func writeSSE(w http.ResponseWriter, event string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// A JSON string never contains a raw newline, but guard anyway so a future
	// non-JSON payload cannot inject extra frames.
	if strings.ContainsAny(string(raw), "\r\n") {
		raw, _ = json.Marshal(strings.ReplaceAll(string(raw), "\n", " "))
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, raw); err != nil {
		return err
	}
	return nil
}

// PublishAlertCreated implements ingest.Publisher.
func (s *Server) PublishAlertCreated(a *alerts.Alert) {
	s.publishAlert(stream.EventAlertCreated, a)
}

// PublishIncident implements ingest.Publisher.
func (s *Server) PublishIncident(created bool, inc *incidents.Incident) {
	if created {
		s.publishIncident(stream.EventIncidentCreated, inc)
		// Webhooks fire on creation only, not on every merge: a merge is
		// routine correlation output, and notifying per merge would turn one
		// incident into an alert storm at the receiver.
		if s.notifier != nil {
			s.notifier.NotifyIncident(inc)
		}
		return
	}
	s.publishIncident(stream.EventIncidentUpdated, inc)
}

// publishAlert emits an alert event to permitted subscribers.
//
// The permission is attached here rather than at the call site so that every
// event's authorization requirement is decided in one place.
func (s *Server) publishAlert(evType stream.EventType, a *alerts.Alert) {
	if s.hub == nil || a == nil {
		return
	}
	s.hub.Publish(stream.Event{
		Type:       evType,
		Data:       map[string]any{"alert": stream.NewAlertView(a)},
		Permission: authorization.PermViewAlerts,
	})
}

// publishIncident emits an incident event.
func (s *Server) publishIncident(evType stream.EventType, inc *incidents.Incident) {
	if s.hub == nil || inc == nil {
		return
	}
	s.hub.Publish(stream.Event{
		Type:       evType,
		Data:       map[string]any{"incident": stream.NewIncidentView(inc)},
		Permission: authorization.PermViewIncidents,
	})
}

// publishAgent emits an agent status event.
func (s *Server) publishAgent(a *agents.Agent) {
	if s.hub == nil || a == nil {
		return
	}
	s.hub.Publish(stream.Event{
		Type:       stream.EventAgentStatus,
		Data:       map[string]any{"agent": stream.NewAgentView(a)},
		Permission: authorization.PermViewAgents,
	})
}

// PublishSessionRevoked tells the hub a session has ended.
//
// It is exported so that the logout and revocation paths cannot forget to do it:
// without it, a stream would stay open until its next revalidation.
func (s *Server) PublishSessionRevoked(sessionID string) {
	if s.hub == nil {
		return
	}
	s.hub.RevokeSession(sessionID)
}

// MetricsSnapshot returns the counters shown in the dashboard header.
//
// It is the payload of the periodic keepalive event. A quiet system and a broken
// connection look identical to a browser, so the stream sends a heartbeat that
// carries the platform's current state; that also gives the header live numbers
// without polling.
func (s *Server) MetricsSnapshot(ctx context.Context) map[string]any {
	snapshot := map[string]any{
		"generated_at": s.now(),
	}

	// The local name must not shadow the agents package, which is used below.
	if agentList, err := s.store.ListAgents(ctx); err == nil {
		online := 0
		for _, a := range agentList {
			if a.Status == agents.StatusOnline && !a.Revoked() {
				online++
			}
		}
		snapshot["agents_total"] = len(agentList)
		snapshot["agents_online"] = online
	}

	if bySeverity, err := s.store.CountAlertsBySeverity(ctx); err == nil {
		open := int64(0)
		if page, err := s.store.ListAlerts(ctx, storage.AlertQuery{Status: alerts.StatusOpen, Limit: 1}); err == nil {
			open = int64(len(page.Alerts))
		}
		snapshot["alerts_by_severity"] = map[string]int64{
			"low":      bySeverity[model.SeverityLow],
			"medium":   bySeverity[model.SeverityMedium],
			"high":     bySeverity[model.SeverityHigh],
			"critical": bySeverity[model.SeverityCritical],
		}
		_ = open
	}

	if incidents, err := s.store.ListOpenIncidents(ctx); err == nil {
		snapshot["open_incidents"] = len(incidents)
	}

	if events, err := s.store.CountEvents(ctx); err == nil {
		snapshot["events_total"] = events
	}

	if s.hub != nil {
		snapshot["stream_subscribers"] = s.hub.Count()
	}
	if s.detector != nil {
		snapshot["rules_loaded"] = s.detector.Rules().Len()
	}
	snapshot["ai_enabled"] = s.analyst.Enabled()

	return snapshot
}

// StreamSessionValidator returns the per-subscriber validity check used by the
// hub's periodic revalidation.
//
// It exists so that the main loop can ask the hub to enforce session validity
// without the hub needing to know about the store or the session model.
func (s *Server) StreamSessionValidator() func(*stream.Subscriber) bool {
	return func(sub *stream.Subscriber) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.sessionStillUsable(ctx, sub.ID, sub.UserID)
	}
}
