package api

import (
	"net/http"
	"time"
)

// healthResponse is the liveness payload.
type healthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	UptimeSec int64     `json:"uptime_seconds"`
	Time      time.Time `json:"time"`
}

// handleHealth reports process liveness.
//
// Liveness deliberately does not touch the database: a database outage should
// not cause an orchestrator to kill an otherwise healthy process, because
// restarting it would not fix the outage and would only lose detection state.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	writeJSON(w, http.StatusOK, healthResponse{
		Status:    "ok",
		Version:   s.appVersion,
		UptimeSec: int64(now.Sub(s.startedAt).Seconds()),
		Time:      now,
	})
}

// readyResponse is the readiness payload.
type readyResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
	Rules    int    `json:"rules_loaded"`
	Details  string `json:"details,omitempty"`
}

// handleReady reports whether the server can serve requests.
//
// Unlike liveness, readiness does check the database and reports the rule count,
// because serving ingestion with zero loaded rules would silently stop detecting
// anything while still accepting telemetry.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	resp := readyResponse{Status: "ok", Database: "ok"}
	status := http.StatusOK

	if err := s.store.Ping(r.Context()); err != nil {
		resp.Status = "degraded"
		resp.Database = "unavailable"
		resp.Details = "database ping failed"
		status = http.StatusServiceUnavailable
	}

	if s.detector != nil {
		resp.Rules = s.detector.Rules().Len()
		if resp.Rules == 0 {
			resp.Status = "degraded"
			resp.Details = "no detection rules loaded"
			status = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, status, resp)
}

// handleMetrics renders the Prometheus exposition format.
//
// The endpoint is intentionally unauthenticated: it exposes counters and gauges
// only, never event content or credentials. In a real deployment it is bound to
// an internal interface or protected by the reverse proxy; that is documented in
// docs/security rather than assumed.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := s.reg.WritePrometheus(w); err != nil {
		s.log.Warn("write metrics failed", "error", err)
	}
}
