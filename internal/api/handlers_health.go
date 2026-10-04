package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
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
// The endpoint exposes counters and gauges only, never event content or
// credentials. When MetricsToken is set it requires
// Authorization: Bearer <token> (constant-time); otherwise it stays
// unauthenticated and the reverse proxy must restrict it to the monitoring
// network, as documented in docs/security/configuration.md.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsToken != "" {
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		token := ""
		if strings.HasPrefix(header, prefix) {
			token = strings.TrimSpace(strings.TrimPrefix(header, prefix))
		}
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.metricsToken)) != 1 {
			writeError(w, http.StatusUnauthorized, CodeUnauthorized, "authentication required")
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := s.reg.WritePrometheus(w); err != nil {
		s.log.Warn("write metrics failed", "error", err)
	}
}
