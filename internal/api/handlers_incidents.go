package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/storage"
)

// handleListIncidents returns a page of incidents.
func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewIncidents) {
		return
	}

	page, err := s.store.ListIncidents(r.Context(), s.pageSize(r), r.URL.Query().Get("cursor"))
	if err != nil {
		s.fail(w, err, "list incidents")
		return
	}
	page.Incidents = nonNil(page.Incidents)
	writeJSON(w, http.StatusOK, page)
}

// handleGetIncident returns one incident.
func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewIncidents) {
		return
	}
	inc, err := s.store.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "get incident")
		return
	}
	writeJSON(w, http.StatusOK, inc)
}

// handleUpdateIncidentStatus changes an incident's lifecycle state.
//
// The requested status is validated against the incident state machine, so a
// client cannot skip stages or reopen a closed incident.
func (s *Server) handleUpdateIncidentStatus(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermChangeIncidentStatus) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}

	var req statusRequest
	if err := s.decodeJSON(w, r, &req, 4<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	to := incidentStatus(req.Status)
	if !to.Valid() {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "unknown incident status")
		return
	}

	id := r.PathValue("id")
	current, err := s.store.GetIncident(r.Context(), id)
	if err != nil {
		s.fail(w, err, "get incident")
		return
	}
	if err := incidents.Transition(current.Status, to); err != nil {
		writeError(w, http.StatusConflict, CodeConflict, "incident status transition is not permitted")
		return
	}

	updated := *current
	updated.Status = to
	updated.UpdatedAt = s.now()
	if err := s.store.SaveIncident(r.Context(), &updated); err != nil {
		s.fail(w, err, "save incident")
		return
	}
	s.writeAudit(r, auditEntryForIncidentStatus(p, updated.ID, to))
	s.publishIncident(stream.EventIncidentUpdated, &updated)
	writeJSON(w, http.StatusOK, &updated)
}

// handleListAssets derives a bounded asset inventory from the agents and the
// events they have reported.
//
// The MVP has no dedicated asset table: an asset is an enrolled agent plus the
// host-level facts visible in its events. That keeps the inventory consistent
// with observed telemetry instead of inventing a second source of truth.
func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewAssets) {
		return
	}

	agentList, err := s.store.ListAgents(r.Context())
	if err != nil {
		s.fail(w, err, "list agents")
		return
	}

	type assetView struct {
		Host          string    `json:"host"`
		AgentID       string    `json:"agent_id,omitempty"`
		Status        string    `json:"status"`
		OS            string    `json:"os,omitempty"`
		AgentVersion  string    `json:"agent_version,omitempty"`
		LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
		EventCount    int       `json:"event_count"`
	}

	out := make([]assetView, 0, len(agentList))
	for _, a := range agentList {
		page, err := s.store.ListEvents(r.Context(), storageEventQueryForHost(a.Host, 1))
		if err != nil {
			s.fail(w, err, "list events for asset")
			return
		}
		v := assetView{
			Host:          a.Host,
			AgentID:       a.ID,
			Status:        string(a.Status),
			OS:            a.OS,
			AgentVersion:  a.Version,
			LastHeartbeat: a.LastHeartbeat,
		}
		if len(page.Events) > 0 {
			v.EventCount = 1
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets": out})
}

// handleSummary returns the dashboard overview counters.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermViewEvents) {
		return
	}

	bySeverity, err := s.store.CountAlertsBySeverity(r.Context())
	if err != nil {
		s.fail(w, err, "count alerts")
		return
	}
	events, err := s.store.CountEvents(r.Context())
	if err != nil {
		s.fail(w, err, "count events")
		return
	}
	agentList, err := s.store.ListAgents(r.Context())
	if err != nil {
		s.fail(w, err, "list agents")
		return
	}
	openIncidents, err := s.store.ListOpenIncidents(r.Context())
	if err != nil {
		s.fail(w, err, "list incidents")
		return
	}

	alertsBySeverity := map[string]int64{}
	for _, sev := range model.SeveritySet {
		alertsBySeverity[string(sev)] = bySeverity[sev]
	}

	online := 0
	for _, a := range agentList {
		if a.Status == agents.StatusOnline {
			online++
		}
	}

	var ruleCount int
	if s.detector != nil {
		ruleCount = s.detector.Rules().Len()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events_total":         events,
		"alerts_by_severity":   alertsBySeverity,
		"open_incidents":       len(openIncidents),
		"agents_total":         len(agentList),
		"agents_online":        online,
		"rules_loaded":         ruleCount,
		"detection_state_size": s.detectorStateSize(),
		"ai_enabled":           false,
	})
}

func (s *Server) detectorStateSize() int {
	if s.detector == nil {
		return 0
	}
	return s.detector.StateSize()
}

func storageEventQueryForHost(host string, limit int) storage.EventQuery {
	return storage.EventQuery{Host: strings.ToLower(strings.TrimSpace(host)), Limit: limit}
}
