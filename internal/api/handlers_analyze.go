package api

import (
	"fmt"
	"net/http"
	"sort"

	"github.com/halimi/halimisoc/internal/ai"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/incidents"
)

// analyzeResponse is the incident analysis payload.
//
// The shape is deliberately explicit about provenance. `analysis` is the
// narrative text, and every other field states what the analysis is grounded in
// and what it is not.
type analyzeResponse struct {
	IncidentID string            `json:"incident_id"`
	Analysis   string            `json:"analysis"`
	Mode       ai.Mode           `json:"mode"`
	Grounded   bool              `json:"grounded"`
	Evidence   []ai.EvidenceItem `json:"evidence"`
	Provider   string            `json:"provider,omitempty"`

	// Advisory is always true and exists so that no client can render this
	// output without the statement that it did not drive any decision.
	Advisory bool `json:"advisory"`
}

// handleAnalyzeIncident produces an advisory explanation of an incident.
//
// DESIGN.md §13 keeps AI outside the authoritative path, and ADR-004 records
// why. This endpoint therefore has three properties that are not negotiable:
//
//  1. It never runs unless the caller explicitly asks. Nothing in the ingestion
//     or detection path invokes it.
//  2. When no provider is configured it returns the deterministic, evidence-only
//     summary rather than an error, so the feature degrades instead of breaking.
//  3. The response states its mode and whether it was grounded in evidence, so a
//     reader can tell a model narrative from a computed one.
//
// It performs no state change, so it requires no CSRF token, and it grants no
// ability to modify the incident.
func (s *Server) handleAnalyzeIncident(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermRunAIAnalysis) {
		return
	}

	incidentID := r.PathValue("id")
	inc, err := s.store.GetIncident(r.Context(), incidentID)
	if err != nil {
		s.fail(w, err, "get incident")
		return
	}

	// Evidence is assembled from application-owned records only. Nothing from
	// the request body is ever part of the analysis input, which is what makes
	// prompt injection through this endpoint impossible by construction.
	evidence, err := s.collectEvidence(r, inc)
	if err != nil {
		s.fail(w, err, "collect evidence")
		return
	}

	result, err := s.analyst.Analyze(r.Context(), ai.Request{
		Incident: inc,
		Evidence: evidence,
	})
	if err != nil {
		// A provider failure is reported as a degraded analysis, not as a
		// server error: the incident and its evidence are still available, and
		// the operator should still get the deterministic summary.
		s.log.Warn("ai analysis failed", "incident", incidentID, "error", err)
		result = ai.Fallback(inc, evidence)
	}

	s.writeAudit(r, audit.Entry{
		Actor:      actorName(p),
		Action:     audit.ActionAIAnalysisRequested,
		Resource:   "incident",
		ResourceID: incidentID,
		Result:     audit.ResultSuccess,
		Detail:     "mode=" + string(result.Mode),
	})

	writeJSON(w, http.StatusOK, analyzeResponse{
		IncidentID: inc.ID,
		Analysis:   result.Analysis,
		Mode:       result.Mode,
		Grounded:   result.Grounded,
		Evidence:   evidence,
		Provider:   result.Provider,
		Advisory:   true,
	})
}

// maxEvidenceEvents bounds how many raw events are offered as context.
//
// The incident's own alert list is the primary evidence. Raw events are added
// only up to this bound, because the prompt is a cost and latency surface and an
// unbounded incident must not become an unbounded request.
const maxEvidenceEvents = 40

// collectEvidence gathers the application-owned records that support an incident.
//
// Every item is read from the store by identifier; nothing is taken from the
// request. That is the property that makes this endpoint immune to injection
// through the request body: the caller can only choose which incident to
// explain, never what the explanation is built from.
func (s *Server) collectEvidence(r *http.Request, inc *incidents.Incident) ([]ai.EvidenceItem, error) {
	var items []ai.EvidenceItem

	// The incident itself, as the framing record.
	items = append(items, ai.EvidenceItem{
		Kind:      ai.EvidenceIncident,
		ID:        inc.ID,
		Timestamp: inc.FirstSeen,
		Summary: fmt.Sprintf("%s (severity %s, status %s)",
			inc.Title, inc.Severity, inc.Status),
		Detail: fmt.Sprintf("%d alert(s), %d event(s), %d stage(s)",
			len(inc.AlertIDs), len(inc.EventIDs), len(inc.Stages)),
	})

	// Alerts, which carry the deterministic reason and the exact rule version.
	for _, alertID := range inc.AlertIDs {
		a, err := s.store.GetAlert(r.Context(), alertID)
		if err != nil {
			// A missing alert must not fail the analysis: the incident may
			// reference a record that was retained away. The gap is stated in
			// the evidence rather than hidden.
			items = append(items, ai.EvidenceItem{
				Kind:      ai.EvidenceAlert,
				ID:        alertID,
				Timestamp: inc.FirstSeen,
				Summary:   "alert record is no longer available",
			})
			continue
		}
		items = append(items, ai.EvidenceItem{
			Kind:      ai.EvidenceAlert,
			ID:        a.ID,
			Timestamp: a.CreatedAt,
			Summary: fmt.Sprintf("%s (severity %s, %d qualifying event(s))",
				a.RuleName, a.Severity, a.Count),
			Detail: fmt.Sprintf("rule %s@%d; %s", a.RuleID, a.RuleVersion, a.Reason),
		})
	}

	// Selected raw events, newest first, bounded.
	seen := map[string]bool{}
	var eventIDs []string
	for _, id := range inc.EventIDs {
		if !seen[id] {
			seen[id] = true
			eventIDs = append(eventIDs, id)
		}
	}
	sort.Strings(eventIDs)

	added := 0
	for i := len(eventIDs) - 1; i >= 0 && added < maxEvidenceEvents; i-- {
		e, err := s.store.GetEvent(r.Context(), eventIDs[i])
		if err != nil {
			continue
		}
		detail := ""
		if e.Raw != "" {
			// Raw evidence is untrusted and is what the prompt-injection tests
			// target. It is included because it is the highest-fidelity context,
			// and it is fenced and sanitised by the prompt builder.
			detail = e.Raw
		}
		items = append(items, ai.EvidenceItem{
			Kind:      ai.EvidenceEvent,
			ID:        e.ID,
			Timestamp: e.Time,
			Summary:   fmt.Sprintf("%s on %s", e.Type, e.Host),
			Detail:    detail,
		})
		added++
	}

	sort.SliceStable(items, func(i, j int) bool { return items[i].Timestamp.Before(items[j].Timestamp) })
	return items, nil
}
