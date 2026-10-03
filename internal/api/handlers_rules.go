package api

import (
	"net/http"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/detection/rules"
)

// handleReloadRules replaces the active rule set from disk.
//
// Reload is transactional: the files are parsed and validated first, and the
// detector swaps to the new set only when the whole set is valid. An invalid
// file leaves the previous known-good set active and returns an error, so a
// typo can never silently stop detection. Detection state is kept across the
// swap; it is keyed by rule id and version, so unchanged rules keep their
// windows while removed rules age out under their bounds.
func (s *Server) handleReloadRules(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageRules) {
		return
	}
	if !s.requireCSRF(w, r, p) {
		return
	}
	if s.detector == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "detection is unavailable")
		return
	}
	if s.rulesPath == "" {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "rule source is not configured")
		return
	}

	set, err := rules.LoadDir(s.rulesPath)
	if err != nil {
		s.writeAudit(r, audit.Entry{
			Actor:    audit.ActorRef(audit.ActorUser, p.User.Username),
			Action:   audit.ActionRuleLoadFailed,
			Resource: "rules",
			Result:   audit.ResultFailure,
			Detail:   "rule reload rejected: invalid rule set",
		})
		writeError(w, http.StatusInternalServerError, CodeInternal, "rule set is invalid; previous rules remain active")
		return
	}

	s.detector.Reload(set)
	s.writeAudit(r, audit.Entry{
		Actor:    audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:   audit.ActionRuleLoaded,
		Resource: "rules",
		Result:   audit.ResultSuccess,
		Detail:   "rule set reloaded",
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":  len(set.Rules()),
		"status": "reloaded",
	})
}
