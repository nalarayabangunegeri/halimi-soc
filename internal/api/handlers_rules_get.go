package api

import (
	"net/http"
	"os"

	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/detection/rules"
)

// handleGetRule returns one rule file as YAML for the authoring UI.
//
// Reading raw rule text requires manage_rules, not just the listing
// permission: the listing exposes what is deployed, while the file body is
// the editable configuration. Keeping them separate means a read-only
// operator can see the posture without gaining the material needed to
// reconstruct and exfiltrate the detection logic verbatim.
func (s *Server) handleGetRule(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageRules) {
		return
	}
	if s.rulesPath == "" {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "rule source is not configured")
		return
	}

	id := r.PathValue("id")
	if !rules.ValidID(id) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid rule id")
		return
	}
	path, err := ruleFilePath(s.rulesPath, id)
	if err != nil {
		writeError(w, http.StatusNotFound, CodeNotFound, "rule not found")
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		s.log.Error("read rule file failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not read the rule")
		return
	}
	if len(raw) > 64<<10 {
		writeError(w, http.StatusInternalServerError, CodeInternal, "rule file exceeds the readable size")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "yaml": string(raw)})
}
