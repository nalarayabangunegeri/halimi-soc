package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/detection/rules"
)

// ruleDocRequest carries one YAML rule document for validation or saving.
type ruleDocRequest struct {
	YAML string `json:"yaml"`
}

type ruleDocView struct {
	ID       string `json:"id"`
	Version  int    `json:"version"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// handleValidateRule checks one YAML document without changing anything.
//
// It requires authentication and the manage_rules permission but no CSRF
// token: validation changes no state, so there is nothing a cross-site
// request could mutate. The permission check matters more here — the
// validator reports exactly why a rule is rejected, which is information
// about the detection posture.
func (s *Server) handleValidateRule(w http.ResponseWriter, r *http.Request) {
	p := s.authenticate(w, r)
	if p == nil {
		return
	}
	if !s.requirePermission(w, r, p, authorization.PermManageRules) {
		return
	}

	var req ruleDocRequest
	if err := s.decodeJSON(w, r, &req, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	rule, err := parseSingleRule(req.YAML)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true,
		"rule": ruleDocView{
			ID:       rule.ID,
			Version:  rule.Version,
			Name:     rule.Name,
			Severity: string(rule.Severity),
		},
	})
}

// handleSaveRule creates or replaces the rule file for id.
//
// The document must contain exactly one rule whose id matches the path,
// otherwise a request could write a file whose name disagrees with its
// content. The write is atomic (temporary file plus rename) so a crash
// mid-save leaves either the old file or the new one, never a truncation.
// Saving does not reload: activation stays an explicit, audited step via
// POST /api/v1/rules/reload.
func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request) {
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
	if s.rulesPath == "" {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable, "rule source is not configured")
		return
	}

	id := r.PathValue("id")
	if !rules.ValidID(id) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid rule id")
		return
	}

	var req ruleDocRequest
	if err := s.decodeJSON(w, r, &req, 64<<10); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}
	rule, err := parseSingleRule(req.YAML)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, err.Error())
		return
	}
	if rule.ID != id {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "rule id does not match the path")
		return
	}

	path := filepath.Join(s.rulesPath, id+".yaml")
	existed := fileExists(path)
	if err := writeFileAtomic(path, req.YAML); err != nil {
		s.log.Error("write rule file failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not save the rule")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionRuleSaved,
		Resource:   "rule",
		ResourceID: rule.Key(),
		Result:     audit.ResultSuccess,
		Detail:     "rule file saved; reload to activate",
	})
	status := http.StatusOK
	if !existed {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{
		"rule": ruleDocView{
			ID:       rule.ID,
			Version:  rule.Version,
			Name:     rule.Name,
			Severity: string(rule.Severity),
		},
		"status": "saved",
	})
}

// handleDeleteRule removes a rule file.
//
// The detector keeps running the deleted rule until an explicit reload, which
// is deliberate: removal and activation are separate audited decisions, and a
// reload validates the whole remaining set before swapping. Deleting the last
// rule file is refused — detection with zero rules would silently stop
// detecting while still accepting telemetry.
func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
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
	if remaining, err := countRuleFiles(s.rulesPath); err != nil {
		s.log.Error("count rule files failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not delete the rule")
		return
	} else if remaining <= 1 {
		writeError(w, http.StatusConflict, CodeConflict, "cannot delete the last rule")
		return
	}

	if err := os.Remove(path); err != nil {
		s.log.Error("delete rule file failed", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal, "could not delete the rule")
		return
	}
	s.writeAudit(r, audit.Entry{
		Actor:      audit.ActorRef(audit.ActorUser, p.User.Username),
		Action:     audit.ActionRuleDeleted,
		Resource:   "rule",
		ResourceID: id,
		Result:     audit.ResultSuccess,
		Detail:     "rule file deleted; reload to activate",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// parseSingleRule validates that doc is exactly one rule.
func parseSingleRule(doc string) (*rules.Rule, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, errors.New("rule document is empty")
	}
	if len(doc) > 64<<10 {
		return nil, errors.New("rule document exceeds 64 KiB")
	}
	parsed, err := rules.ParseDocuments([]byte(doc))
	if err != nil {
		// The loader error already names the violation; prefix it so the
		// envelope stays stable while the detail stays useful.
		return nil, fmt.Errorf("invalid rule: %w", err)
	}
	if len(parsed) != 1 {
		return nil, fmt.Errorf("document must contain exactly one rule, found %d", len(parsed))
	}
	return parsed[0], nil
}

// ruleFilePath resolves the file holding id. Only the extensions the loader
// reads are considered, so the endpoint can never address an arbitrary file.
func ruleFilePath(dir, id string) (string, error) {
	for _, ext := range []string{".yaml", ".yml"} {
		path := filepath.Join(dir, id+ext)
		if fileExists(path) {
			return path, nil
		}
	}
	return "", fmt.Errorf("no rule file for %q", id)
}

// countRuleFiles counts loadable rule files in dir.
func countRuleFiles(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			n++
		}
	}
	return n, nil
}

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

// writeFileAtomic replaces path without ever exposing a truncation: the new
// content lands in a temporary file in the same directory and is renamed over
// the target, so a crash mid-write leaves the previous file intact.
func writeFileAtomic(path, content string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rule-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
