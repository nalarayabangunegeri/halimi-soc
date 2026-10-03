package api_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/id"
)

func TestRulesReloadPrivileged(t *testing.T) {
	h := newHarness(t)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// An admin reload against the real rule directory succeeds and reports
	// the loaded set, which now includes the HTTP spike rule.
	resp := h.do(http.MethodPost, "/api/v1/rules/reload", nil, headers)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("reload = %d, want 200", resp.StatusCode)
	}
	out := decode[struct {
		Rules  int    `json:"rules"`
		Status string `json:"status"`
	}](t, resp)
	if out.Rules < 7 {
		t.Errorf("reloaded rules = %d, want at least 7", out.Rules)
	}
	if out.Status != "reloaded" {
		t.Errorf("status = %q, want reloaded", out.Status)
	}

	// The detector still serves the set afterwards: the swap did not leave a
	// half-loaded detector behind.
	resp = h.do(http.MethodGet, "/api/v1/rules", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list rules after reload = %d, want 200", resp.StatusCode)
	}
	rules := decode[struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}](t, resp)
	found := false
	for _, r := range rules.Rules {
		if r.ID == "http-auth-failure-spike" {
			found = true
		}
	}
	if !found {
		t.Error("http-auth-failure-spike missing after reload")
	}
}

func TestRulesReloadAuthorization(t *testing.T) {
	h := newHarness(t)

	// Anonymous reload is rejected.
	resp := h.do(http.MethodPost, "/api/v1/rules/reload", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous reload = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// A non-admin operator cannot reload rules: rule control is admin-only.
	hash, err := auth.HashPassword("analyst-password-value")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "analyst",
		PasswordHash: hash,
		Role:         authorization.RoleAnalyst,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	csrf, _ := h.login("analyst", "analyst-password-value")
	resp = h.do(http.MethodPost, "/api/v1/rules/reload", nil, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("analyst reload = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// Without CSRF the state change is refused even for an admin.
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("admin login = %d", status)
	}
	resp = h.do(http.MethodPost, "/api/v1/rules/reload", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("reload without CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	// An agent credential is never an operator credential.
	h.enrollAgent()
	resp = h.do(http.MethodPost, "/api/v1/rules/reload", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		t.Errorf("agent reload = %d, want 401/403", resp.StatusCode)
	}
	resp.Body.Close()
}
