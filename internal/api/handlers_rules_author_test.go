package api_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/api"
	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/config"
	"github.com/halimi/halimisoc/internal/correlation"
	"github.com/halimi/halimisoc/internal/detection/engine"
	"github.com/halimi/halimisoc/internal/detection/rules"
	"github.com/halimi/halimisoc/internal/detection/state"
	"github.com/halimi/halimisoc/internal/events/ingest"
	"github.com/halimi/halimisoc/internal/events/stream"
	"github.com/halimi/halimisoc/internal/events/validation"
	"github.com/halimi/halimisoc/internal/id"
	"github.com/halimi/halimisoc/internal/metrics"
	memorystore "github.com/halimi/halimisoc/internal/storage/memory"
)

const authorRuleDoc = `id: test-authored-rule
version: 1
name: Test Authored Rule
description: Written through the authoring endpoint
severity: low
match:
  types:
    - auth.ssh.login_failed
threshold:
  count: 100
  window: 60s
group_by:
  - network.src_ip
cooldown: 5m
`

// newAuthorHarness mirrors newHarness but serves rules from a temp directory,
// so save/delete tests never touch the shipped rule files.
func newAuthorHarness(t *testing.T, rulesDir string) *harness {
	t.Helper()

	ruleSet, err := rules.LoadDir(rulesDir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	store := memorystore.New()
	reg := metrics.New()
	detector := engine.New(ruleSet, state.New(state.DefaultOptions()), store, reg)
	correlator := correlation.NewEngine(store, reg)

	opts := validation.DefaultOptions()
	ingester := ingest.New(store, detector, correlator, opts, reg, 100)

	hub := stream.NewHub(stream.Options{MaxSubscribers: 16, Buffer: 32})

	srv := api.New(api.Options{
		Store:        store,
		Hub:          hub,
		Ingester:     ingester,
		Detector:     detector,
		Limits:       config.DefaultLimits(),
		SessionTTL:   time.Hour,
		ClockSkew:    5 * time.Minute,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:      reg,
		EnrollSecret: enrollSecret,
		Version:      "test",
		RulesPath:    rulesDir,
	})

	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     "admin",
		PasswordHash: hash,
		Role:         authorization.RoleAdmin,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	ingester.SetPublisher(srv)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &harness{
		t:      t,
		server: ts,
		store:  store,
		hub:    hub,
		api:    srv,
		client: &http.Client{Jar: jar, Timeout: 10 * time.Second},
	}
}

// seedRulesDir copies the shipped rules into a temp dir for authoring tests.
func seedRulesDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("..", "..", "packages", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("..", "..", "packages", "rules", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRuleValidate(t *testing.T) {
	h := newAuthorHarness(t, seedRulesDir(t))
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// A valid document validates without needing the CSRF header: validation
	// changes no state.
	resp := h.do(http.MethodPost, "/api/v1/rules/validate", map[string]string{"yaml": authorRuleDoc}, nil)
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("validate = %d: %s", resp.StatusCode, body)
	}
	out := decode[struct {
		Valid bool `json:"valid"`
		Rule  struct {
			ID      string `json:"id"`
			Version int    `json:"version"`
		} `json:"rule"`
	}](t, resp)
	if !out.Valid || out.Rule.ID != "test-authored-rule" || out.Rule.Version != 1 {
		t.Errorf("validate response = %+v", out)
	}

	for _, tc := range []struct {
		name string
		doc  string
	}{
		{"empty", ""},
		{"bad severity", "id: x\nversion: 1\nname: X\nseverity: critical-ish\nmatch:\n  types: [auth.ssh.login_failed]\nthreshold:\n  count: 1\n  window: 60s\ngroup_by: [network.src_ip]\ncooldown: 5m\n"},
		{"unknown field", "id: x\nversion: 1\nname: X\nseverity: low\nmatch:\n  types: [auth.ssh.login_failed]\nthreshold:\n  count: 1\n  window: 60s\ngroup_by: [network.src_ip]\ncooldown: 5m\nexec: rm -rf /\n"},
		{"two documents", authorRuleDoc + "\n---\n" + authorRuleDoc},
	} {
		resp := h.do(http.MethodPost, "/api/v1/rules/validate", map[string]string{"yaml": tc.doc}, headers)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", tc.name, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Anonymous and non-admin callers are refused.
	resp = h.do(http.MethodPost, "/api/v1/rules/validate", map[string]string{"yaml": authorRuleDoc}, nil)
	resp.Body.Close()
}

func TestRuleSaveAndReloadFlow(t *testing.T) {
	dir := seedRulesDir(t)
	h := newAuthorHarness(t, dir)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// Save a new rule: 201 the first time.
	resp := h.do(http.MethodPut, "/api/v1/rules/test-authored-rule",
		map[string]string{"yaml": authorRuleDoc}, headers)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("save = %d: %s", resp.StatusCode, body)
	}
	resp.Body.Close()

	raw, err := os.ReadFile(filepath.Join(dir, "test-authored-rule.yaml"))
	if err != nil {
		t.Fatalf("saved file not on disk: %v", err)
	}
	if string(raw) != authorRuleDoc {
		t.Fatal("saved file content differs from the submitted document")
	}

	// Saving again replaces: 200, and the engine still runs the old set
	// until an explicit reload.
	resp = h.do(http.MethodPut, "/api/v1/rules/test-authored-rule",
		map[string]string{"yaml": authorRuleDoc}, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-save = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/rules/reload", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reload = %d", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodGet, "/api/v1/rules", nil, nil)
	listed := decode[struct {
		Rules []struct {
			ID string `json:"id"`
		} `json:"rules"`
	}](t, resp)
	found := false
	for _, r := range listed.Rules {
		if r.ID == "test-authored-rule" {
			found = true
		}
	}
	if !found {
		t.Error("saved rule missing after reload")
	}

	// An id mismatch between path and document is refused.
	resp = h.do(http.MethodPut, "/api/v1/rules/other-id",
		map[string]string{"yaml": authorRuleDoc}, headers)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("id mismatch = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Path traversal is refused by the id allowlist.
	resp = h.do(http.MethodPut, "/api/v1/rules/..%2F..%2Fevil",
		map[string]string{"yaml": authorRuleDoc}, headers)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		t.Errorf("traversal id accepted with %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuleDelete(t *testing.T) {
	dir := seedRulesDir(t)
	h := newAuthorHarness(t, dir)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	resp := h.do(http.MethodPut, "/api/v1/rules/test-authored-rule",
		map[string]string{"yaml": authorRuleDoc}, headers)
	resp.Body.Close()

	resp = h.do(http.MethodDelete, "/api/v1/rules/test-authored-rule", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	if _, err := os.Stat(filepath.Join(dir, "test-authored-rule.yaml")); !os.IsNotExist(err) {
		t.Fatal("rule file still on disk after delete")
	}

	resp = h.do(http.MethodDelete, "/api/v1/rules/test-authored-rule", nil, headers)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// The detector still runs the deleted rule until reload: removal and
	// activation are separate decisions.
	resp = h.do(http.MethodPost, "/api/v1/rules/reload", nil, headers)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reload after delete = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuleDeleteLastIsRefused(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "packages", "rules", "ssh-bruteforce.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ssh-bruteforce.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	h := newAuthorHarness(t, dir)
	csrf, _ := h.login("admin", adminPassword)

	resp := h.do(http.MethodDelete, "/api/v1/rules/ssh-bruteforce", nil, map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("delete last rule = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuleAuthoringAuthorization(t *testing.T) {
	h := newAuthorHarness(t, seedRulesDir(t))

	// Anonymous.
	resp := h.do(http.MethodPost, "/api/v1/rules/validate", map[string]string{"yaml": authorRuleDoc}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous validate = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Non-admin.
	createOperator(t, h, "analyst", "analyst-password-value", authorization.RoleAnalyst)
	csrf, _ := h.login("analyst", "analyst-password-value")
	headers := map[string]string{"X-CSRF-Token": csrf}
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/v1/rules/validate"},
		{http.MethodPut, "/api/v1/rules/x"},
		{http.MethodDelete, "/api/v1/rules/x"},
	} {
		resp := h.do(tc.method, tc.path, map[string]string{"yaml": authorRuleDoc}, headers)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("analyst %s %s = %d, want 403", tc.method, tc.path, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Admin without CSRF cannot mutate.
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatal("admin login failed")
	}
	resp = h.do(http.MethodPut, "/api/v1/rules/x", map[string]string{"yaml": authorRuleDoc}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("save without CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestRuleGetBody(t *testing.T) {
	dir := seedRulesDir(t)
	h := newAuthorHarness(t, dir)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	resp := h.do(http.MethodPut, "/api/v1/rules/test-authored-rule",
		map[string]string{"yaml": authorRuleDoc}, headers)
	resp.Body.Close()

	// The author reads the file body back for editing.
	resp = h.do(http.MethodGet, "/api/v1/rules/test-authored-rule", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get rule = %d, want 200", resp.StatusCode)
	}
	got := decode[struct {
		ID   string `json:"id"`
		YAML string `json:"yaml"`
	}](t, resp)
	if got.ID != "test-authored-rule" || got.YAML != authorRuleDoc {
		t.Error("rule body round-trip mismatch")
	}

	// Unknown ids 404 rather than leaking directory state.
	resp = h.do(http.MethodGet, "/api/v1/rules/no-such-rule", nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing rule = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()

	// A read-only operator cannot read rule bodies, though the listing stays
	// visible to them.
	createOperator(t, h, "viewer", "viewer-password-value", authorization.RoleReadonly)
	if _, status := h.login("viewer", "viewer-password-value"); status != http.StatusOK {
		t.Fatal("viewer login failed")
	}
	resp = h.do(http.MethodGet, "/api/v1/rules/test-authored-rule", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer get rule = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}
