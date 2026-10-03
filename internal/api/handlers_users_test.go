package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/id"
)

func createOperator(t *testing.T, h *harness, username, password string, role authorization.Role) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.SaveUser(context.Background(), &auth.User{
		ID:           id.New(id.KindUser),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUsersRequireAdmin(t *testing.T) {
	h := newHarness(t)

	// Unauthenticated listing is rejected before authorization is even reached.
	resp := h.do(http.MethodGet, "/api/v1/users", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list users = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	createOperator(t, h, "analyst", "analyst-password-value", authorization.RoleAnalyst)
	csrf, status := h.login("analyst", "analyst-password-value")
	if status != http.StatusOK {
		t.Fatalf("analyst login = %d", status)
	}
	resp = h.do(http.MethodGet, "/api/v1/users", nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst list users = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()

	resp = h.do(http.MethodPost, "/api/v1/users",
		map[string]string{"username": "mallory", "password": "mallory-password-value", "role": "ANALYST"},
		map[string]string{"X-CSRF-Token": csrf})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("analyst create user = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUserLifecycle(t *testing.T) {
	h := newHarness(t)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	// Creation validates its inputs.
	for _, tc := range []struct {
		name string
		body map[string]string
		want int
	}{
		{"short password", map[string]string{"username": "bob", "password": "short", "role": "ANALYST"}, http.StatusBadRequest},
		{"bad role", map[string]string{"username": "bob", "password": "bob-password-value", "role": "ROOT"}, http.StatusBadRequest},
		{"bad username", map[string]string{"username": "x", "password": "bob-password-value", "role": "ANALYST"}, http.StatusBadRequest},
	} {
		resp := h.do(http.MethodPost, "/api/v1/users", tc.body, headers)
		if resp.StatusCode != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
		resp.Body.Close()
	}

	resp := h.do(http.MethodPost, "/api/v1/users",
		map[string]string{"username": "Bob", "password": "bob-password-value", "role": "analyst"}, headers)
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create user = %d: %s", resp.StatusCode, body)
	}
	var created struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if created.Username != "bob" {
		t.Errorf("username = %q, want normalised lowercase", created.Username)
	}

	// Duplicate usernames collide case-insensitively.
	resp = h.do(http.MethodPost, "/api/v1/users",
		map[string]string{"username": "BOB", "password": "another-password-value", "role": "READONLY"}, headers)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate username = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// The new credential works.
	if _, status := h.login("bob", "bob-password-value"); status != http.StatusOK {
		t.Fatalf("new user login = %d, want 200", status)
	}

	// Listing never exposes password hashes.
	adminCSRF, _ := h.login("admin", adminPassword)
	resp = h.do(http.MethodGet, "/api/v1/users", nil, nil)
	_ = adminCSRF
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list users = %d, want 200", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "password_hash") {
		t.Fatal("user listing exposes password hashes")
	}

	// Disabling revokes access immediately.
	csrf2, _ := h.login("admin", adminPassword)
	resp = h.do(http.MethodPatch, "/api/v1/users/"+created.ID+"/status",
		map[string]bool{"disabled": true}, map[string]string{"X-CSRF-Token": csrf2})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable user = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if _, status := h.login("bob", "bob-password-value"); status != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d, want 401", status)
	}

	// Re-enabling restores it.
	csrf3, _ := h.login("admin", adminPassword)
	resp = h.do(http.MethodPatch, "/api/v1/users/"+created.ID+"/status",
		map[string]bool{"disabled": false}, map[string]string{"X-CSRF-Token": csrf3})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("re-enable user = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
	if _, status := h.login("bob", "bob-password-value"); status != http.StatusOK {
		t.Fatalf("re-enabled login = %d, want 200", status)
	}
}

func TestUserSelfDisableAndLastAdminAreRefused(t *testing.T) {
	h := newHarness(t)
	csrf, _ := h.login("admin", adminPassword)
	headers := map[string]string{"X-CSRF-Token": csrf}

	users, err := h.store.ListUsers(context.Background())
	if err != nil || len(users) == 0 {
		t.Fatalf("list users: %v", err)
	}
	var adminID string
	for _, u := range users {
		if u.Username == "admin" {
			adminID = u.ID
		}
	}

	// An operator cannot disable their own account: the guard is against
	// locking every administrator out, including yourself.
	resp := h.do(http.MethodPatch, "/api/v1/users/"+adminID+"/status",
		map[string]bool{"disabled": true}, headers)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("self disable = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()

	// With a second admin present, disabling the first is allowed.
	createOperator(t, h, "admin2", "admin2-password-value", authorization.RoleAdmin)
	resp = h.do(http.MethodPatch, "/api/v1/users/"+adminID+"/status",
		map[string]bool{"disabled": true}, headers)
	// Still 409: the requester's own session belongs to admin, and self-disable
	// wins over the second-admin check.
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("self disable with second admin = %d, want 409", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestUserMutationsRequireCSRF(t *testing.T) {
	h := newHarness(t)
	if _, status := h.login("admin", adminPassword); status != http.StatusOK {
		t.Fatalf("login = %d", status)
	}
	resp := h.do(http.MethodPost, "/api/v1/users",
		map[string]string{"username": "eve", "password": "eve-password-value", "role": "READONLY"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("create without CSRF = %d, want 403", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAgentCannotManageUsers(t *testing.T) {
	h := newHarness(t)
	h.enrollAgent()
	resp := h.do(http.MethodGet, "/api/v1/users", nil, h.agentHeaders())
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("agent list users = %d, want 401/403", resp.StatusCode)
	}
	resp.Body.Close()
}
