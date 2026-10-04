package api_test

import (
	"net/http"
	"net/http/cookiejar"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/mfa"
)

// Full MFA lifecycle: setup -> enable -> login with TOTP -> disable.
func TestMFALifecycle(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "dave", "dave-password-value123", "ANALYST")
	csrf, _ := h.login("dave", "dave-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}

	// Status starts disabled.
	st := decode[struct {
		Enabled bool `json:"enabled"`
	}](t, h.do(http.MethodGet, "/api/v1/auth/mfa/status", nil, nil))
	if st.Enabled {
		t.Fatal("mfa should start disabled")
	}

	// Setup returns a secret + otpauth url.
	setup := decode[struct {
		Secret     string `json:"secret"`
		OTPAUTHURL string `json:"otpauth_url"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup", nil, headers))
	if setup.Secret == "" || setup.OTPAUTHURL == "" {
		t.Fatalf("setup = %+v", setup)
	}

	// Enable with a wrong code fails closed.
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": "000000"}, headers)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enable wrong code = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Enable with the real code.
	code, err := mfa.CodeAt(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	enabled := decode[struct {
		BackupCodes []string `json:"backup_codes"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/enable",
		map[string]string{"code": code}, headers))
	if len(enabled.BackupCodes) != mfa.BackupCodeCount {
		t.Fatalf("backup codes = %d, want %d", len(enabled.BackupCodes), mfa.BackupCodeCount)
	}

	// Password-only login now returns MFA_REQUIRED.
	h.client.Jar = freshJar(t)
	if _, status := h.login("dave", "dave-password-value123"); status != http.StatusUnauthorized {
		t.Fatalf("password-only login after enable = %d, want 401", status)
	}

	// Login with TOTP succeeds.
	code2, err := mfa.CodeAt(setup.Secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, status := h.loginWithMFA("dave", "dave-password-value123", code2, ""); status != http.StatusOK {
		t.Fatalf("totp login = %d, want 200", status)
	}

	// Login with a backup code succeeds and consumes it.
	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("dave", "dave-password-value123", "", enabled.BackupCodes[0]); status != http.StatusOK {
		t.Fatalf("backup login = %d, want 200", status)
	}
	// Same backup code must not work twice.
	h.client.Jar = freshJar(t)
	if _, status := h.loginWithMFA("dave", "dave-password-value123", "", enabled.BackupCodes[0]); status == http.StatusOK {
		t.Fatal("reused backup code accepted")
	}
}

// Admin can reset a lost authenticator.
func TestMFAAdminReset(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "erin", "erin-password-value123", "ANALYST")
	csrf, _ := h.login("erin", "erin-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup", nil, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": code}, headers)
	resp.Body.Close()

	adminCSRF, _ := h.login("admin", adminPassword)
	erinID := userIDByName(t, h, "erin")
	resp = h.do(http.MethodPost, "/api/v1/users/"+erinID+"/mfa/reset", nil,
		map[string]string{"X-CSRF-Token": adminCSRF})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin reset = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()

	// Password-only login works again after reset.
	h.client.Jar = freshJar(t)
	if _, status := h.login("erin", "erin-password-value123"); status != http.StatusOK {
		t.Fatalf("login after reset = %d, want 200", status)
	}
}

// TOTP guessing is throttled.
func TestMFALoginIsRateLimited(t *testing.T) {
	h := newHarness(t)
	createOperator(t, h, "frank", "frank-password-value123", "ANALYST")
	csrf, _ := h.login("frank", "frank-password-value123")
	headers := map[string]string{"X-CSRF-Token": csrf}
	setup := decode[struct {
		Secret string `json:"secret"`
	}](t, h.do(http.MethodPost, "/api/v1/auth/mfa/setup", nil, headers))
	code, _ := mfa.CodeAt(setup.Secret, time.Now().UTC())
	resp := h.do(http.MethodPost, "/api/v1/auth/mfa/enable", map[string]string{"code": code}, headers)
	resp.Body.Close()

	var last int
	for i := 0; i < 15; i++ {
		h.client.Jar = freshJar(t)
		_, last = h.loginWithMFA("frank", "frank-password-value123", "000000", "")
		if last == http.StatusTooManyRequests {
			return
		}
	}
	t.Fatalf("mfa guessing never throttled, last = %d", last)
}

func freshJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

func (h *harness) loginWithMFA(username, password, totp, backup string) (string, int) {
	h.t.Helper()
	resp := h.do(http.MethodPost, "/api/v1/auth/login", map[string]string{
		"username": username, "password": password,
		"totp_code": totp, "backup_code": backup,
	}, nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return "", resp.StatusCode
	}
	out := decode[struct {
		CSRFToken string `json:"csrf_token"`
	}](h.t, resp)
	return out.CSRFToken, resp.StatusCode
}

func userIDByName(t *testing.T, h *harness, username string) string {
	t.Helper()
	resp := h.do(http.MethodGet, "/api/v1/users", nil, nil)
	list := decode[struct {
		Users []struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"users"`
	}](t, resp)
	for _, u := range list.Users {
		if u.Username == username {
			return u.ID
		}
	}
	t.Fatalf("user %q not found", username)
	return ""
}
