package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/auth"
	"github.com/halimi/halimisoc/internal/authorization"
	"github.com/halimi/halimisoc/internal/secret"
)

func TestHashPasswordProducesArgon2idPHC(t *testing.T) {
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("hash = %q, want an argon2id PHC string", hash)
	}
	// The parameters must be encoded so they can be raised later without
	// invalidating existing credentials.
	for _, want := range []string{"v=", "m=", "t=", "p="} {
		if !strings.Contains(hash, want) {
			t.Errorf("hash is missing parameter %q: %s", want, hash)
		}
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	a, err := auth.HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := auth.HashPassword("same-password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical; the salt is missing")
	}
}

func TestVerifyPassword(t *testing.T) {
	hash, err := auth.HashPassword("s3cret-passphrase")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := auth.VerifyPassword("s3cret-passphrase", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("correct password rejected")
	}

	ok, err = auth.VerifyPassword("wrong", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("wrong password accepted")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3$c2FsdA$aGFzaA",
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA",
	} {
		if _, err := auth.VerifyPassword("x", bad); err == nil {
			t.Errorf("VerifyPassword accepted malformed hash %q", bad)
		}
	}
}

func TestPasswordHashIsNotReversible(t *testing.T) {
	const password = "my-unique-password"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, password) {
		t.Fatal("plaintext password appears in the stored hash")
	}
}

func TestSessionLifecycle(t *testing.T) {
	now := time.Now().UTC()
	sess, token, err := auth.NewSession("usr_1", "203.0.113.9", "test-agent", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	if token == "" || sess.CSRFToken == "" {
		t.Fatal("session must carry a token and a CSRF token")
	}
	if sess.TokenHash == token {
		t.Fatal("the stored session value must be a hash, not the token itself")
	}
	if err := auth.AuthenticateSession(sess, token, now); err != nil {
		t.Fatalf("valid session rejected: %v", err)
	}

	// Wrong token.
	if err := auth.AuthenticateSession(sess, "sess_wrong", now); err == nil {
		t.Error("a wrong token was accepted")
	}

	// Expired.
	if err := auth.AuthenticateSession(sess, token, now.Add(2*time.Hour)); err == nil {
		t.Error("an expired session was accepted")
	}

	// Revoked.
	revoked := *sess
	ts := now
	revoked.RevokedAt = &ts
	if err := auth.AuthenticateSession(&revoked, token, now); err == nil {
		t.Error("a revoked session was accepted")
	}
}

func TestSessionIDIsDerivedFromToken(t *testing.T) {
	now := time.Now().UTC()
	sess, token, err := auth.NewSession("usr_1", "", "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if got := auth.SessionIDFromToken(token); got != sess.ID {
		t.Fatalf("derived id %q != session id %q", got, sess.ID)
	}
	if sess.ID == token {
		t.Fatal("session id must not be the plaintext token")
	}
}

func TestCSRFVerification(t *testing.T) {
	now := time.Now().UTC()
	sess, _, err := auth.NewSession("usr_1", "", "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	if err := auth.VerifyCSRF(sess, sess.CSRFToken); err != nil {
		t.Fatalf("valid CSRF token rejected: %v", err)
	}
	if err := auth.VerifyCSRF(sess, "wrong"); err == nil {
		t.Error("invalid CSRF token accepted")
	}
	if err := auth.VerifyCSRF(sess, ""); err == nil {
		t.Error("missing CSRF token must fail closed")
	}
	if err := auth.VerifyCSRF(nil, "x"); err == nil {
		t.Error("nil session must fail closed")
	}
}

func TestLimiterAllowsThenBacksOff(t *testing.T) {
	l := auth.NewLimiter(auth.DefaultLimiterOptions())
	now := time.Now().UTC()
	key := "acct:admin"

	for i := 0; i < 5; i++ {
		if wait := l.RetryAfter(key, now); wait != 0 {
			t.Fatalf("attempt %d blocked before the threshold: %v", i+1, wait)
		}
		l.Fail(key, now)
	}

	if wait := l.RetryAfter(key, now); wait == 0 {
		t.Fatal("expected backoff after exceeding the threshold")
	}

	// A successful attempt clears the counter.
	l.Succeed(key)
	if wait := l.RetryAfter(key, now); wait != 0 {
		t.Fatalf("limiter still backoff after success: %v", wait)
	}
}

func TestLimiterBackoffIsBoundedAndDecays(t *testing.T) {
	opts := auth.DefaultLimiterOptions()
	opts.MaxAttempts = 2
	opts.BaseDelay = time.Second
	opts.MaxDelay = 8 * time.Second
	opts.ResetAfter = time.Minute
	l := auth.NewLimiter(opts)

	now := time.Now().UTC()
	key := "acct:x"
	for i := 0; i < 20; i++ {
		l.Fail(key, now)
	}

	wait := l.RetryAfter(key, now)
	if wait > opts.MaxDelay {
		t.Fatalf("backoff %v exceeds the cap %v", wait, opts.MaxDelay)
	}

	// After the quiet period the limiter resets entirely, so a legitimate
	// operator is not locked out indefinitely.
	if wait := l.RetryAfter(key, now.Add(2*time.Minute)); wait != 0 {
		t.Fatalf("limiter did not reset after the quiet period: %v", wait)
	}
}

func TestLimiterDoesNotLockOutPermanently(t *testing.T) {
	// DESIGN.md explicitly warns against permanent lockout as the only control:
	// an attacker who can lock out an operator has produced a denial of service.
	opts := auth.DefaultLimiterOptions()
	opts.ResetAfter = 100 * time.Millisecond
	l := auth.NewLimiter(opts)

	now := time.Now().UTC()
	for i := 0; i < 50; i++ {
		l.Fail("acct:admin", now)
	}
	if wait := l.RetryAfter("acct:admin", now.Add(opts.ResetAfter+time.Second)); wait != 0 {
		t.Fatal("account remained blocked after the reset window")
	}
}

func TestLimiterBoundsItsTrackedKeys(t *testing.T) {
	opts := auth.DefaultLimiterOptions()
	opts.MaxEntries = 10
	l := auth.NewLimiter(opts)

	now := time.Now().UTC()
	for i := 0; i < 100; i++ {
		l.Fail(string(rune('a'+i%26))+string(rune('0'+i/26)), now)
	}
	if l.Size() > opts.MaxEntries {
		t.Fatalf("tracked keys = %d, want <= %d", l.Size(), opts.MaxEntries)
	}
}

func TestTokenGenerationAndVerification(t *testing.T) {
	token, hash, err := secret.NewToken("agt_")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, "agt_") {
		t.Fatalf("token = %q, want the agt_ prefix", token)
	}
	if !secret.VerifyToken(token, hash) {
		t.Fatal("generated token failed verification")
	}
	if secret.VerifyToken(token+"x", hash) {
		t.Fatal("a modified token verified")
	}
	if secret.VerifyToken("", hash) {
		t.Fatal("an empty token verified")
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		token, _, err := secret.NewToken("tok_")
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Fatal("duplicate token generated")
		}
		seen[token] = true
	}
}

func TestTokenPrefixDoesNotRevealTheToken(t *testing.T) {
	token := "agt_abcdefghijklmnopqrstuvwxyz012345"
	p := secret.Prefix(token)
	if strings.Contains(p, token) {
		t.Fatal("prefix must not contain the whole token")
	}
	if len(p) > 12 {
		t.Fatalf("prefix too long: %q", p)
	}
}

func TestRedactRemovesKnownSecrets(t *testing.T) {
	const apiKey = "sk-live-0123456789abcdefghij"
	line := "auth failed using token=" + apiKey + " for user root"

	got := secret.Redact(line, apiKey)
	if strings.Contains(got, apiKey) {
		t.Fatalf("secret survived redaction: %q", got)
	}

	// A value too short to match reliably is refused rather than corrupting
	// unrelated parts of the evidence.
	short := "abc"
	if out := secret.Redact("abcabcabc", short); out != "abcabcabc" {
		t.Fatalf("short value was redacted: %q", out)
	}
}

func TestRedactPatternsMasksKeyValueSecrets(t *testing.T) {
	line := "curl -H 'password=hunter2' https://example.test token=abcdef123456&x=1"
	got := secret.RedactPatterns(line)
	if strings.Contains(got, "hunter2") {
		t.Errorf("password survived pattern redaction: %q", got)
	}
	if strings.Contains(got, "abcdef123456") {
		t.Errorf("token survived pattern redaction: %q", got)
	}
}

func TestDummyHashIsUsableForTimingEqualisation(t *testing.T) {
	// The login path verifies against a dummy hash when the account does not
	// exist, so the hash must be a real Argon2id hash and must never match.
	hash, err := auth.HashPassword(secret.RandomString(32))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := auth.VerifyPassword("", hash)
	if err != nil {
		t.Fatalf("verification of a real hash failed: %v", err)
	}
	if ok {
		t.Fatal("an empty password matched the timing-equalisation hash")
	}
}

func TestRolePermissionsAreFailClosed(t *testing.T) {
	// Every declared permission must have a matrix entry; otherwise a newly
	// added permission would silently deny for everyone, which is safe but
	// should be caught during development.
	for _, perm := range authorization.PermissionSet {
		// An unknown role must never be granted a permission.
		if authorization.Allowed(authorization.Role("SUPERUSER"), perm) {
			t.Errorf("unknown role was granted %s", perm)
		}
	}

	if authorization.Allowed(authorization.RoleAdmin, authorization.Permission("not_a_permission")) {
		t.Error("an unknown permission was allowed")
	}
	if !authorization.Allowed(authorization.RoleAdmin, authorization.PermManageUsers) {
		t.Error("admin must be able to manage users")
	}
	if authorization.Allowed(authorization.RoleReadonly, authorization.PermChangeAlertStatus) {
		t.Error("readonly must not change alert status")
	}
	if authorization.Allowed(authorization.RoleAnalyst, authorization.PermManageRules) {
		t.Error("analyst must not manage detection rules")
	}
}

func TestHashPasswordEnforcesLengthBounds(t *testing.T) {
	if _, err := auth.HashPassword(""); err == nil {
		t.Error("empty password accepted")
	}
	if _, err := auth.HashPassword("short-11-ch"); err == nil {
		t.Error("11-char password accepted; minimum is 12")
	}
	if _, err := auth.HashPassword("twelve-chars"); err != nil {
		t.Errorf("12-char password rejected: %v", err)
	}
	long := string(make([]byte, auth.MaxPasswordLength+1))
	for i := range []byte(long) {
		long = long[:i] + "a" + long[i+1:]
	}
	if _, err := auth.HashPassword(long); err == nil {
		t.Error("overlong password hashed; must be rejected before Argon2id work")
	}
}

func TestVerifyPasswordFastRejectsOverlong(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	long := ""
	for i := 0; i < auth.MaxPasswordLength+1; i++ {
		long += "a"
	}
	ok, err := auth.VerifyPassword(long, hash)
	if err != nil {
		t.Fatalf("overlong verify returned an error (must be a cheap non-match): %v", err)
	}
	if ok {
		t.Fatal("overlong password verified")
	}
}

func TestNeedsRehashFlagsWeakAndCorrupt(t *testing.T) {
	hash, err := auth.HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatal(err)
	}
	if auth.NeedsRehash(hash) {
		t.Error("fresh hash flagged for rehash")
	}
	if !auth.NeedsRehash("not-a-hash") {
		t.Error("corrupt hash not flagged for rehash")
	}
}

func TestUserActiveAndSessionUsable(t *testing.T) {
	now := time.Now().UTC()
	u := &auth.User{Username: "admin"}
	if !u.Active() {
		t.Error("enabled user reported inactive")
	}
	u.Disabled = true
	if u.Active() {
		t.Error("disabled user reported active")
	}

	sess, _, err := auth.NewSession("usr_1", "", "", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !sess.Usable(now) {
		t.Error("fresh session not usable")
	}
	revoked := *sess
	ts := now
	revoked.RevokedAt = &ts
	if revoked.Usable(now) {
		t.Error("revoked session usable")
	}
	expired, _, err := auth.NewSession("usr_1", "", "", time.Hour, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if expired.Usable(now) {
		t.Error("expired session usable")
	}
}

func TestIdleExpiryBoundsStolenCookies(t *testing.T) {
	now := time.Now().UTC()
	sess, _, err := auth.NewSession("usr_1", "", "", 12*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	// Zero idle disables the check: absolute TTL decides alone.
	if sess.IdleExpired(now.Add(time.Hour), 0) {
		t.Error("zero idle must disable the check")
	}
	// Fresh activity is fine.
	if sess.IdleExpired(now.Add(time.Minute), 2*time.Hour) {
		t.Error("fresh session reported idle-expired")
	}
	// A session unused beyond the idle window is dead even with TTL left.
	stale, _, err := auth.NewSession("usr_1", "", "", 12*time.Hour, now.Add(-3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !stale.IdleExpired(now, 2*time.Hour) {
		t.Error("3h-idle session with 2h bound not expired")
	}
}

func TestLimiterPrunesExpiredEntries(t *testing.T) {
	opts := auth.DefaultLimiterOptions()
	opts.ResetAfter = 50 * time.Millisecond
	l := auth.NewLimiter(opts)
	now := time.Now().UTC()
	l.Fail("acct:prune", now)
	if l.Size() != 1 {
		t.Fatalf("size = %d, want 1", l.Size())
	}
	l.Prune(now.Add(2 * opts.ResetAfter))
	if l.Size() != 0 {
		t.Fatalf("size after prune = %d, want 0", l.Size())
	}
}

func TestNewSessionTruncatesLongUserAgent(t *testing.T) {
	long := ""
	for i := 0; i < 300; i++ {
		long += "a"
	}
	sess, _, err := auth.NewSession("usr_1", "", long, time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(sess.UserAgent) > 256 {
		t.Fatalf("user agent = %d bytes, want <= 256", len(sess.UserAgent))
	}
}
