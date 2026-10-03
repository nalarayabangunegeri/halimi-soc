// Package secret handles credential material.
//
// Every credential in HalimiSOC is compared in constant time and stored only as
// a hash. Plaintext secrets exist for exactly one round trip: the response that
// creates them.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// tokenBytes is the entropy of a generated opaque token. 32 bytes (256 bits)
// makes online brute force infeasible regardless of the comparison cost.
const tokenBytes = 32

// NewToken returns a new opaque token and its storage hash.
//
// The token is URL-safe base64 so it can be placed in a header or a cookie
// without escaping. The hash is a plain SHA-256 because the token is already
// full-entropy: a password-style KDF would add cost without adding security,
// whereas for low-entropy passwords it is essential (see password.go).
func NewToken(prefix string) (token string, hash string, err error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	token = prefix + base64.RawURLEncoding.EncodeToString(raw)
	return token, HashToken(token), nil
}

// HashToken returns the storage representation of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// EqualHash compares two hex-encoded hashes in constant time.
func EqualHash(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyToken reports whether the presented token matches the stored hash.
//
// The comparison is constant time so that a timing side channel cannot be used
// to recover a valid token byte by byte.
func VerifyToken(presented, storedHash string) bool {
	if presented == "" || storedHash == "" {
		return false
	}
	return EqualHash(HashToken(presented), storedHash)
}

// Prefix returns a short, non-secret fragment of a token for audit logs.
func Prefix(token string) string {
	const want = 8
	if len(token) <= want {
		return "…"
	}
	return token[:want] + "…"
}

// Redact replaces every occurrence of each known secret in s with a placeholder.
//
// This is the last line of defence before text reaches a log sink, an API
// response or an AI provider. It is applied to raw telemetry too, because a
// credential can appear inside a log line.
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if len(sec) < 8 {
			// Short values would match unrelated substrings and destroy the
			// evidence. Refuse rather than silently corrupt the record.
			continue
		}
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	return s
}

// redactionPatterns are shape-based redactions applied when the exact secret
// value is unknown, for example credentials belonging to a third party.
var redactionPatterns = []struct {
	marker string
	tail   int
}{
	{"password=", 0},
	{"passwd=", 0},
	{"pwd=", 0},
	{"token=", 0},
	{"secret=", 0},
	{"apikey=", 0},
	{"api_key=", 0},
}

// RedactPatterns masks values following common credential key names in
// key=value text.
func RedactPatterns(s string) string {
	lower := strings.ToLower(s)
	var out strings.Builder
	out.Grow(len(s))

	last := 0
	for _, p := range redactionPatterns {
		idx := 0
		for {
			i := strings.Index(lower[idx:], p.marker)
			if i < 0 {
				break
			}
			start := idx + i
			valStart := start + len(p.marker)
			if valStart <= last {
				idx = valStart
				continue
			}
			valEnd := valStart
			for valEnd < len(s) && !isValueTerminator(s[valEnd]) {
				valEnd++
			}
			out.WriteString(s[last:valStart])
			out.WriteString("[REDACTED]")
			last = valEnd
			idx = valEnd
		}
	}
	if last == 0 {
		return s
	}
	out.WriteString(s[last:])
	return out.String()
}

func isValueTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ',', ';', '&', '"', '\'':
		return true
	}
	return false
}

// RandomString returns a random URL-safe string of n bytes of entropy.
func RandomString(n int) string {
	if n <= 0 {
		n = 32
	}
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
