package id

import "strings"

// Prefix is the canonical prefix for event identifiers.
const Prefix = "evt_"

// Valid reports whether s is a well-formed HalimiSOC event identifier.
//
// Validation is strict and case-sensitive. Crockford base32 excludes I, L, O
// and U precisely so that a human copying an ID from a log cannot confuse it
// with 1, 1, 0 and V. Accepting lowercase would discard that property.
func Valid(s string) bool {
	if !strings.HasPrefix(s, Prefix) {
		return false
	}
	body := s[len(Prefix):]
	if len(body) != encodedLen {
		return false
	}
	for i := 0; i < len(body); i++ {
		if !strings.ContainsRune(crockford, rune(body[i])) {
			return false
		}
	}
	return true
}

// TimestampMS extracts the millisecond timestamp encoded in a valid ULID.
// It returns 0 for a malformed identifier.
func TimestampMS(s string) int64 {
	if !Valid(s) {
		return 0
	}
	body := s[len(Prefix):]
	var ms int64
	for i := 0; i < 10; i++ {
		idx := strings.IndexByte(crockford, body[i])
		if idx < 0 {
			return 0
		}
		ms = ms<<5 | int64(idx)
	}
	return ms
}
