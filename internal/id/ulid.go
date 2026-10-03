// Package id generates HalimiSOC event identifiers.
//
// IDs are ULID-shaped: 48-bit millisecond timestamp followed by 80 bits of
// randomness, rendered as 26 Crockford base32 characters. This gives two
// properties the pipeline depends on:
//
//   - lexicographic order matches creation order, so the DB can sort by id as
//     a stable tie-breaker without a second column;
//   - the random tail makes IDs unguessable, so an untrusted client cannot
//     predict or collide with a future event id.
//
// Implemented with the standard library only: no dependency is justified for
// ~40 lines of bit packing.
package id

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"
)

const (
	// crockford is the Crockford base32 alphabet (no I, L, O, U).
	crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// encodedLen is the number of base32 characters in a ULID.
	encodedLen = 26
)

var (
	mu      sync.Mutex
	lastMS  uint64
	lastRnd [10]byte
)

// Kind is the object class an identifier belongs to. The prefix is part of the
// public contract: an id is self-describing, so a log line or an error message
// that contains one states what it refers to.
type Kind string

const (
	KindEvent    Kind = "evt_"
	KindAlert    Kind = "alt_"
	KindIncident Kind = "inc_"
	KindAgent    Kind = "agt_"
	KindToken    Kind = "tok_"
	KindUser     Kind = "usr_"
	KindSession  Kind = "sess_"
	KindAudit    Kind = "aud_"
)

// New returns a new time-ordered identifier for the given kind.
func New(kind Kind) string {
	return string(kind) + NewULID()
}

// NewEvent returns a new event identifier. It is the hot path, so it exists to
// keep call sites free of the kind constant.
func NewEvent() string {
	return New(KindEvent)
}

// NewULID returns a raw 26-character ULID string.
//
// Within the same millisecond, the random component is incremented so IDs stay
// strictly monotonic. Overflow past the 80-bit space rolls into the next
// millisecond rather than wrapping, preserving ordering.
func NewULID() string {
	now := uint64(time.Now().UTC().UnixMilli())

	mu.Lock()
	defer mu.Unlock()

	if now == lastMS {
		if !incr(lastRnd[:]) {
			// Random space exhausted within this millisecond; borrow the next.
			now++
			lastMS = now
			fillRandom(lastRnd[:])
		}
	} else {
		lastMS = now
		fillRandom(lastRnd[:])
	}

	var b [16]byte
	b[0] = byte(now >> 40)
	b[1] = byte(now >> 32)
	b[2] = byte(now >> 24)
	b[3] = byte(now >> 16)
	b[4] = byte(now >> 8)
	b[5] = byte(now)
	copy(b[6:], lastRnd[:])

	return encode(b)
}

// incr increments the big-endian 80-bit value in b. It returns false on
// overflow.
func incr(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

func fillRandom(b []byte) {
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the platform entropy source is broken.
		// Falling back to a time-derived value keeps the process alive without
		// silently producing predictable IDs across restarts.
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], uint64(time.Now().UnixNano()))
		for i := range b {
			b[i] = seed[i%8] ^ byte(i*31)
		}
	}
}

// encode renders 16 bytes as 26 Crockford base32 characters.
//
// 128 bits are packed into 26 five-bit groups (130 bits). The two spare bits
// are the leading zeros of the padded value, so group i covers padded bits
// [5i, 5i+5) which map back to input bits [5i-2, 5i+3).
func encode(b [16]byte) string {
	out := make([]byte, encodedLen)
	for i := 0; i < encodedLen; i++ {
		var v byte
		for k := 0; k < 5; k++ {
			q := 5*i + k - 2
			if q < 0 {
				continue // leading pad bit
			}
			bit := (b[q/8] >> (7 - uint(q%8))) & 1
			v = v<<1 | bit
		}
		out[i] = crockford[v]
	}
	return string(out)
}
