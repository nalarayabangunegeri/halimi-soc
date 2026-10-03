package id

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

func TestNewEventIsWellFormed(t *testing.T) {
	got := NewEvent()
	if len(got) != len(Prefix)+encodedLen {
		t.Fatalf("length = %d, want %d", len(got), len(Prefix)+encodedLen)
	}
	if !Valid(got) {
		t.Fatalf("NewEvent() produced an invalid id: %q", got)
	}
}

func TestNewEventIsUnique(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		v := NewEvent()
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate id at iteration %d: %q", i, v)
		}
		seen[v] = struct{}{}
	}
}

func TestNewEventIsMonotonic(t *testing.T) {
	prev := NewEvent()
	for i := 0; i < 5000; i++ {
		cur := NewEvent()
		if bytes.Compare([]byte(prev), []byte(cur)) >= 0 {
			t.Fatalf("ids not strictly increasing: %q then %q", prev, cur)
		}
		prev = cur
	}
}

func TestTimestampRoundTrip(t *testing.T) {
	v := NewEvent()
	got := TimestampMS(v)
	if got <= 0 {
		t.Fatalf("TimestampMS(%q) = %d, want positive", v, got)
	}
	// The encoded timestamp must be ordered consistently with the id itself.
	ids := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		ids = append(ids, NewEvent())
	}
	ts := make([]int64, len(ids))
	for i, s := range ids {
		ts[i] = TimestampMS(s)
	}
	if !sort.SliceIsSorted(ts, func(i, j int) bool { return ts[i] < ts[j] }) {
		t.Fatal("encoded timestamps are not non-decreasing")
	}
}

func TestValidRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"missing prefix":   "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"wrong prefix":     "xyz_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"too short":        "evt_01ARZ3NDEKTSV4RRFFQ69G5FA",
		"too long":         "evt_01ARZ3NDEKTSV4RRFFQ69G5FAVX",
		"lowercase":        "evt_01arz3ndektsv4rrffq69g5fav",
		"ambiguous char I": "evt_01ARZ3NDEKTSV4RRFFQ69G5FAI",
		"ambiguous char L": "evt_01ARZ3NDEKTSV4RRFFQ69G5FAL",
		"ambiguous char O": "evt_01ARZ3NDEKTSV4RRFFQ69G5FAO",
		"ambiguous char U": "evt_01ARZ3NDEKTSV4RRFFQ69G5FAU",
		"symbol":           "evt_01ARZ3NDEKTSV4RRFFQ69G5F@V",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if Valid(in) {
				t.Fatalf("Valid(%q) = true, want false", in)
			}
		})
	}
}

func TestTimestampMSRejectsMalformed(t *testing.T) {
	if got := TimestampMS("not-an-id"); got != 0 {
		t.Fatalf("TimestampMS(invalid) = %d, want 0", got)
	}
}

func TestEncodeMatchesKnownVector(t *testing.T) {
	// ULID spec test vector: timestamp 1469918176385 with an all-zero random
	// component encodes to 01ARYZ6S41 followed by 16 zeros.
	var b [16]byte
	const ms uint64 = 1469918176385
	for i := 0; i < 6; i++ {
		b[i] = byte(ms >> (8 * (5 - i)))
	}

	got := encode(b)
	const want = "01ARYZ6S410000000000000000"
	if got != want {
		t.Fatalf("encode() = %q, want %q", got, want)
	}
}

func TestNewUsesTheKindPrefix(t *testing.T) {
	cases := map[Kind]string{
		KindEvent:    "evt_",
		KindAlert:    "alt_",
		KindIncident: "inc_",
		KindAgent:    "agt_",
		KindToken:    "tok_",
		KindUser:     "usr_",
		KindSession:  "sess_",
		KindAudit:    "aud_",
	}
	for kind, prefix := range cases {
		got := New(kind)
		if !strings.HasPrefix(got, prefix) {
			t.Errorf("New(%q) = %q, want the %q prefix", kind, got, prefix)
		}
		if len(got) != len(prefix)+encodedLen {
			t.Errorf("New(%q) length = %d, want %d", kind, len(got), len(prefix)+encodedLen)
		}
	}

	// Two calls for the same kind must still be unique.
	if New(KindAlert) == New(KindAlert) {
		t.Error("New(KindAlert) returned the same id twice")
	}
}
