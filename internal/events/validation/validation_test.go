package validation

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

func fixedNow() time.Time {
	return time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)
}

func opts() Options {
	o := DefaultOptions()
	o.Now = fixedNow
	return o
}

func validEvent() *model.Event {
	return &model.Event{
		ID:            "evt_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SchemaVersion: model.SchemaVersion,
		Type:          model.TypeSSHLoginFailed,
		Time:          fixedNow().Add(-time.Minute),
		Host:          "Web-01.",
		Source:        model.SourceAuthLog,
		Actor:         "ROOT",
		Outcome:       model.OutcomeFailure,
		Severity:      "medium",
		Network:       model.Network{SourceIP: "2001:0db8::1", SourcePort: 22},
		Attributes:    map[string]string{"Parser": "sshd"},
		Raw:           "raw line",
	}
}

func TestNormalizeAcceptsCanonicalEvent(t *testing.T) {
	e := validEvent()
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v, want nil", err)
	}
	if e.Host != "web-01" {
		t.Errorf("host = %q, want web-01 (lowercased, trailing dot stripped)", e.Host)
	}
	if e.Actor != "root" {
		t.Errorf("actor = %q, want root", e.Actor)
	}
	if e.Time.Location() != time.UTC || e.ObservedAt.Location() != time.UTC {
		t.Error("timestamps must be normalized to UTC")
	}
	if !e.ReceivedAt.Equal(fixedNow()) {
		t.Errorf("received_at = %s, want %s", e.ReceivedAt, fixedNow())
	}
	if e.Network.SourceIP != "2001:db8::1" {
		t.Errorf("source_ip = %q, want canonical compression", e.Network.SourceIP)
	}
	if _, ok := e.Attributes["parser"]; !ok {
		t.Error("attribute keys must be lowercased")
	}
}

func TestNormalizeRejectsUnknownSchemaVersion(t *testing.T) {
	e := validEvent()
	e.SchemaVersion = "99"
	err := Normalize(e, opts())
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("err = %v, want ErrUnsupportedSchema", err)
	}
}

func TestNormalizeDefaultsMissingSchemaVersion(t *testing.T) {
	e := validEvent()
	e.SchemaVersion = ""
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if e.SchemaVersion != model.SchemaVersion {
		t.Errorf("schema_version = %q, want %q", e.SchemaVersion, model.SchemaVersion)
	}
}

func TestNormalizeRejectsUnknownEnums(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.Event)
	}{
		{"unknown type", func(e *model.Event) { e.Type = "auth.ssh.explode" }},
		{"unknown source", func(e *model.Event) { e.Source = "journald" }},
		{"unknown outcome", func(e *model.Event) { e.Outcome = "maybe" }},
		{"uppercase severity", func(e *model.Event) { e.Severity = "HIGH" }},
		{"unknown severity", func(e *model.Event) { e.Severity = "important" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			tc.mutate(e)
			if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestNormalizeRejectsMissingRequiredFields(t *testing.T) {
	e := validEvent()
	e.Host = ""
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for missing host", err)
	}

	e = validEvent()
	e.Time = time.Time{}
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for missing time", err)
	}
}

func TestNormalizeRejectsFutureTimestampBeyondSkew(t *testing.T) {
	e := validEvent()
	e.Time = fixedNow().Add(10 * time.Minute)
	err := Normalize(e, opts())
	if !errors.Is(err, ErrClockSkew) {
		t.Fatalf("err = %v, want ErrClockSkew", err)
	}
}

func TestNormalizeAcceptsTimestampWithinSkew(t *testing.T) {
	e := validEvent()
	e.Time = fixedNow().Add(4 * time.Minute)
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v, want nil within skew", err)
	}
}

func TestNormalizeAcceptsOldTimestamp(t *testing.T) {
	// Backfill from a rotated log is legitimate; only future times are bounded.
	e := validEvent()
	e.Time = fixedNow().AddDate(0, 0, -30)
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v, want nil for backfill", err)
	}
}

func TestNormalizeRejectsInvalidIP(t *testing.T) {
	e := validEvent()
	e.Network.SourceIP = "999.999.999.999"
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestNormalizeRejectsScopedIPv6(t *testing.T) {
	e := validEvent()
	e.Network.SourceIP = "fe80::1%eth0"
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for scoped address", err)
	}
}

func TestNormalizeRejectsInvalidPorts(t *testing.T) {
	e := validEvent()
	e.Network.SourcePort = 70000
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestNormalizeRejectsOversizedField(t *testing.T) {
	o := opts()
	o.FieldBytes = 32

	e := validEvent()
	e.Message = strings.Repeat("x", 33)
	if err := Normalize(e, o); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestNormalizeStripsControlCharactersFromFreeText(t *testing.T) {
	e := validEvent()
	e.Message = "before\x00\x01\x7fafter"
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if strings.ContainsAny(e.Message, "\x00\x01\x7f") {
		t.Errorf("message still contains control characters: %q", e.Message)
	}
}

func TestNormalizeRejectsControlCharactersInIdentity(t *testing.T) {
	e := validEvent()
	e.Actor = "root\ninjected"
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for log injection attempt", err)
	}
}

func TestNormalizeRejectsIllegalHostCharacters(t *testing.T) {
	for _, host := range []string{"web 01", "web;01", "web/01", "$(whoami)", "web|01"} {
		e := validEvent()
		e.Host = host
		if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
			t.Errorf("host %q: err = %v, want ErrMalformed", host, err)
		}
	}
}

func TestNormalizeSanitizesSourcePath(t *testing.T) {
	e := validEvent()
	e.SourcePath = "/var/log/../../etc/../../../shadow"
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if strings.Contains(e.SourcePath, "..") || strings.HasPrefix(e.SourcePath, "/") {
		t.Errorf("source_path not sanitized: %q", e.SourcePath)
	}
}

func TestNormalizeRejectsInvalidAttributeKey(t *testing.T) {
	e := validEvent()
	e.Attributes = map[string]string{"Bad Key!": "v"}
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestNormalizeBoundsAttributeCount(t *testing.T) {
	e := validEvent()
	e.Attributes = map[string]string{}
	for i := 0; i < 65; i++ {
		e.Attributes["k"+strings.Repeat("a", i%5)+string(rune('a'+i%26))+string(rune('0'+i/26))] = "v"
	}
	if len(e.Attributes) <= 64 {
		t.Skip("generated fewer than 65 distinct keys")
	}
	if err := Normalize(e, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed for too many attributes", err)
	}
}

func TestNormalizeTruncatesRawAndMarksEvidence(t *testing.T) {
	o := opts()
	o.RawBytes = 16

	e := validEvent()
	e.Raw = strings.Repeat("A", 100)
	if err := Normalize(e, o); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if len(e.Raw) > 16 {
		t.Errorf("raw length = %d, want <= 16", len(e.Raw))
	}
	if e.Attributes["raw_truncated"] != "true" {
		t.Error("truncated raw evidence must be marked so partial evidence is not mistaken for complete")
	}
}

func TestNormalizeTruncatesOnRuneBoundary(t *testing.T) {
	o := opts()
	o.RawBytes = 5

	e := validEvent()
	e.Raw = "日本語テスト"
	if err := Normalize(e, o); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if !isValidUTF8(e.Raw) {
		t.Errorf("truncation produced invalid UTF-8: %q", e.Raw)
	}
}

func TestNormalizeRejectsNilEvent(t *testing.T) {
	if err := Normalize(nil, opts()); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestCanonicalIP(t *testing.T) {
	cases := map[string]string{
		"192.168.001.001":    "",
		"192.168.1.1":        "192.168.1.1",
		"::ffff:192.168.1.1": "192.168.1.1",
		"":                   "",
	}
	for in, want := range cases {
		got, err := CanonicalIP(in)
		if want == "" && in != "" {
			if err == nil {
				t.Errorf("CanonicalIP(%q) = %q, want error", in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("CanonicalIP(%q) = %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CanonicalIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEntityKeyPrecedence(t *testing.T) {
	// EntityKey reads the canonical fields, so the event must be normalized
	// first. Calling it on raw input would compare un-normalized identities.
	e := validEvent()
	if err := Normalize(e, opts()); err != nil {
		t.Fatalf("Normalize() = %v", err)
	}
	if got := e.EntityKey(); got != "user:root" {
		t.Errorf("EntityKey() = %q, want user:root", got)
	}

	e.Actor = ""
	if got := e.EntityKey(); got != "ip:2001:db8::1" {
		t.Errorf("EntityKey() = %q, want ip:2001:db8::1", got)
	}

	e.Network.SourceIP = ""
	e.Target = "alice"
	if got := e.EntityKey(); got != "target:alice" {
		t.Errorf("EntityKey() = %q, want target:alice", got)
	}

	e.Target = ""
	if got := e.EntityKey(); got != "" {
		t.Errorf("EntityKey() = %q, want empty", got)
	}
}

func TestDedupeKeyIgnoresServerAssignedFields(t *testing.T) {
	a := validEvent()
	b := validEvent()
	b.ID = "evt_01ARZ3NDEKTSV4RRFFQ69G5FAW"
	b.ReceivedAt = fixedNow().Add(time.Hour)
	if a.DedupeKey() != b.DedupeKey() {
		t.Error("dedupe key must not depend on server-assigned fields")
	}

	b.Raw = "different"
	if a.DedupeKey() == b.DedupeKey() {
		t.Error("dedupe key must distinguish different raw evidence")
	}
}

func TestSeverityOrdering(t *testing.T) {
	if model.MaxSeverity(model.SeverityMedium, model.SeverityCritical) != model.SeverityCritical {
		t.Error("MaxSeverity must fold to the higher rank")
	}
	if model.MaxSeverity(model.SeverityHigh, model.SeverityHigh) != model.SeverityHigh {
		t.Error("MaxSeverity must be idempotent")
	}
	ordered := []model.Severity{
		model.SeverityLow, model.SeverityMedium, model.SeverityHigh, model.SeverityCritical,
	}
	for i := 1; i < len(ordered); i++ {
		if model.SeverityRank(ordered[i]) <= model.SeverityRank(ordered[i-1]) {
			t.Fatalf("severity rank not strictly increasing at %s", ordered[i])
		}
	}
}

func TestParseSeverityIsCaseSensitive(t *testing.T) {
	if _, err := model.ParseSeverity("High"); err == nil {
		t.Fatal("ParseSeverity accepted non-canonical casing")
	}
	if _, err := model.ParseSeverity("high"); err != nil {
		t.Fatalf("ParseSeverity(high) = %v", err)
	}
}

func TestSchemaVersionSupport(t *testing.T) {
	if !model.IsSchemaVersionSupported("1") {
		t.Error("version 1 must be supported")
	}
	if model.IsSchemaVersionSupported("2") {
		t.Error("unimplemented version 2 must be rejected, never coerced")
	}
}

func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '\uFFFD' {
			return false
		}
	}
	return true
}

func TestNormalizeAcceptsNewSourceClasses(t *testing.T) {
	// Every source class a parser can emit must pass the validation boundary.
	// A parser whose output the validator rejects is telemetry that is
	// collected and then silently dropped.
	cases := []struct {
		name   string
		typ    model.EventType
		source model.Source
	}{
		{"http access failure", model.TypeHTTPAuthFailed, model.SourceHTTPAccess},
		{"container log ssh failure", model.TypeSSHLoginFailed, model.SourceContainerLog},
		{"firewall block", model.TypeFirewallBlock, model.SourceSyslog},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := validEvent()
			e.Type = tc.typ
			e.Source = tc.source
			if tc.typ == model.TypeFirewallBlock {
				e.Actor = ""
				e.Target = ""
				e.Outcome = model.OutcomeUnknown
				e.Network = model.Network{SourceIP: "203.0.113.7", DestIP: "10.0.0.5", DestPort: 22}
			}
			if err := Normalize(e, opts()); err != nil {
				t.Fatalf("Normalize() = %v, want nil", err)
			}
		})
	}
}
