// Package validate enforces the untrusted-input boundary defined in DESIGN.md.
//
// Every field that originates from telemetry is normalized here before any
// security-sensitive logic may read it. The package deliberately never
// "repairs" a value silently: it either normalizes with a documented rule or
// rejects the event, because a silent repair changes what detection is looking
// at.
package validation

import (
	"errors"
	"fmt"
	"net/netip"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/halimi/halimisoc/internal/events/model"
)

// Errors returned by Normalize. Callers use errors.Is to distinguish a
// per-event drop (continue the batch) from a request-level failure.
var (
	// ErrMalformed means the event cannot be trusted even after normalization.
	ErrMalformed = errors.New("malformed event")

	// ErrUnsupportedSchema means the event uses an unknown contract version.
	ErrUnsupportedSchema = errors.New("unsupported schema version")

	// ErrClockSkew means the event timestamp is outside the accepted window.
	ErrClockSkew = errors.New("event time outside accepted clock skew")

	// ErrTooLarge means a field exceeded the configured byte limit.
	ErrTooLarge = errors.New("event field exceeds limit")
)

// Options controls normalization bounds.
type Options struct {
	// FieldBytes is the maximum byte length of a single string field.
	FieldBytes int

	// RawBytes is the maximum byte length of the retained raw line.
	RawBytes int

	// ClockSkew is the accepted absolute difference between the event time and
	// the server receive time.
	ClockSkew time.Duration

	// Now is injectable for deterministic tests. Defaults to time.Now.
	Now func() time.Time
}

// DefaultOptions returns conservative defaults matching config.DefaultLimits.
func DefaultOptions() Options {
	return Options{
		FieldBytes: 4 << 10,
		RawBytes:   8 << 10,
		ClockSkew:  5 * time.Minute,
		Now:        time.Now,
	}
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now().UTC()
	}
	return o.Now().UTC()
}

// Normalize validates and canonicalizes an event in place.
//
// It is the single gate between untrusted telemetry and the trusted pipeline.
// On success the returned event is safe to persist, detect on and expose.
func Normalize(e *model.Event, opts Options) error {
	if opts.FieldBytes <= 0 {
		opts.FieldBytes = DefaultOptions().FieldBytes
	}
	if opts.RawBytes <= 0 {
		opts.RawBytes = DefaultOptions().RawBytes
	}
	if opts.ClockSkew <= 0 {
		opts.ClockSkew = DefaultOptions().ClockSkew
	}

	if e == nil {
		return fmt.Errorf("%w: nil event", ErrMalformed)
	}

	// --- Contract version -------------------------------------------------

	if e.SchemaVersion == "" {
		e.SchemaVersion = model.SchemaVersion
	}
	if !model.IsSchemaVersionSupported(e.SchemaVersion) {
		return fmt.Errorf("%w: %q", ErrUnsupportedSchema, e.SchemaVersion)
	}

	// --- Required enums ---------------------------------------------------

	if !e.Type.Valid() {
		return fmt.Errorf("%w: unknown event type %q", ErrMalformed, e.Type)
	}
	if !e.Source.Valid() {
		return fmt.Errorf("%w: unknown source %q", ErrMalformed, e.Source)
	}
	if e.Outcome != "" && !e.Outcome.Valid() {
		return fmt.Errorf("%w: unknown outcome %q", ErrMalformed, e.Outcome)
	}
	sev, err := model.ParseSeverity(string(e.Severity))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	e.Severity = sev

	// --- Time -------------------------------------------------------------

	now := opts.now()
	if e.Time.IsZero() {
		return fmt.Errorf("%w: event time is required", ErrMalformed)
	}
	e.Time = e.Time.UTC()
	if e.ObservedAt.IsZero() {
		e.ObservedAt = e.Time
	}
	e.ObservedAt = e.ObservedAt.UTC()
	e.ReceivedAt = now

	// Reject timestamps too far in the future: a forged timestamp would let an
	// attacker place events outside a sliding detection window, either to evade
	// a threshold or to burst-trigger one.
	if e.Time.After(now.Add(opts.ClockSkew)) {
		return fmt.Errorf("%w: event time %s is %s ahead of server time",
			ErrClockSkew, e.Time.Format(time.RFC3339), e.Time.Sub(now))
	}

	// --- String fields ----------------------------------------------------

	var err2 error
	e.Host, err2 = CanonicalHost(e.Host, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("host: %w", err2)
	}
	if e.Host == "" {
		return fmt.Errorf("%w: host is required", ErrMalformed)
	}

	e.Actor, err2 = Identity(e.Actor, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("actor: %w", err2)
	}
	e.Target, err2 = Identity(e.Target, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("target: %w", err2)
	}
	e.AgentID, err2 = safeToken(e.AgentID, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("agent_id: %w", err2)
	}
	e.Message, err2 = Printable(e.Message, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("message: %w", err2)
	}
	e.SourcePath, err2 = safePath(e.SourcePath, opts.FieldBytes)
	if err2 != nil {
		return fmt.Errorf("source_path: %w", err2)
	}

	// --- Network ----------------------------------------------------------

	if e.Network.SourceIP, err2 = CanonicalIP(e.Network.SourceIP); err2 != nil {
		return fmt.Errorf("network.source_ip: %w", err2)
	}
	if e.Network.DestIP, err2 = CanonicalIP(e.Network.DestIP); err2 != nil {
		return fmt.Errorf("network.dest_ip: %w", err2)
	}
	if err2 = port("network.source_port", e.Network.SourcePort); err2 != nil {
		return err2
	}
	if err2 = port("network.dest_port", e.Network.DestPort); err2 != nil {
		return err2
	}
	e.Network.Protocol = strings.ToLower(strings.TrimSpace(e.Network.Protocol))
	if e.Network.Protocol != "" && !isAlnum(e.Network.Protocol, 16) {
		return fmt.Errorf("%w: network.protocol %q is not a known protocol token",
			ErrMalformed, e.Network.Protocol)
	}

	// --- Attributes -------------------------------------------------------

	if len(e.Attributes) > 64 {
		return fmt.Errorf("%w: too many attributes (%d)", ErrMalformed, len(e.Attributes))
	}
	if e.Attributes != nil {
		clean := make(map[string]string, len(e.Attributes))
		for k, v := range e.Attributes {
			key := strings.ToLower(strings.TrimSpace(k))
			if key == "" || !isAttrKey(key) {
				return fmt.Errorf("%w: invalid attribute key %q", ErrMalformed, k)
			}
			// Attribute values are untrusted and are forwarded to the AI
			// evidence packer, so they are stripped of control characters even
			// though they are not used in detection.
			cv, err := Printable(v, opts.FieldBytes)
			if err != nil {
				return fmt.Errorf("attribute %s: %w", key, err)
			}
			clean[key] = cv
		}
		e.Attributes = clean
	}

	// --- Raw evidence -----------------------------------------------------

	if e.Raw != "" {
		if len(e.Raw) > opts.RawBytes {
			// Truncate rather than reject: dropping the whole event because the
			// source line was long would blind detection. The truncation is
			// recorded so an analyst knows the evidence is partial.
			e.Raw = truncateBytes(e.Raw, opts.RawBytes)
			if e.Attributes == nil {
				e.Attributes = map[string]string{}
			}
			e.Attributes["raw_truncated"] = "true"
		}
		e.Raw = stripControl(e.Raw, true)
	}

	return nil
}

// CanonicalHost normalizes a host identifier.
//
// Rule: trim, lowercase, strip a trailing dot, and restrict to the character
// set legal in a DNS label or IPv4 literal. Anything else is rejected so that
// two spellings of one host ("Web-01." vs "web-01") cannot split correlation.
func CanonicalHost(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	s = strings.ToLower(s)
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		return "", ErrTooLarge
	}
	if utf8.RuneCountInString(s) != len(s) {
		return "", fmt.Errorf("%w: host contains non-ASCII characters", ErrMalformed)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_':
		default:
			return "", fmt.Errorf("%w: host contains illegal character %q", ErrMalformed, c)
		}
	}
	if strings.HasPrefix(s, "-") || strings.Contains(s, "..") {
		return "", fmt.Errorf("%w: host has an invalid label structure", ErrMalformed)
	}
	return s, nil
}

// Identity normalizes a user or key identity.
//
// Identities are compared for correlation, so the canonical form is lowercased.
// Control characters are rejected outright because an identity containing them
// can be used for log injection or to forge an unrelated identity.
func Identity(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		return "", ErrTooLarge
	}
	if strings.ContainsAny(s, "\x00\r\n\t") {
		return "", fmt.Errorf("%w: identity contains control characters", ErrMalformed)
	}
	return strings.ToLower(s), nil
}

// Printable removes control characters from free text and enforces a byte limit.
//
// Free text is frequently forwarded to an AI provider and to the UI, so it is
// stripped of control characters rather than merely validated.
func Printable(s string, max int) (string, error) {
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		return "", ErrTooLarge
	}
	return stripControl(strings.TrimSpace(s), false), nil
}

// CanonicalIP normalizes an IP address to its canonical textual form.
//
// An empty input is allowed (many events have no network peer), but a
// non-empty input that does not parse is rejected: a bogus peer address would
// silently join an unrelated correlation group.
func CanonicalIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a valid IP address", ErrMalformed, s)
	}
	// Reject zone identifiers: they are host-local and meaningless centrally.
	if addr.Zone() != "" {
		return "", fmt.Errorf("%w: scoped address %q is not accepted", ErrMalformed, s)
	}
	return addr.Unmap().String(), nil
}

func port(field string, p int) error {
	if p < 0 || p > 65535 {
		return fmt.Errorf("%w: %s %d out of range", ErrMalformed, field, p)
	}
	return nil
}

// stripControl removes control characters. When keepNewlines is true, newline
// and carriage return are preserved so a multi-line raw record stays readable.
func stripControl(s string, keepNewlines bool) string {
	if !strings.ContainsFunc(s, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == 0x7f {
			continue
		}
		if r < 0x20 {
			if keepNewlines && (r == '\n' || r == '\r') {
				b.WriteRune(r)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isAlnum(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '/' {
			return false
		}
	}
	return true
}

func isAttrKey(s string) bool {
	if len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.' || c == '-':
		default:
			return false
		}
	}
	return true
}

// safeToken accepts identifier-shaped values only.
func safeToken(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		return "", ErrTooLarge
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == ':':
		default:
			return "", fmt.Errorf("%w: token contains illegal character %q", ErrMalformed, c)
		}
	}
	return s, nil
}

// safePath strips directory traversal from a producer-supplied source path.
//
// The path is retained for evidence provenance, so it is reduced to a relative
// form rather than dropped. Cleaning is done against a rooted copy so that ".."
// segments can never climb above the root and escape into an unrelated path.
func safePath(s string, max int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > max {
		return "", ErrTooLarge
	}
	if strings.Contains(s, "\x00") {
		return "", fmt.Errorf("%w: path contains NUL", ErrMalformed)
	}
	s = strings.ReplaceAll(s, "\\", "/")
	s = path.Clean("/" + strings.TrimPrefix(s, "/"))
	return strings.TrimPrefix(s, "/"), nil
}

func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Cut on a rune boundary so the result stays valid UTF-8.
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
