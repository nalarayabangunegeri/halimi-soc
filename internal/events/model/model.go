// Package event defines the canonical HalimiSOC event contract.
//
// This package is the single source of truth for the event model shared by:
// the agent, the parsers, ingestion, detection, correlation and the API.
//
// Security note: every field here can originate from untrusted telemetry.
// Values are validated in this package before any security-sensitive logic
// (detection, correlation, authorization decisions) may consume them.
package model

import (
	"fmt"
	"strings"
	"time"
)

// SchemaVersion is the canonical event schema version emitted by this build.
//
// Compatibility policy (DESIGN.md): a consumer MUST reject an event whose
// schema_version is not in SupportedSchemaVersions. Unknown versions are never
// coerced, because silent coercion would let an untrusted payload change the
// meaning of trusted detection input.
const SchemaVersion = "1"

// SupportedSchemaVersions lists schema versions this build can ingest.
var SupportedSchemaVersions = []string{"1"}

// IsSchemaVersionSupported reports whether v is ingestible by this build.
func IsSchemaVersionSupported(v string) bool {
	for _, s := range SupportedSchemaVersions {
		if s == v {
			return true
		}
	}
	return false
}

// Severity is the canonical severity enum.
//
// Casing rule: lowercase on the wire and in storage. Any other casing is a
// validation error rather than a coercion target, so two systems built from
// the same spec cannot disagree about what "HIGH" means.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// SeverityRank orders severities for comparison and max() folding.
func SeverityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}

// MaxSeverity returns the higher-ranked of a and b.
func MaxSeverity(a, b Severity) Severity {
	if SeverityRank(a) >= SeverityRank(b) {
		return a
	}
	return b
}

// SeveritySet is the closed set of valid severities.
var SeveritySet = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// ParseSeverity validates a severity string strictly (case-sensitive lowercase).
func ParseSeverity(s string) (Severity, error) {
	for _, v := range SeveritySet {
		if string(v) == s {
			return v, nil
		}
	}
	return "", fmt.Errorf("unknown severity %q", s)
}

// Outcome is the canonical authentication/action outcome enum.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeUnknown Outcome = "unknown"
)

// Valid reports whether o is a canonical outcome.
func (o Outcome) Valid() bool {
	return o == OutcomeSuccess || o == OutcomeFailure || o == OutcomeUnknown
}

// EventType is the canonical event type identifier.
//
// Types are dotted, lowercase, and versionless: "auth.ssh.login_failed".
// Detection rules match on these identifiers, so the set is closed.
type EventType string

const (
	TypeSSHLoginFailed  EventType = "auth.ssh.login_failed"
	TypeSSHLoginSuccess EventType = "auth.ssh.login_success"
	TypeSSHInvalidUser  EventType = "auth.ssh.invalid_user"
	TypeSSHDisconnect   EventType = "auth.ssh.disconnect"
	TypeSudoCommand     EventType = "auth.sudo.command"
	TypeSudoAuthFailed  EventType = "auth.sudo.auth_failed"
	TypeAuthorizedKeys  EventType = "security.authorized_keys.modified"
	TypeHTTPAuthFailed  EventType = "http.auth.failed"
	TypeHTTPAuthSuccess EventType = "http.auth.success"
	TypeFirewallBlock   EventType = "network.firewall.block"
	TypeAgentHeartbeat  EventType = "agent.heartbeat"
	TypeAgentLifecycle  EventType = "agent.lifecycle"
)

// EventTypeSet is the closed set of canonical event types.
var EventTypeSet = []EventType{
	TypeSSHLoginFailed,
	TypeSSHLoginSuccess,
	TypeSSHInvalidUser,
	TypeSSHDisconnect,
	TypeSudoCommand,
	TypeSudoAuthFailed,
	TypeAuthorizedKeys,
	TypeHTTPAuthFailed,
	TypeHTTPAuthSuccess,
	TypeFirewallBlock,
	TypeAgentHeartbeat,
	TypeAgentLifecycle,
}

// Valid reports whether t is a known canonical event type.
func (t EventType) Valid() bool {
	for _, v := range EventTypeSet {
		if v == t {
			return true
		}
	}
	return false
}

// Source identifies the telemetry source class that produced an event.
type Source string

const (
	SourceAuthLog Source = "auth.log"
	SourceSyslog  Source = "syslog"
	SourceAgent   Source = "agent"
	// SourceHTTPAccess is the nginx/HTTP access log family. It is a distinct
	// source class so rules can separate network-edge authentication failures
	// from host authentication failures.
	SourceHTTPAccess Source = "http.access"
	// SourceContainerLog is container stdout/stderr collected from the Docker
	// JSON-file log driver. The envelope is stripped and the inner line is
	// parsed by the same registry as host telemetry, so container activity
	// produces the same canonical types.
	SourceContainerLog Source = "container.log"
)

// Valid reports whether s is a supported source.
func (s Source) Valid() bool {
	return s == SourceAuthLog || s == SourceSyslog || s == SourceAgent ||
		s == SourceHTTPAccess || s == SourceContainerLog
}

// Event is the canonical, normalized security event.
//
// Field names are stable: they are a public contract used by the API, the
// detection rules, correlation and the AI evidence packer.
type Event struct {
	// ID is a producer-generated, time-ordered ULID and the ingestion
	// idempotency key. It is immutable: a replay MUST reuse the same ID so the
	// server can collapse duplicates without re-running detection side effects.
	ID string `json:"id"`

	// SchemaVersion is the contract version of this payload.
	SchemaVersion string `json:"schema_version"`

	// Type is the canonical event type.
	Type EventType `json:"type"`

	// Time is the normalized event occurrence time in UTC.
	Time time.Time `json:"time"`

	// ReceivedAt is the server-assigned ingestion time in UTC.
	ReceivedAt time.Time `json:"received_at"`

	// ObservedAt is the agent-side observation time in UTC.
	ObservedAt time.Time `json:"observed_at"`

	// Host is the canonical host identifier (lowercased, trimmed).
	Host string `json:"host"`

	// AgentID is the identifier of the collecting agent, when known.
	AgentID string `json:"agent_id,omitempty"`

	// Source is the telemetry source class.
	Source Source `json:"source"`

	// SourcePath is the origin file or stream, relative and sanitized.
	SourcePath string `json:"source_path,omitempty"`

	// Actor is the acting entity (user, process owner, key fingerprint).
	Actor string `json:"actor,omitempty"`

	// Target is the acted-upon entity (user, file, resource).
	Target string `json:"target,omitempty"`

	// Network contains network-level entity attributes.
	Network Network `json:"network,omitempty"`

	// Outcome is the canonical outcome, when applicable.
	Outcome Outcome `json:"outcome,omitempty"`

	// Severity is the source-declared severity (not a detection verdict).
	Severity Severity `json:"severity"`

	// Attributes carries type-specific structured detail.
	Attributes map[string]string `json:"attributes,omitempty"`

	// Message is a human-readable summary.
	Message string `json:"message,omitempty"`

	// Raw is the original telemetry line, retained as evidence.
	//
	// Retained because detection cannot be audited without the source record.
	// It is treated as untrusted on every read and must be redacted before it
	// is ever exposed to an AI provider or an unauthenticated surface.
	Raw string `json:"raw,omitempty"`
}

// Network holds network entity attributes.
type Network struct {
	// SourceIP is the observed source address, normalized when parseable.
	//
	// The wire name is src_ip, matching the canonical event contract and the
	// database column. The Go field keeps the longer name because SourceIP
	// reads better in code than SrcIP.
	SourceIP string `json:"src_ip,omitempty"`

	// SourcePort is the observed source port.
	SourcePort int `json:"src_port,omitempty"`

	// DestIP is the observed destination address.
	DestIP string `json:"dst_ip,omitempty"`

	// DestPort is the observed destination port.
	DestPort int `json:"dst_port,omitempty"`

	// Protocol is the transport protocol in lowercase.
	Protocol string `json:"protocol,omitempty"`
}

// EntityKey returns the stable correlation key for this event, or "" when the
// event has no usable correlation entity.
//
// Correlation is entity-aware (DESIGN.md): an incident is only joined when a
// concrete entity matches, never on time proximity alone.
func (e *Event) EntityKey() string {
	if e.Actor != "" {
		return "user:" + e.Actor
	}
	if e.Network.SourceIP != "" {
		return "ip:" + e.Network.SourceIP
	}
	if e.Target != "" {
		return "target:" + e.Target
	}
	return ""
}

// DedupeKey returns the secondary idempotency key for this event.
//
// The primary idempotency key is the event ID. This key exists to catch a
// producer that regenerated an ID for the same physical log line (for example
// after losing spool metadata). It is scoped to the emitting host so two hosts
// cannot collide, and excludes every server-assigned field so a legitimate
// replay produces an identical key.
func (e *Event) DedupeKey() string {
	return strings.Join([]string{
		e.Host,
		e.AgentID,
		string(e.Type),
		e.Time.UTC().Format(time.RFC3339Nano),
		e.Actor,
		e.Network.SourceIP,
		e.Raw,
	}, "\x1f")
}
