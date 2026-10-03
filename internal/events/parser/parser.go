// Package parser turns raw telemetry lines into canonical events.
//
// Security contract (DESIGN.md §7): a parser must never panic on
// attacker-controlled input, must bound line and field length, and must
// classify rather than guess. Every parser returns one of five explicit
// statuses so the caller can account for what it dropped and why.
package parser

import (
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// Status is the parser's verdict for a single assembled record.
type Status string

const (
	// StatusValid means a canonical event was produced.
	StatusValid Status = "VALID"

	// StatusMalformed means the record matched a known format but could not be
	// trusted, for example a truncated field.
	StatusMalformed Status = "MALFORMED"

	// StatusUnsupported means no parser claimed the record.
	StatusUnsupported Status = "UNSUPPORTED"

	// StatusIncomplete means the record is a known type but lacks a field
	// required to make it actionable, such as a missing principal.
	StatusIncomplete Status = "INCOMPLETE"

	// StatusNonSecurityRelevant means the record is understood but carries no
	// security signal.
	StatusNonSecurityRelevant Status = "NON_SECURITY_RELEVANT"
)

// Line is one assembled source record handed to a parser.
type Line struct {
	// Raw is the assembled record, already bounded by the assembler.
	Raw string

	// Host is the authenticated agent's host claim. It is preferred over a
	// hostname embedded in the line because it is bound to an agent credential.
	Host string

	// AgentID is the authenticated agent identity.
	AgentID string

	// SourcePath is the origin file, relative and sanitized.
	SourcePath string

	// ObservedAt is when the agent read the record.
	ObservedAt time.Time
}

// Result is a parser verdict plus, when valid, the canonical event.
type Result struct {
	Status Status
	Event  *model.Event
	Reason string
}

// Parser recognizes one family of source records.
type Parser interface {
	// Name is the stable parser identifier recorded on every event it emits.
	Name() string

	// Match reports whether this parser recognizes the record. It must be
	// cheap and must not mutate the line.
	Match(raw string) bool

	// Parse converts a matched record into a canonical event.
	Parse(l Line) Result
}

// Registry selects a parser for a record.
type Registry struct {
	parsers []Parser
}

// NewRegistry builds a registry from the given parsers, preserving order.
// Order matters: the first matching parser wins, so more specific parsers must
// be registered before more general ones.
func NewRegistry(parsers ...Parser) *Registry {
	return &Registry{parsers: parsers}
}

// Default returns the registry of built-in parsers.
func Default() *Registry {
	return NewRegistry(
		&DockerParser{},
		&UFWParser{},
		&NginxParser{},
		&SudoParser{},
		&AuthorizedKeysParser{},
		&SSHParser{},
	)
}

// Select returns the first parser that matches raw, or nil.
func (r *Registry) Select(raw string) Parser {
	for _, p := range r.parsers {
		if p.Match(raw) {
			return p
		}
	}
	return nil
}

// Parse classifies and parses a record.
//
// An unrecognized record yields StatusUnsupported rather than an error: a
// syslog stream legitimately contains records no security parser cares about,
// and treating those as failures would drown real parser errors in noise.
func (r *Registry) Parse(l Line) Result {
	raw := strings.TrimRight(l.Raw, "\r\n")
	if strings.TrimSpace(raw) == "" {
		return Result{Status: StatusNonSecurityRelevant, Reason: "empty record"}
	}
	p := r.Select(raw)
	if p == nil {
		return Result{Status: StatusUnsupported, Reason: "no parser matched"}
	}
	res := p.Parse(l)
	if res.Event != nil {
		if res.Event.Attributes == nil {
			res.Event.Attributes = map[string]string{}
		}
		res.Event.Attributes["parser"] = p.Name()
	}
	return res
}

// baseEvent returns an event pre-populated with fields common to every parser.
func baseEvent(l Line, t model.EventType, at time.Time, severity model.Severity) *model.Event {
	return &model.Event{
		SchemaVersion: model.SchemaVersion,
		Type:          t,
		Time:          at.UTC(),
		ObservedAt:    l.ObservedAt.UTC(),
		Host:          l.Host,
		AgentID:       l.AgentID,
		SourcePath:    l.SourcePath,
		Severity:      severity,
		Raw:           l.Raw,
		Attributes:    map[string]string{},
	}
}
