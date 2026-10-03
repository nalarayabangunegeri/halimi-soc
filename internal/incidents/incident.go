// Package incidents defines the incident contract and its lifecycle.
package incidents

import (
	"fmt"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// Status is the incident lifecycle state.
//
// The set is a superset of the PRD minimum (NEW, ACKNOWLEDGED, INVESTIGATING,
// RESOLVED, FALSE_POSITIVE): CONTAINED and CLOSED are added because a real
// investigation needs to record that the immediate threat was stopped before it
// is formally resolved, and that a resolved incident was later closed out.
// PRD.md records this amendment.
type Status string

const (
	// StatusNew is a freshly correlated incident nobody has looked at yet.
	StatusNew Status = "NEW"

	// StatusAcknowledged means an operator has seen it and owns it.
	StatusAcknowledged Status = "ACKNOWLEDGED"

	// StatusInvestigating means active analysis is in progress.
	StatusInvestigating Status = "INVESTIGATING"

	// StatusContained means the immediate threat was stopped, but the
	// investigation is not finished.
	StatusContained Status = "CONTAINED"

	// StatusResolved means the investigation concluded.
	StatusResolved Status = "RESOLVED"

	// StatusClosed means the incident was closed out after resolution.
	StatusClosed Status = "CLOSED"

	// StatusFalsePositive means the incident was judged not to be a real
	// security event.
	StatusFalsePositive Status = "FALSE_POSITIVE"
)

// StatusSet is the closed set of incident statuses.
var StatusSet = []Status{
	StatusNew, StatusAcknowledged, StatusInvestigating,
	StatusContained, StatusResolved, StatusClosed, StatusFalsePositive,
}

// Valid reports whether s is canonical.
func (s Status) Valid() bool {
	for _, v := range StatusSet {
		if v == s {
			return true
		}
	}
	return false
}

// Terminal reports whether the status ends active work on the incident.
func (s Status) Terminal() bool {
	return s == StatusResolved || s == StatusClosed || s == StatusFalsePositive
}

// allowedTransitions is the incident state machine.
//
// Progress is forward-only through the investigation phases. An incident is
// never reopened: new activity creates a new incident, which keeps the timeline
// of each investigation immutable. FALSE_POSITIVE is reachable from any active
// state because a false positive can be recognised at any point.
var allowedTransitions = map[Status]map[Status]bool{
	StatusNew: {
		StatusAcknowledged:  true,
		StatusInvestigating: true,
		StatusFalsePositive: true,
	},
	StatusAcknowledged: {
		StatusInvestigating: true,
		StatusFalsePositive: true,
	},
	StatusInvestigating: {
		StatusContained:     true,
		StatusResolved:      true,
		StatusFalsePositive: true,
	},
	StatusContained: {
		StatusResolved:      true,
		StatusFalsePositive: true,
	},
	StatusResolved: {
		StatusClosed: true,
	},
	// Terminal states accept nothing. A client that wants to continue the work
	// must create a new incident, so history cannot be rewritten.
	StatusClosed:        {},
	StatusFalsePositive: {},
}

// CanTransition reports whether a status change is permitted.
func CanTransition(from, to Status) bool {
	return allowedTransitions[from][to]
}

// Transition validates a status change.
func Transition(from, to Status) error {
	if !from.Valid() {
		return fmt.Errorf("incident status %q is not canonical", from)
	}
	if !to.Valid() {
		return fmt.Errorf("incident status %q is not canonical", to)
	}
	if !CanTransition(from, to) {
		return fmt.Errorf("incident transition %s -> %s is not permitted", from, to)
	}
	return nil
}

// Incident is a correlated group of alerts describing one security event.
type Incident struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Summary  string         `json:"summary"`
	Severity model.Severity `json:"severity"`
	Status   Status         `json:"status"`

	// Hosts, Actors and SourceIPs are the entities the incident is scoped to.
	// SourceIPs is what lets alerts from different hosts still join when they
	// share an attacker address; without it correlation could only merge
	// within one host, contradicting the documented entity policy.
	Hosts     []string `json:"hosts"`
	Actors    []string `json:"actors"`
	SourceIPs []string `json:"source_ips"`

	// AlertIDs and EventIDs are the evidence trail.
	AlertIDs []string `json:"alert_ids"`
	EventIDs []string `json:"event_ids"`

	// Stages records which attack phases were observed, in order.
	Stages []Stage `json:"stages"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Stage is one observed attack phase inside an incident.
//
// Stages are derived deterministically from the rule that fired, and the naming
// follows a kill-chain vocabulary so an analyst reads the incident as a
// narrative rather than a list of alerts.
type Stage struct {
	Name     string         `json:"name"`
	AlertID  string         `json:"alert_id"`
	RuleID   string         `json:"rule_id"`
	At       time.Time      `json:"at"`
	Severity model.Severity `json:"severity"`
}

// Stage names, ordered by the kill chain.
const (
	StageReconnaissance      = "RECONNAISSANCE"
	StageInitialAccess       = "INITIAL_ACCESS"
	StageCredentialAccess    = "CREDENTIAL_ACCESS"
	StagePrivilegeEscalation = "PRIVILEGE_ESCALATION"
	StagePersistence         = "PERSISTENCE"
	StageExecution           = "EXECUTION"
	StageUnknown             = "UNKNOWN"
)

// StageOrder gives each stage a rank for sorting the narrative.
func StageOrder(name string) int {
	switch name {
	case StageReconnaissance:
		return 0
	case StageInitialAccess:
		return 1
	case StageCredentialAccess:
		return 2
	case StageExecution:
		return 3
	case StagePrivilegeEscalation:
		return 4
	case StagePersistence:
		return 5
	}
	return 99
}

// Validate checks incident invariants.
func (i *Incident) Validate() error {
	if i.ID == "" {
		return fmt.Errorf("incident id is required")
	}
	if i.Title == "" {
		return fmt.Errorf("incident title is required")
	}
	if model.SeverityRank(i.Severity) == 0 {
		return fmt.Errorf("incident severity %q is not canonical", i.Severity)
	}
	if !i.Status.Valid() {
		return fmt.Errorf("incident status %q is not canonical", i.Status)
	}
	if len(i.AlertIDs) == 0 {
		return fmt.Errorf("incident must reference at least one alert")
	}
	if i.LastSeen.Before(i.FirstSeen) {
		return fmt.Errorf("incident last_seen precedes first_seen")
	}
	return nil
}

// IncidentList is a page of incidents.
type IncidentList struct {
	Incidents  []*Incident `json:"incidents"`
	NextCursor string      `json:"next_cursor,omitempty"`
}
