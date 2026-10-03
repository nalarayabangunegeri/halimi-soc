// Package agents defines the agent identity and credential contract.
package agents

import (
	"fmt"
	"time"
)

// Status is the agent liveness state.
type Status string

const (
	StatusOnline   Status = "ONLINE"
	StatusOffline  Status = "OFFLINE"
	StatusDegraded Status = "DEGRADED"
	StatusUnknown  Status = "UNKNOWN"
)

// StatusSet is the closed set of agent statuses.
var StatusSet = []Status{StatusOnline, StatusOffline, StatusDegraded, StatusUnknown}

// Valid reports whether s is a canonical agent status.
func (s Status) Valid() bool {
	for _, v := range StatusSet {
		if v == s {
			return true
		}
	}
	return false
}

// Agent is an enrolled collection endpoint.
type Agent struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Status  Status `json:"status"`

	EnrolledAt    time.Time  `json:"enrolled_at"`
	LastHeartbeat time.Time  `json:"last_heartbeat"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`

	// QueueDepth and SpoolBytes are self-reported by the agent. They are
	// operational telemetry, not security truth, and are surfaced as-is.
	QueueDepth int64 `json:"queue_depth"`
	SpoolBytes int64 `json:"spool_bytes"`
}

// Validate checks the agent invariants.
func (a *Agent) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("agent id is required")
	}
	if a.Host == "" {
		return fmt.Errorf("agent host is required")
	}
	if !a.Status.Valid() {
		return fmt.Errorf("agent status %q is not canonical", a.Status)
	}
	return nil
}

// Revoked reports whether the agent's credentials have been revoked.
func (a *Agent) Revoked() bool { return a.RevokedAt != nil }

// Token is an agent authentication credential.
//
// Only the SHA-256 hash of the token is stored. The plaintext token exists
// exactly once, in the enrollment response, and is never persisted or logged.
type Token struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	TokenHash string `json:"-"`

	// Prefix is a short, non-secret fragment used to identify a token in an
	// audit log without disclosing it.
	Prefix string `json:"prefix"`

	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RotatedAt  *time.Time `json:"rotated_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// Active reports whether the token may authenticate a request at time now.
func (t *Token) Active(now time.Time) bool {
	if t.Revoked() || t.Rotated() {
		return false
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// Revoked reports whether the token has been revoked.
func (t *Token) Revoked() bool { return t.RevokedAt != nil }

// Rotated reports whether the token has been superseded by a newer one.
func (t *Token) Rotated() bool { return t.RotatedAt != nil }
