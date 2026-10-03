package stream

import (
	"time"

	"github.com/halimi/halimisoc/internal/agents"
	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
)

// The types in this file are the stream's wire contract.
//
// They are projections, not the stored records. A stream is pushed to every
// connected operator continuously, so it must carry the minimum a dashboard needs
// to render a change and nothing more. In particular:
//
//   - raw evidence is never included, because a stream is not an evidence channel
//     and raw telemetry is the most sensitive field in the system;
//   - the full event id list is replaced by a count, so a stream cannot be used to
//     enumerate an incident's evidence without the REST permission for it.

// AlertView is the projected alert payload.
type AlertView struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"rule_id"`
	RuleVersion int       `json:"rule_version"`
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Title       string    `json:"title"`
	Host        string    `json:"host,omitempty"`
	Actor       string    `json:"actor,omitempty"`
	SourceIP    string    `json:"src_ip,omitempty"`
	Count       int       `json:"count"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewAlertView projects an alert.
func NewAlertView(a *alerts.Alert) AlertView {
	if a == nil {
		return AlertView{}
	}
	return AlertView{
		ID:          a.ID,
		RuleID:      a.RuleID,
		RuleVersion: a.RuleVersion,
		RuleName:    a.RuleName,
		Severity:    string(a.Severity),
		Status:      string(a.Status),
		Title:       a.Title,
		Host:        a.Host,
		Actor:       a.Actor,
		SourceIP:    a.SourceIP,
		Count:       a.Count,
		WindowStart: a.WindowStart,
		WindowEnd:   a.WindowEnd,
		CreatedAt:   a.CreatedAt,
	}
}

// IncidentView is the projected incident payload.
type IncidentView struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Summary    string    `json:"summary"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	Hosts      []string  `json:"hosts"`
	Actors     []string  `json:"actors"`
	AlertCount int       `json:"alert_count"`
	EventCount int       `json:"event_count"`
	StageCount int       `json:"stage_count"`
	LastStage  string    `json:"last_stage,omitempty"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// NewIncidentView projects an incident.
func NewIncidentView(inc *incidents.Incident) IncidentView {
	if inc == nil {
		return IncidentView{}
	}
	v := IncidentView{
		ID:         inc.ID,
		Title:      inc.Title,
		Summary:    inc.Summary,
		Severity:   string(inc.Severity),
		Status:     string(inc.Status),
		Hosts:      append([]string(nil), inc.Hosts...),
		Actors:     append([]string(nil), inc.Actors...),
		AlertCount: len(inc.AlertIDs),
		EventCount: len(inc.EventIDs),
		StageCount: len(inc.Stages),
		FirstSeen:  inc.FirstSeen,
		LastSeen:   inc.LastSeen,
		UpdatedAt:  inc.UpdatedAt,
	}
	if len(inc.Stages) > 0 {
		v.LastStage = inc.Stages[len(inc.Stages)-1].Name
	}
	return v
}

// AgentView is the projected agent payload.
type AgentView struct {
	ID            string    `json:"id"`
	Host          string    `json:"host"`
	Status        string    `json:"status"`
	Version       string    `json:"version,omitempty"`
	QueueDepth    int64     `json:"queue_depth"`
	SpoolBytes    int64     `json:"spool_bytes"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
	Revoked       bool      `json:"revoked"`
}

// NewAgentView projects an agent.
func NewAgentView(a *agents.Agent) AgentView {
	if a == nil {
		return AgentView{}
	}
	return AgentView{
		ID:            a.ID,
		Host:          a.Host,
		Status:        string(a.Status),
		Version:       a.Version,
		QueueDepth:    a.QueueDepth,
		SpoolBytes:    a.SpoolBytes,
		LastHeartbeat: a.LastHeartbeat,
		Revoked:       a.Revoked(),
	}
}

// EventView is the projected event payload, used only by tests and the metrics
// snapshot. Raw telemetry is deliberately absent.
type EventView struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Host     string    `json:"host"`
	Actor    string    `json:"actor,omitempty"`
	SourceIP string    `json:"src_ip,omitempty"`
	Severity string    `json:"severity"`
	Time     time.Time `json:"time"`
}

// NewEventView projects an event without its raw evidence.
func NewEventView(e *model.Event) EventView {
	if e == nil {
		return EventView{}
	}
	return EventView{
		ID:       e.ID,
		Type:     string(e.Type),
		Host:     e.Host,
		Actor:    e.Actor,
		SourceIP: e.Network.SourceIP,
		Severity: string(e.Severity),
		Time:     e.Time,
	}
}
