// Package correlation groups alerts into entity-aware incidents.
//
// DESIGN.md §12: correlation must be explainable and entity-aware. An alert only
// joins an incident when it shares a concrete entity (host, actor or source IP)
// within a bounded time window. Correlation never joins on time proximity alone,
// because "two alerts happened near each other" is not evidence that they are
// related, and a wrongly merged incident is worse than two honest ones.
package correlation

import (
	"sort"
	"time"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/events/model"
	"github.com/halimi/halimisoc/internal/incidents"
)

// Options bound the correlation behaviour.
type Options struct {
	// Window is the maximum gap between the first and last alert that may still
	// be considered one incident.
	Window time.Duration

	// MaxEntities caps how many distinct entity values an incident may span
	// before it stops absorbing further alerts. This keeps one noisy host from
	// merging unrelated incidents together.
	MaxEntities int

	// MaxAlerts caps the alerts attached to a single incident.
	MaxAlerts int
}

// DefaultOptions returns the shipped correlation bounds.
func DefaultOptions() Options {
	return Options{
		Window:      30 * time.Minute,
		MaxEntities: 32,
		MaxAlerts:   256,
	}
}

// Data is the entity tuple extracted from an alert.
type Data struct {
	Host     string
	Actor    string
	SourceIP string
}

// Extract pulls the correlatable entities from an alert.
func Extract(a *alerts.Alert) Data {
	return Data{Host: a.Host, Actor: a.Actor, SourceIP: a.SourceIP}
}

// SharedEntity reports whether two entity sets share a concrete value.
//
// It returns the shared values so the caller can record why the merge happened.
// An empty value never matches another empty value: two alerts that both lack a
// source IP do not share one.
func SharedEntity(a, b Data) []string {
	var shared []string
	if a.Host != "" && a.Host == b.Host {
		shared = append(shared, "host:"+a.Host)
	}
	if a.Actor != "" && a.Actor == b.Actor {
		shared = append(shared, "actor:"+a.Actor)
	}
	if a.SourceIP != "" && a.SourceIP == b.SourceIP {
		shared = append(shared, "ip:"+a.SourceIP)
	}
	return shared
}

// sharedWithIncident reports whether an alert shares a concrete entity value
// with any value already scoped to the incident.
//
// The incident side is a list, not a single value: an incident that already
// spans two hosts must still match an alert on either host. Comparing only the
// first host would silently stop merging once an incident grew past one host.
//
// A shared source address alone never merges two different hosts: one attacker
// address probing unrelated machines is not one incident. The address still
// joins when the hosts do not conflict (same host, or unknown on either side),
// which is what lets host-less alerts correlate without ever overriding an
// explicit host mismatch.
func sharedWithIncident(inc *incidents.Incident, a Data) []string {
	var shared []string
	for _, h := range inc.Hosts {
		if h != "" && h == a.Host {
			shared = append(shared, "host:"+h)
			break
		}
	}
	for _, u := range inc.Actors {
		if u != "" && u == a.Actor {
			shared = append(shared, "actor:"+u)
			break
		}
	}
	if !hostsConflict(inc.Hosts, a.Host) {
		for _, ip := range inc.SourceIPs {
			if ip != "" && ip == a.SourceIP {
				shared = append(shared, "ip:"+ip)
				break
			}
		}
	}
	return shared
}

// hostsConflict reports whether the alert names a host the incident does not
// scope to. An unknown host on either side is not a conflict: missing evidence
// must not veto a match that concrete evidence supports.
func hostsConflict(hosts []string, host string) bool {
	if host == "" || len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if h == host {
			return false
		}
	}
	return true
}

// ShouldJoin reports whether alert a may join incident inc.
func ShouldJoin(inc *incidents.Incident, a *alerts.Alert, opts Options) (bool, []string) {
	if inc == nil {
		return false, nil
	}
	if len(inc.AlertIDs) >= opts.MaxAlerts {
		return false, nil
	}

	// The window is measured from the incident's own span, not from creation
	// time, so an incident stays joinable for as long as it is active.
	if a.WindowEnd.After(inc.LastSeen.Add(opts.Window)) {
		return false, nil
	}

	shared := sharedWithIncident(inc, Extract(a))
	if len(shared) == 0 {
		return false, nil
	}

	distinct := len(inc.Hosts) + len(inc.Actors) + len(inc.SourceIPs)
	if distinct >= opts.MaxEntities {
		return false, nil
	}
	return true, shared
}

// StageFor maps a rule id to a kill-chain stage.
//
// The mapping is explicit and total: an unknown rule maps to UNKNOWN rather than
// being guessed from the rule's name, because a guessed stage would mislead an
// analyst reading the narrative.
func StageFor(ruleID string) string {
	switch ruleID {
	case "ssh-bruteforce", "sudo-auth-failure-burst", "http-auth-failure-spike":
		return incidents.StageCredentialAccess
	case "ssh-login-after-bruteforce":
		return incidents.StageInitialAccess
	case "sudo-after-suspicious-login":
		return incidents.StagePrivilegeEscalation
	case "privileged-command-after-remote-login":
		return incidents.StageExecution
	case "ssh-authorized-keys-modified":
		return incidents.StagePersistence
	case "firewall-port-scan":
		return incidents.StageReconnaissance
	}
	return incidents.StageUnknown
}

// Append merges an alert into an incident, returning the updated incident.
//
// The function is pure: it never mutates the input incident. Callers persist the
// result, which keeps the merge auditable and makes the function trivially
// testable.
func Append(inc *incidents.Incident, a *alerts.Alert, at time.Time) *incidents.Incident {
	out := *inc
	out.Hosts = appendUnique(out.Hosts, a.Host)
	out.Actors = appendUnique(out.Actors, a.Actor)
	out.SourceIPs = appendUnique(out.SourceIPs, a.SourceIP)
	out.AlertIDs = appendUnique(out.AlertIDs, a.ID)
	out.EventIDs = appendUnique(out.EventIDs, a.EventIDs...)
	out.Severity = model.MaxSeverity(out.Severity, a.Severity)
	out.Stages = append(out.Stages, incidents.Stage{
		Name:     StageFor(a.RuleID),
		AlertID:  a.ID,
		RuleID:   a.RuleID,
		At:       a.WindowEnd,
		Severity: a.Severity,
	})
	sort.SliceStable(out.Stages, func(i, j int) bool {
		if !out.Stages[i].At.Equal(out.Stages[j].At) {
			return out.Stages[i].At.Before(out.Stages[j].At)
		}
		return incidents.StageOrder(out.Stages[i].Name) < incidents.StageOrder(out.Stages[j].Name)
	})

	if a.WindowStart.Before(out.FirstSeen) || out.FirstSeen.IsZero() {
		out.FirstSeen = a.WindowStart
	}
	if a.WindowEnd.After(out.LastSeen) {
		out.LastSeen = a.WindowEnd
	}
	out.UpdatedAt = at
	return &out
}

// New builds an incident from its first alert.
func New(id string, a *alerts.Alert, at time.Time) *incidents.Incident {
	inc := &incidents.Incident{
		ID:        id,
		Title:     titleFor(a),
		Summary:   summaryFor(a),
		Severity:  a.Severity,
		Status:    incidents.StatusNew,
		CreatedAt: at,
		UpdatedAt: at,
	}
	return Append(inc, a, at)
}

// titleFor derives a stable, human-readable incident title from the alert.
//
// The title is built from canonical values only, so it cannot carry injected
// content even though the alert reason ultimately descends from telemetry.
func titleFor(a *alerts.Alert) string {
	subject := a.Host
	if subject == "" {
		subject = a.SourceIP
	}
	if subject == "" {
		subject = "unknown host"
	}
	return a.RuleName + " on " + subject
}

func summaryFor(a *alerts.Alert) string {
	return a.Reason
}

func appendUnique(list []string, values ...string) []string {
	for _, v := range values {
		if v == "" {
			continue
		}
		dup := false
		for _, existing := range list {
			if existing == v {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, v)
		}
	}
	return list
}
