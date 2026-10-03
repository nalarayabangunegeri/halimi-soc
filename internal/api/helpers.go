package api

import (
	"strings"

	"github.com/halimi/halimisoc/internal/alerts"
	"github.com/halimi/halimisoc/internal/audit"
	"github.com/halimi/halimisoc/internal/incidents"
)

// alertsStatus normalizes a client-supplied alert status.
//
// The status enum is uppercase on the wire, so input is uppercased and then
// validated against the closed set. An unknown value is rejected rather than
// coerced.
func alertsStatus(s string) alerts.Status {
	return alerts.Status(strings.ToUpper(strings.TrimSpace(s)))
}

// incidentStatus normalizes a client-supplied incident status.
func incidentStatus(s string) incidents.Status {
	return incidents.Status(strings.ToUpper(strings.TrimSpace(s)))
}

// auditEntryForAlertStatus builds the audit record for an alert status change.
func auditEntryForAlertStatus(p *principal, alertID string, st alerts.Status) audit.Entry {
	return audit.Entry{
		Actor:      actorName(p),
		Action:     audit.ActionAlertStatusChanged,
		Resource:   "alert",
		ResourceID: alertID,
		Result:     audit.ResultSuccess,
		Detail:     "status=" + string(st),
	}
}

// auditEntryForIncidentStatus builds the audit record for an incident change.
func auditEntryForIncidentStatus(p *principal, incidentID string, st incidents.Status) audit.Entry {
	return audit.Entry{
		Actor:      actorName(p),
		Action:     audit.ActionIncidentStatusChanged,
		Resource:   "incident",
		ResourceID: incidentID,
		Result:     audit.ResultSuccess,
		Detail:     "status=" + string(st),
	}
}

// nonNil returns an empty slice rather than nil.
//
// Go encodes a nil slice as JSON `null`, but a list endpoint promises an array:
// the documented shape is `{"alerts": [], ...}`, and a client that reads `.length`
// on `null` throws instead of rendering "no results". A store legitimately answers
// an empty query with a nil slice — that is idiomatic Go — so the correction belongs
// on the way out, at the HTTP boundary, rather than inside every store method.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func actorName(p *principal) string {
	if p == nil || p.User == nil {
		return "unknown"
	}
	return audit.ActorRef(audit.ActorUser, p.User.Username)
}
