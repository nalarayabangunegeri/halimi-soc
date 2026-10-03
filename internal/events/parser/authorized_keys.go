package parser

import (
	"strings"

	"github.com/halimi/halimisoc/internal/events/model"
)

// AuthorizedKeysParser recognizes persistence-oriented changes to an SSH
// authorized_keys file reported by non-sudo sources such as auditd, a file
// integrity monitor, or a hardening script's log output.
//
// It deliberately requires both the file name and a change verb. Matching on
// the file name alone would classify every log line that merely mentions the
// path, which is a reliable way to build a noisy rule.
type AuthorizedKeysParser struct{}

// Name implements Parser.
func (p *AuthorizedKeysParser) Name() string { return "authorized_keys" }

var authorizedKeysVerbs = []string{
	"modified", "changed", "written", "updated", "added", "appended",
	"created", "deleted", "removed", "replaced",
}

// Match implements Parser.
func (p *AuthorizedKeysParser) Match(raw string) bool {
	lower := strings.ToLower(raw)
	if !strings.Contains(lower, "authorized_keys") {
		return false
	}
	for _, v := range authorizedKeysVerbs {
		if strings.Contains(lower, v) {
			return true
		}
	}
	return false
}

// Parse implements Parser.
func (p *AuthorizedKeysParser) Parse(l Line) Result {
	ts, _, msg := splitSyslogPrefix(l.Raw)
	_, _, body := splitProgram(msg)

	at, ok := ParseTime(ts, l.ObservedAt)
	if !ok {
		at = l.ObservedAt
	}

	e := baseEvent(l, model.TypeAuthorizedKeys, at, model.SeverityCritical)
	e.Source = model.SourceSyslog
	e.Message = "SSH authorized_keys modified"
	e.Attributes["file"] = "authorized_keys"
	e.Attributes["authorized_keys_modified"] = "true"

	if user := extractUser(body); user != "" {
		e.Actor = user
		e.Target = user
	}
	if !ok {
		e.Attributes["timestamp_source"] = "observed"
	}
	return Result{Status: StatusValid, Event: e}
}

// extractUser makes a bounded attempt to attribute the change to a principal.
// It returns "" rather than guessing when no recognizable field is present,
// because a wrong attribution would corrupt correlation.
func extractUser(s string) string {
	for _, key := range []string{"user=", "USER=", "uid=", "by "} {
		i := strings.Index(s, key)
		if i < 0 {
			continue
		}
		fields := strings.Fields(s[i+len(key):])
		if len(fields) == 0 {
			continue
		}
		v := strings.Trim(fields[0], `",;`)
		if v == "" || strings.ContainsAny(v, "[]()") {
			continue
		}
		return v
	}
	return ""
}
