package parser

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// SSHParser parses OpenSSH server records from auth.log / secure / syslog.
type SSHParser struct{}

// Name implements Parser.
func (p *SSHParser) Name() string { return "sshd" }

var (
	reFailedPassword = regexp.MustCompile(`^Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reFailedPublic   = regexp.MustCompile(`^Failed publickey for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reAcceptedAuth   = regexp.MustCompile(`^Accepted (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reInvalidUser    = regexp.MustCompile(`^Invalid user (\S+) from (\S+) port (\d+)`)
	reMaxAttempts    = regexp.MustCompile(`^error: maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reDisconnect     = regexp.MustCompile(`^(?:Disconnected from|Connection closed by(?: authenticating user \S+)?|Received disconnect from) (\S+) port (\d+)`)
	reSessionOpened  = regexp.MustCompile(`^pam_unix\(sshd:session\): session opened for user (\S+)`)
	reSessionClosed  = regexp.MustCompile(`^pam_unix\(sshd:session\): session closed for user (\S+)`)
)

// Match implements Parser. It claims records emitted by an sshd process.
func (p *SSHParser) Match(raw string) bool {
	_, _, msg := splitSyslogPrefix(raw)
	program, _, _ := splitProgram(msg)
	if program == "sshd" {
		return true
	}
	// Some distributions log through a wrapper that keeps the sshd prefix
	// inside the message body.
	return strings.Contains(raw, "sshd[") && strings.Contains(raw, "]:")
}

// Parse implements Parser.
func (p *SSHParser) Parse(l Line) Result {
	ts, _, msg := splitSyslogPrefix(l.Raw)
	program, pid, body := splitProgram(msg)
	if program == "" {
		// Tolerate the wrapped form: locate the last "sshd[...]:" marker.
		if i := strings.LastIndex(l.Raw, "sshd["); i >= 0 {
			program, pid, body = splitProgram(l.Raw[i:])
		}
	}

	at, ok := ParseTime(ts, l.ObservedAt)
	if !ok {
		at = l.ObservedAt
	}

	e, status, reason := p.classify(l, body, at)
	if e == nil {
		return Result{Status: status, Reason: reason}
	}

	e.Source = model.SourceAuthLog
	if pid != "" {
		e.Attributes["pid"] = pid
	}
	if !ok {
		e.Attributes["timestamp_source"] = "observed"
	}
	return Result{Status: StatusValid, Event: e}
}

func (p *SSHParser) classify(ln Line, body string, at time.Time) (*model.Event, Status, string) {
	// Order matters: the most specific patterns are attempted first so that a
	// "Failed password ... invalid user ..." record is not misclassified by the
	// generic invalid-user rule.
	switch {
	case reFailedPassword.MatchString(body):
		m := reFailedPassword.FindStringSubmatch(body)
		return loginFailed(ln, m[1], m[2], m[3], at, body), StatusValid, ""

	case reFailedPublic.MatchString(body):
		m := reFailedPublic.FindStringSubmatch(body)
		e := loginFailed(ln, m[1], m[2], m[3], at, body)
		e.Attributes["auth_method"] = "publickey"
		return e, StatusValid, ""

	case reAcceptedAuth.MatchString(body):
		m := reAcceptedAuth.FindStringSubmatch(body)
		e := loginSucceeded(ln, m[2], m[3], m[4], at, body)
		e.Attributes["auth_method"] = m[1]
		return e, StatusValid, ""

	case reInvalidUser.MatchString(body):
		m := reInvalidUser.FindStringSubmatch(body)
		e := loginFailedAs(ln, model.TypeSSHInvalidUser, m[1], m[2], m[3], at, body)
		e.Severity = model.SeverityLow
		e.Attributes["invalid_user"] = "true"
		return e, StatusValid, ""

	case reMaxAttempts.MatchString(body):
		m := reMaxAttempts.FindStringSubmatch(body)
		e := loginFailed(ln, m[1], m[2], m[3], at, body)
		e.Severity = model.SeverityMedium
		e.Attributes["max_attempts_exceeded"] = "true"
		return e, StatusValid, ""

	case reDisconnect.MatchString(body):
		m := reDisconnect.FindStringSubmatch(body)
		e := baseEvent(ln, model.TypeSSHDisconnect, at, model.SeverityLow)
		setPeer(e, m[1], m[2])
		return e, StatusValid, ""

	case reSessionOpened.MatchString(body):
		m := reSessionOpened.FindStringSubmatch(body)
		e := baseEvent(ln, model.TypeSSHLoginSuccess, at, model.SeverityLow)
		e.Actor = m[1]
		e.Target = m[1]
		e.Outcome = model.OutcomeSuccess
		e.Attributes["session"] = "opened"
		return e, StatusValid, ""

	case reSessionClosed.MatchString(body):
		m := reSessionClosed.FindStringSubmatch(body)
		e := baseEvent(ln, model.TypeSSHDisconnect, at, model.SeverityLow)
		e.Actor = m[1]
		e.Attributes["session"] = "closed"
		return e, StatusValid, ""
	}

	// The record is a genuine sshd line we simply do not model yet. It is
	// reported as non-security-relevant rather than malformed so that parser
	// error metrics stay meaningful.
	return nil, StatusNonSecurityRelevant, "unmodeled sshd record"
}

// loginFailed builds a failed-authentication event.
//
// It is a pure function rather than a method because it reads nothing from the
// parser: making that explicit prevents a future field on SSHParser from
// silently becoming part of an event.
func loginFailed(ln Line, user, ip, port string, at time.Time, body string) *model.Event {
	return loginFailedAs(ln, model.TypeSSHLoginFailed, user, ip, port, at, body)
}

// loginFailedAs builds a failed-authentication event with an explicit type.
//
// The type is a parameter rather than a constant because the same failure shape
// covers more than one canonical event type: an authentication failure for a
// known account and an attempt for an account that does not exist are different
// signals, and collapsing them would lose the distinction a rule may want to
// match on.
func loginFailedAs(ln Line, t model.EventType, user, ip, port string, at time.Time, body string) *model.Event {
	e := sshEvent(ln, t, user, ip, port, at)
	e.Outcome = model.OutcomeFailure
	e.Severity = model.SeverityMedium
	e.Message = "SSH authentication failed"
	if strings.Contains(body, "invalid user") {
		e.Attributes["invalid_user"] = "true"
	}
	return e
}

// loginSucceeded builds a successful-authentication event, recording the key
// fingerprint when the source line carries one.
func loginSucceeded(ln Line, user, ip, port string, at time.Time, body string) *model.Event {
	e := sshEvent(ln, model.TypeSSHLoginSuccess, user, ip, port, at)
	e.Outcome = model.OutcomeSuccess
	e.Severity = model.SeverityLow
	e.Message = "SSH authentication succeeded"
	if i := strings.Index(body, "SHA256:"); i >= 0 {
		key := strings.Fields(body[i:])
		if len(key) > 0 {
			e.Attributes["key_fingerprint"] = strings.TrimSuffix(key[0], ",")
		}
	}
	return e
}

// sshEvent builds the common shape of an sshd authentication event.
func sshEvent(ln Line, t model.EventType, user, ip, port string, at time.Time) *model.Event {
	e := baseEvent(ln, t, at, model.SeverityMedium)
	e.Actor = user
	e.Target = user
	setPeer(e, ip, port)
	return e
}

// setPeer records a network peer, keeping unparseable values as attributes so
// they remain visible for investigation without becoming a correlation entity.
func setPeer(e *model.Event, ip, port string) {
	if addr, err := netip.ParseAddr(ip); err == nil {
		e.Network.SourceIP = addr.Unmap().String()
	} else if ip != "" {
		e.Attributes["unparsed_source"] = ip
	}
	if n, err := strconv.Atoi(port); err == nil && n > 0 && n <= 65535 {
		e.Network.SourcePort = n
	}
}
