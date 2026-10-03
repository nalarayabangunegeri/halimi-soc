package parser

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// NginxParser parses nginx HTTP access log records in the combined (or common)
// log format.
//
// Only authentication failures (401/403) become canonical events: a successful
// request carries no authentication signal worth persisting per-request, and
// emitting an event per 200 response would turn normal traffic into a
// self-inflicted load spike. Everything else is NON_SECURITY_RELEVANT rather
// than MALFORMED so parser error metrics keep meaning "the parser is broken",
// not "the site serves traffic".
type NginxParser struct{}

// Name implements Parser.
func (p *NginxParser) Name() string { return "nginx" }

var (
	// Combined log format, with the referrer and user-agent quoted fields
	// optional so the common format parses too:
	//
	//   203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420
	//
	// Character classes are negated ([^"]*, [^\]]*) rather than nested, so
	// matching stays linear in input length even on hostile input.
	reNginxCombined = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]+) ([^"]*?) (HTTP/[0-9.]+)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?\s*$`)

	// reNginxMethod is the cheap pre-filter for Match: it must be specific
	// enough not to claim sshd/sudo records, which never contain a quoted
	// HTTP request line.
	reNginxMethod = regexp.MustCompile(`"[A-Z]+ [^"]* HTTP/[0-9.]+"`)
)

// nginxTimeLayout is the access log timestamp: 10/Oct/2000:13:55:36 -0700.
const nginxTimeLayout = "02/Jan/2006:15:04:05 -0700"

// Match implements Parser.
func (p *NginxParser) Match(raw string) bool {
	return reNginxMethod.MatchString(raw)
}

// Parse implements Parser.
func (p *NginxParser) Parse(l Line) Result {
	m := reNginxCombined.FindStringSubmatch(strings.TrimRight(l.Raw, "\r\n"))
	if m == nil {
		// The line advertises an HTTP request but does not fit the access log
		// shape. It is malformed rather than unsupported so the operator can
		// see a format drift instead of silent silence.
		return Result{Status: StatusMalformed, Reason: "unparseable http access record"}
	}
	ip, user, ts, method, target, proto, status, size := m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]

	code, err := strconv.Atoi(status)
	if err != nil || code < 100 || code > 599 {
		return Result{Status: StatusMalformed, Reason: "invalid http status"}
	}
	if code != 401 && code != 403 {
		return Result{Status: StatusNonSecurityRelevant, Reason: "http status is not an authentication failure"}
	}

	at, err := time.Parse(nginxTimeLayout, ts)
	parsed := err == nil
	if !parsed {
		at = l.ObservedAt
	}
	at = at.UTC()

	e := baseEvent(l, model.TypeHTTPAuthFailed, at, model.SeverityMedium)
	e.Source = model.SourceHTTPAccess
	e.Outcome = model.OutcomeFailure
	if user != "" && user != "-" {
		e.Actor = user
		e.Target = user
	}
	if addr, err := netip.ParseAddr(ip); err == nil {
		e.Network.SourceIP = addr.Unmap().String()
	} else if ip != "" && ip != "-" {
		e.Attributes["unparsed_source"] = ip
	}
	e.Attributes["http_method"] = method
	e.Attributes["http_status"] = status
	e.Attributes["http_proto"] = proto
	if path := strings.Fields(target); len(path) > 0 {
		// Only the path's first token is kept: the request target is a single
		// token, and anything beyond it is not part of the resource identity.
		e.Attributes["http_path"] = path[0]
	} else {
		e.Attributes["http_path"] = target
	}
	if size != "" && size != "-" {
		e.Attributes["http_bytes"] = size
	}
	if !parsed {
		e.Attributes["timestamp_source"] = "observed"
	}
	e.Message = "HTTP authentication failed"
	return Result{Status: StatusValid, Event: e}
}
