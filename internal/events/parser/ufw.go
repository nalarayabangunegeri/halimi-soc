package parser

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/halimi/halimisoc/internal/events/model"
)

// UFWParser parses kernel firewall block records from syslog:
//
//	Oct  3 12:00:00 host kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= ... SRC=203.0.113.7 DST=10.0.0.5 ... PROTO=TCP SPT=51234 DPT=22 ...
//
// Only BLOCK records become events. ALLOW records describe permitted traffic
// and would turn every accepted connection into stored telemetry. Other
// firewall drivers (plain iptables, nftables without the UFW prefix) are out
// of scope and reported as unsupported rather than guessed at.
type UFWParser struct{}

// Name implements Parser.
func (p *UFWParser) Name() string { return "ufw" }

var (
	// Flat field extractors rather than one nested pattern: each matches a
	// single KEY=value token, so matching stays linear and a reordered or
	// abbreviated kernel line still parses the fields it carries.
	reUFWSrc   = regexp.MustCompile(`\bSRC=(\S+)`)
	reUFWDst   = regexp.MustCompile(`\bDST=(\S+)`)
	reUFWProto = regexp.MustCompile(`\bPROTO=([A-Za-z]+)`)
	reUFWSpt   = regexp.MustCompile(`\bSPT=(\d{1,5})`)
	reUFWDpt   = regexp.MustCompile(`\bDPT=(\d{1,5})`)
)

// Match implements Parser. Both conditions are required: the UFW marker alone
// could appear quoted inside an unrelated record, and the program check alone
// would claim every kernel line.
func (p *UFWParser) Match(raw string) bool {
	if !strings.Contains(raw, "[UFW BLOCK]") {
		return false
	}
	_, _, msg := splitSyslogPrefix(raw)
	program, _, _ := splitProgram(msg)
	return program == "kernel"
}

// Parse implements Parser.
func (p *UFWParser) Parse(l Line) Result {
	if !strings.Contains(l.Raw, "[UFW BLOCK]") {
		// Reached directly rather than through Match: only block records are
		// actionable, and an allow record must never become an event.
		return Result{Status: StatusUnsupported, Reason: "not a firewall block record"}
	}
	ts, _, msg := splitSyslogPrefix(l.Raw)
	_, _, body := splitProgram(msg)

	src := firstGroup(reUFWSrc, body)
	dst := firstGroup(reUFWDst, body)
	if src == "" || dst == "" {
		// A block record without both endpoints cannot be attributed to an
		// attacker or a target, so it is not actionable telemetry.
		return Result{Status: StatusIncomplete, Reason: "firewall block without endpoints"}
	}

	at, ok := ParseTime(ts, l.ObservedAt)
	if !ok {
		at = l.ObservedAt
	}

	e := baseEvent(l, model.TypeFirewallBlock, at, model.SeverityLow)
	e.Source = model.SourceSyslog
	e.Outcome = model.OutcomeUnknown
	if addr, err := netip.ParseAddr(src); err == nil {
		e.Network.SourceIP = addr.Unmap().String()
	} else {
		e.Attributes["unparsed_source"] = src
	}
	if addr, err := netip.ParseAddr(dst); err == nil {
		e.Network.DestIP = addr.Unmap().String()
	}
	if proto := firstGroup(reUFWProto, body); proto != "" {
		e.Network.Protocol = strings.ToLower(proto)
		e.Attributes["firewall_proto"] = strings.ToUpper(proto)
	}
	if spt := firstGroup(reUFWSpt, body); spt != "" {
		if n, err := strconv.Atoi(spt); err == nil && n <= 65535 {
			e.Network.SourcePort = n
		}
	}
	if dpt := firstGroup(reUFWDpt, body); dpt != "" {
		if n, err := strconv.Atoi(dpt); err == nil && n <= 65535 {
			e.Network.DestPort = n
			e.Attributes["firewall_dport"] = dpt
		}
	}
	e.Attributes["firewall_action"] = "block"
	if !ok {
		e.Attributes["timestamp_source"] = "observed"
	}
	e.Message = "Firewall blocked inbound packet"
	return Result{Status: StatusValid, Event: e}
}

// firstGroup returns the first capture group of the first match, or "".
func firstGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}
