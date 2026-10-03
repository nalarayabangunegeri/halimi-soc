package parser

import (
	"strings"
	"time"
)

// syslogLayouts are the timestamp layouts found in the supported log sources.
//
// Classic syslog omits the year, so the year is inferred from a reference time
// (see inferYear). The underscore layout handles the space-padded day used by
// BSD syslog ("Aug  9" rather than "Aug 9").
var syslogLayouts = []string{
	"Jan _2 15:04:05",
	"Jan 2 15:04:05",
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05",
}

// ParseTime parses the leading timestamp of a syslog record.
//
// ref supplies the year for year-less layouts and the rollover boundary.
// When no layout matches, ok is false and the caller must fall back to the
// agent observation time rather than discarding the record: a security event
// with a surprising timestamp is still evidence.
func ParseTime(s string, ref time.Time) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	ref = ref.UTC()

	for _, layout := range syslogLayouts {
		t, err := time.Parse(layout, s)
		if err != nil {
			continue
		}
		if hasYear(layout) {
			return t.UTC(), true
		}
		return inferYear(t, ref), true
	}
	return time.Time{}, false
}

func hasYear(layout string) bool {
	return strings.Contains(layout, "2006")
}

// inferYear assigns a year to a year-less syslog timestamp.
//
// Syslog records only month, day and time. A log written just before midnight
// on 31 December is read on 1 January, so naively using the reference year
// would place the record up to a year in the future and trip the clock-skew
// guard. Any candidate more than 24h ahead of the reference is therefore
// assumed to belong to the previous year.
func inferYear(t time.Time, ref time.Time) time.Time {
	candidate := time.Date(ref.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
	if candidate.After(ref.Add(24 * time.Hour)) {
		candidate = candidate.AddDate(-1, 0, 0)
	}
	return candidate
}

// splitSyslogPrefix separates the leading syslog header from the message.
//
// A Debian-style record looks like:
//
//	Aug 19 11:20:30 server-01 sshd[1823]: Failed password for root ...
//
// The returned values are the timestamp text, the hostname text (possibly
// empty) and the message. It never fails: a record without a recognizable
// header is returned whole as the message, because dropping it would lose
// evidence.
func splitSyslogPrefix(raw string) (ts, host, msg string) {
	rest := raw

	// Timestamp occupies at most 15 characters ("Aug 19 11:20:30").
	if len(rest) >= 15 {
		head := rest[:15]
		if _, ok := ParseTime(head, time.Unix(0, 0)); ok {
			ts = strings.TrimSpace(head)
			rest = strings.TrimLeft(rest[15:], " ")
		}
	}

	// Optional hostname: the next whitespace-delimited token, when it is not
	// the start of a "program[pid]:" header.
	if i := strings.IndexByte(rest, ' '); i > 0 {
		candidate := rest[:i]
		if !strings.Contains(candidate, ":") && !strings.Contains(candidate, "[") {
			host = candidate
			rest = strings.TrimLeft(rest[i+1:], " ")
		}
	}
	return ts, host, rest
}

// splitProgram splits a "program[pid]: message" header.
func splitProgram(s string) (program, pid, msg string) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", s
	}
	head := s[:i]
	msg = strings.TrimLeft(s[i+1:], " ")

	if j := strings.IndexByte(head, '['); j >= 0 {
		program = head[:j]
		pid = strings.TrimSuffix(head[j+1:], "]")
	} else {
		program = head
	}
	return program, pid, msg
}
