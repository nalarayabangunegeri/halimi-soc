package parser

import (
	"testing"
	"time"
)

// FuzzRegistryParse feeds arbitrary input through the full parser registry.
//
// The invariant is totality: no input, however hostile, may panic the parser
// or the process. A malformed record must come back as a classification, never
// as a crash, because the input is attacker-controlled log data.
func FuzzRegistryParse(f *testing.F) {
	seeds := []string{
		`Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`,
		`Aug 19 11:22:01 web-01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id`,
		`203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420`,
		`198.51.100.4 - - [10/Oct/2000:13:56:01 -0700] "POST /admin HTTP/1.1" 403 512`,
		`{"log":"Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2\n","stream":"stdout","time":"2026-08-19T11:20:30.123456789Z"}`,
		`Oct  3 12:00:00 web-01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 SRC=203.0.113.7 DST=10.0.0.5 PROTO=TCP SPT=51234 DPT=22 LEN=60`,
		"",
		"\x00\x01\x02",
		`Aug 19 11:20:30 web-01 sshd[1823]: `,
		`"GET /x HTTP/1.1" 999 1`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	ref := time.Date(2025, 8, 19, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, raw string) {
		l := Line{
			Raw:        raw,
			Host:       "fuzz-host",
			AgentID:    "agt_fuzz",
			SourcePath: "fuzz.log",
			ObservedAt: ref,
		}
		res := Default().Parse(l)
		switch res.Status {
		case StatusValid:
			if res.Event == nil {
				t.Fatal("VALID result with nil event")
			}
			if res.Event.Raw != l.Raw {
				t.Fatal("parser rewrote its raw evidence")
			}
		case StatusMalformed, StatusUnsupported, StatusIncomplete, StatusNonSecurityRelevant:
			if res.Event != nil {
				t.Fatalf("%s result with non-nil event", res.Status)
			}
		default:
			t.Fatalf("unknown parser status %q", res.Status)
		}
	})
}
