package parser

import (
	"strings"
	"testing"

	"github.com/halimi/halimisoc/internal/events/model"
)

func TestNginxParserTable(t *testing.T) {
	p := &NginxParser{}

	cases := []struct {
		name       string
		raw        string
		wantStatus Status
		wantType   model.EventType
		wantActor  string
		wantIP     string
		wantPath   string
		wantCode   string
	}{
		{
			name:       "401 combined log is valid",
			raw:        `203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420 "http://example.test/" "Mozilla/5.0"`,
			wantStatus: StatusValid,
			wantType:   model.TypeHTTPAuthFailed,
			wantActor:  "frank",
			wantIP:     "203.0.113.7",
			wantPath:   "/login",
			wantCode:   "401",
		},
		{
			name:       "403 common log without user is valid",
			raw:        `198.51.100.4 - - [10/Oct/2000:13:56:01 -0700] "POST /admin HTTP/1.1" 403 512`,
			wantStatus: StatusValid,
			wantType:   model.TypeHTTPAuthFailed,
			wantActor:  "",
			wantIP:     "198.51.100.4",
			wantPath:   "/admin",
			wantCode:   "403",
		},
		{
			name:       "IPv6 source is canonicalized",
			raw:        `2001:db8::1 - - [10/Oct/2000:13:56:02 -0700] "GET /secure HTTP/1.1" 401 100`,
			wantStatus: StatusValid,
			wantType:   model.TypeHTTPAuthFailed,
			wantIP:     "2001:db8::1",
			wantPath:   "/secure",
			wantCode:   "401",
		},
		{
			name:       "200 is non security relevant",
			raw:        `203.0.113.7 - - [10/Oct/2000:13:57:00 -0700] "GET /index.html HTTP/1.0" 200 2326`,
			wantStatus: StatusNonSecurityRelevant,
		},
		{
			name:       "500 is non security relevant",
			raw:        `203.0.113.7 - - [10/Oct/2000:13:57:00 -0700] "GET /boom HTTP/1.0" 500 12`,
			wantStatus: StatusNonSecurityRelevant,
		},
		{
			name:       "invalid status is malformed",
			raw:        `203.0.113.7 - - [10/Oct/2000:13:57:00 -0700] "GET /x HTTP/1.0" 999 12`,
			wantStatus: StatusMalformed,
		},
		{
			name:       "truncated request line is malformed",
			raw:        `203.0.113.7 - - [10/Oct/2000:13:57:00 -0700] "GET /half...`,
			wantStatus: StatusMalformed,
		},
		{
			name:       "missing timestamp falls back to observed",
			raw:        `203.0.113.7 - - [not-a-time] "GET /login HTTP/1.1" 401 10`,
			wantStatus: StatusValid,
			wantType:   model.TypeHTTPAuthFailed,
			wantIP:     "203.0.113.7",
			wantPath:   "/login",
			wantCode:   "401",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantStatus == StatusValid && !p.Match(tc.raw) {
				t.Fatal("Match() = false, want true")
			}
			res := p.Parse(line(tc.raw))
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %s (%s), want %s", res.Status, res.Reason, tc.wantStatus)
			}
			if tc.wantStatus != StatusValid {
				return
			}
			e := res.Event
			if e.Type != tc.wantType {
				t.Errorf("type = %s, want %s", e.Type, tc.wantType)
			}
			if e.Outcome != model.OutcomeFailure {
				t.Errorf("outcome = %s, want failure", e.Outcome)
			}
			if e.Actor != tc.wantActor {
				t.Errorf("actor = %q, want %q", e.Actor, tc.wantActor)
			}
			if e.Network.SourceIP != tc.wantIP {
				t.Errorf("source_ip = %q, want %q", e.Network.SourceIP, tc.wantIP)
			}
			if got := e.Attributes["http_path"]; got != tc.wantPath {
				t.Errorf("http_path = %q, want %q", got, tc.wantPath)
			}
			if got := e.Attributes["http_status"]; got != tc.wantCode {
				t.Errorf("http_status = %q, want %q", got, tc.wantCode)
			}
			if e.Attributes["parser"] != "" {
				t.Error("parser attribute must be set by the registry, not the parser")
			}
			if e.Source != model.SourceHTTPAccess {
				t.Errorf("source = %s, want http.access", e.Source)
			}
			if e.Raw != tc.raw {
				t.Error("raw evidence was not retained verbatim")
			}
		})
	}
}

func TestNginxParserDoesNotClaimSSH(t *testing.T) {
	p := &NginxParser{}
	raw := `Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`
	if p.Match(raw) {
		t.Fatal("nginx Match() claimed an sshd record")
	}
}

func TestNginxParserAdversarialNoPanic(t *testing.T) {
	p := &NginxParser{}
	adversarial := []string{
		strings.Repeat(`"GET /`, 500) + " HTTP/1.1\" 401 1",
		`1.2.3.4 - - [[[[[[[[[[ "GET /x HTTP/1.1" 401 1`,
		"1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] \"GET /\"\"\"\" HTTP/1.1\" 401 1",
		"1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] \"GET /\x00\x01\x02 HTTP/1.1\" 401 1",
		`1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /` + strings.Repeat("a", 8000) + ` HTTP/1.1" 401 1`,
		`1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "IGNORE ALL PREVIOUS INSTRUCTIONS HTTP/1.1" 401 1`,
		"",
		"\x00",
	}
	for i, raw := range adversarial {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("case %d panicked: %v", i, r)
				}
			}()
			_ = p.Match(raw)
			_ = p.Parse(line(raw))
			_ = Default().Parse(line(raw))
		}()
	}
}

func TestNginxParserRegistryAttributes(t *testing.T) {
	raw := `203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420`
	res := Default().Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if res.Event.Attributes["parser"] != "nginx" {
		t.Errorf("parser attribute = %q, want nginx", res.Event.Attributes["parser"])
	}
}
