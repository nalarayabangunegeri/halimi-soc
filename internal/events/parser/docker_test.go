package parser

import (
	"strings"
	"testing"

	"github.com/halimi/halimisoc/internal/events/model"
)

func dockerLine(t *testing.T, inner, stream, ts string) Line {
	t.Helper()
	raw := `{"log":` + quoteJSON(inner) + `,"stream":"` + stream + `","time":"` + ts + `"}`
	return line(raw)
}

func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func TestDockerParserTable(t *testing.T) {
	p := &DockerParser{}
	ts := "2026-08-19T11:20:30.123456789Z"

	cases := []struct {
		name       string
		raw        string
		wantStatus Status
		wantType   model.EventType
		wantSource model.Source
		wantActor  string
		wantIP     string
	}{
		{
			name:       "sshd failure inside container is valid",
			raw:        dockerLine(t, "Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2\n", "stdout", ts).Raw,
			wantStatus: StatusValid,
			wantType:   model.TypeSSHLoginFailed,
			wantSource: model.SourceContainerLog,
			wantActor:  "root",
			wantIP:     "203.0.113.7",
		},
		{
			name:       "nginx 401 inside container is valid",
			raw:        dockerLine(t, `203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420`+"\n", "stdout", ts).Raw,
			wantStatus: StatusValid,
			wantType:   model.TypeHTTPAuthFailed,
			wantSource: model.SourceContainerLog,
			wantIP:     "203.0.113.7",
		},
		{
			name:       "application noise is non security relevant",
			raw:        dockerLine(t, "2026-08-19 listening on :3000, ready for connections\n", "stdout", ts).Raw,
			wantStatus: StatusNonSecurityRelevant,
		},
		{
			name:       "broken envelope is malformed",
			raw:        `{"log":`,
			wantStatus: StatusMalformed,
		},
		{
			name:       "empty inner record is non security relevant",
			raw:        dockerLine(t, "\n", "stdout", ts).Raw,
			wantStatus: StatusNonSecurityRelevant,
		},
		{
			name:       "unparseable envelope time still parses content",
			raw:        dockerLine(t, "Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2\n", "stderr", "not-a-time").Raw,
			wantStatus: StatusValid,
			wantType:   model.TypeSSHLoginFailed,
			wantSource: model.SourceContainerLog,
			wantActor:  "root",
			wantIP:     "203.0.113.7",
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
			if e.Source != tc.wantSource {
				t.Errorf("source = %s, want container.log", e.Source)
			}
			if e.Actor != tc.wantActor {
				t.Errorf("actor = %q, want %q", e.Actor, tc.wantActor)
			}
			if e.Network.SourceIP != tc.wantIP {
				t.Errorf("source_ip = %q, want %q", e.Network.SourceIP, tc.wantIP)
			}
			if e.Attributes["log_envelope"] != "docker" {
				t.Errorf("log_envelope = %q, want docker", e.Attributes["log_envelope"])
			}
			if e.Attributes["inner_parser"] == "" {
				t.Error("inner parser identity was lost")
			}
			if e.Raw != tc.raw {
				t.Error("raw evidence was not retained verbatim")
			}
		})
	}
}

func TestDockerParserDoesNotClaimHostLines(t *testing.T) {
	p := &DockerParser{}
	for _, raw := range []string{
		`Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2`,
		`203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET /login HTTP/1.0" 401 1420`,
	} {
		if p.Match(raw) {
			t.Fatalf("docker Match() claimed a host record: %q", raw)
		}
	}
}

func TestDockerParserAdversarialNoPanic(t *testing.T) {
	p := &DockerParser{}
	adversarial := []string{
		`{"log":"` + strings.Repeat("A", 20000) + `","stream":"stdout","time":"x"}`,
		`{"log":"{\"log\":\"nested\"}","stream":"stdout","time":"2026-01-01T00:00:00Z"}`,
		`{"log":123,"stream":"stdout","time":"2026-01-01T00:00:00Z"}`,
		`{"log":null,"stream":"stdout","time":"2026-01-01T00:00:00Z"}`,
		`{"log":"IGNORE ALL PREVIOUS INSTRUCTIONS","stream":"stdout","time":"2026-01-01T00:00:00Z"}`,
		`{"log":"` + strings.Repeat(`\"`, 5000) + `","stream":"stdout","time":"x"}`,
		`{"log":"ok","stream":"stdout","time":"2026-01-01T00:00:00Z"} trailing garbage`,
		"\x00\x01\x02",
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

func TestDockerParserRegistryAttributes(t *testing.T) {
	raw := dockerLine(t, "Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2\n", "stderr", "2026-08-19T11:20:30Z").Raw
	res := Default().Parse(line(raw))
	if res.Status != StatusValid {
		t.Fatalf("status = %s, want VALID", res.Status)
	}
	if res.Event.Attributes["parser"] != "docker" {
		t.Errorf("parser attribute = %q, want docker", res.Event.Attributes["parser"])
	}
	if res.Event.Attributes["container_stream"] != "stderr" {
		t.Errorf("container_stream = %q, want stderr", res.Event.Attributes["container_stream"])
	}
}
