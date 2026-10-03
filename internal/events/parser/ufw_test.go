package parser

import (
	"strings"
	"testing"

	"github.com/halimi/halimisoc/internal/events/model"
)

const ufwBlockLine = `Oct  3 12:00:00 web-01 kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.7 DST=10.0.0.5 LEN=60 TOS=0x00 PREC=0x00 TTL=64 PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0`

func TestUFWParserTable(t *testing.T) {
	p := &UFWParser{}

	cases := []struct {
		name       string
		raw        string
		wantStatus Status
		wantIP     string
		wantDst    string
		wantDPort  int
		wantProto  string
	}{
		{
			name:       "UFW block is valid",
			raw:        ufwBlockLine,
			wantStatus: StatusValid,
			wantIP:     "203.0.113.7",
			wantDst:    "10.0.0.5",
			wantDPort:  22,
			wantProto:  "tcp",
		},
		{
			name:       "UDP block records protocol",
			raw:        `Oct  3 12:01:00 web-01 kernel: [12346.1] [UFW BLOCK] IN=eth0 SRC=198.51.100.9 DST=10.0.0.5 PROTO=UDP SPT=53 DPT=5353 LEN=100`,
			wantStatus: StatusValid,
			wantIP:     "198.51.100.9",
			wantDst:    "10.0.0.5",
			wantDPort:  5353,
			wantProto:  "udp",
		},
		{
			name:       "block without endpoints is incomplete",
			raw:        `Oct  3 12:02:00 web-01 kernel: [12347.1] [UFW BLOCK] IN=eth0 PROTO=TCP SPT=1 DPT=2 LEN=10`,
			wantStatus: StatusIncomplete,
		},
		{
			name:       "allow record is not an event",
			raw:        `Oct  3 12:03:00 web-01 kernel: [12348.1] [UFW ALLOW] IN=eth0 SRC=203.0.113.7 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=80 LEN=10`,
			wantStatus: StatusUnsupported,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantStatus == StatusValid && !p.Match(tc.raw) {
				t.Fatal("Match() = false, want true")
			}
			// Match must not claim non-kernel lines even when the marker is
			// quoted inside them.
			res := p.Parse(line(tc.raw))
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %s (%s), want %s", res.Status, res.Reason, tc.wantStatus)
			}
			if tc.wantStatus != StatusValid {
				return
			}
			e := res.Event
			if e.Type != model.TypeFirewallBlock {
				t.Errorf("type = %s, want network.firewall.block", e.Type)
			}
			if e.Network.SourceIP != tc.wantIP {
				t.Errorf("source_ip = %q, want %q", e.Network.SourceIP, tc.wantIP)
			}
			if e.Network.DestIP != tc.wantDst {
				t.Errorf("dest_ip = %q, want %q", e.Network.DestIP, tc.wantDst)
			}
			if e.Network.DestPort != tc.wantDPort {
				t.Errorf("dest_port = %d, want %d", e.Network.DestPort, tc.wantDPort)
			}
			if e.Network.Protocol != tc.wantProto {
				t.Errorf("protocol = %q, want %q", e.Network.Protocol, tc.wantProto)
			}
			if e.Attributes["firewall_action"] != "block" {
				t.Errorf("firewall_action = %q, want block", e.Attributes["firewall_action"])
			}
			if e.Source != model.SourceSyslog {
				t.Errorf("source = %s, want syslog", e.Source)
			}
			if e.Raw != tc.raw {
				t.Error("raw evidence was not retained verbatim")
			}
		})
	}
}

func TestUFWParserMatchRequiresKernelProgram(t *testing.T) {
	p := &UFWParser{}
	// The marker quoted inside an sshd record must not reroute it.
	raw := `Aug 19 11:20:30 web-01 sshd[1823]: Failed password for root from 203.0.113.7 port 51022 ssh2 [UFW BLOCK]`
	if p.Match(raw) {
		t.Fatal("ufw Match() claimed a non-kernel record")
	}
	if res := Default().Parse(line(raw)); res.Status != StatusValid || res.Event.Type != model.TypeSSHLoginFailed {
		t.Fatalf("registry misrouted a marked sshd record: %+v", res)
	}
}

func TestUFWParserAdversarialNoPanic(t *testing.T) {
	p := &UFWParser{}
	adversarial := []string{
		`Oct  3 12:00:00 h kernel: [UFW BLOCK] ` + strings.Repeat("SRC=1.2.3.4 ", 2000),
		`Oct  3 12:00:00 h kernel: [UFW BLOCK] SRC= DST= PROTO= SPT= DPT=`,
		`Oct  3 12:00:00 h kernel: [UFW BLOCK] SRC=999.999.999.999 DST=::ffff:1.2.3.4 PROTO=TCP SPT=99999 DPT=-1`,
		"[UFW BLOCK]",
		"kernel: [UFW BLOCK]",
		"\x00[UFW BLOCK]\x00",
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
