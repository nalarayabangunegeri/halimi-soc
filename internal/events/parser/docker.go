package parser

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/events/model"
)

// DockerParser parses container stdout/stderr collected from the Docker
// json-file log driver:
//
//	{"log":"Aug 19 11:20:30 web-01 sshd[1823]: Failed password ...\n","stream":"stdout","time":"2026-08-19T11:20:30.123456789Z"}
//
// The envelope is stripped and the inner line is parsed by the same registry
// as host telemetry, so container activity produces the same canonical event
// types and the same detection rules apply inside containers without a second
// rule set. The inner registry deliberately excludes this parser: a Docker
// envelope inside a Docker envelope is not a format the driver produces, and
// recursing on it would let a hostile container line nest without bound.
type DockerParser struct {
	inner *Registry
}

// Name implements Parser.
func (p *DockerParser) Name() string { return "docker" }

// dockerEnvelope is the json-file log record. Only the fields the pipeline
// needs are decoded; driver metadata such as attrs is ignored.
type dockerEnvelope struct {
	Log    string `json:"log"`
	Stream string `json:"stream"`
	Time   string `json:"time"`
}

// Match implements Parser. The prefix check is cheap and specific: no host
// syslog or nginx record starts with a {"log": object.
func (p *DockerParser) Match(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), `{"log":`)
}

// Parse implements Parser.
func (p *DockerParser) Parse(l Line) Result {
	var env dockerEnvelope
	if err := json.Unmarshal([]byte(strings.TrimSpace(l.Raw)), &env); err != nil {
		// The line advertises the Docker envelope but is not one. Malformed,
		// not unsupported, so a driver format drift is visible in parser
		// error metrics instead of vanishing silently.
		return Result{Status: StatusMalformed, Reason: "unparseable docker log envelope"}
	}

	inner := strings.TrimRight(env.Log, "\r\n")
	if strings.TrimSpace(inner) == "" {
		return Result{Status: StatusNonSecurityRelevant, Reason: "empty container record"}
	}

	reg := p.inner
	if reg == nil {
		reg = innerRegistry()
	}
	res := reg.Parse(Line{
		Raw:        inner,
		Host:       l.Host,
		AgentID:    l.AgentID,
		SourcePath: l.SourcePath,
		ObservedAt: l.ObservedAt,
	})
	if res.Status != StatusValid || res.Event == nil {
		// Container stdout is mostly application noise. Only lines with a
		// security signal become events; the rest must not become load.
		return Result{Status: StatusNonSecurityRelevant, Reason: "no security signal in container record"}
	}

	e := res.Event
	e.Source = model.SourceContainerLog
	// Raw evidence is the envelope exactly as read: it carries the stream and
	// driver timestamp alongside the content, which is what an analyst needs
	// to trust where the record came from.
	e.Raw = l.Raw
	if e.Attributes == nil {
		e.Attributes = map[string]string{}
	}
	// The outer registry stamps parser=docker on return. Keep the inner
	// parser identity under its own key so an analyst can see both the
	// envelope and the content parser that classified the record.
	if inner, ok := e.Attributes["parser"]; ok && inner != "" {
		e.Attributes["inner_parser"] = inner
	}
	if env.Stream != "" {
		e.Attributes["container_stream"] = env.Stream
	}
	e.Attributes["log_envelope"] = "docker"
	if env.Time != "" {
		if at, err := time.Parse(time.RFC3339Nano, env.Time); err == nil {
			e.Time = at.UTC()
		}
	}
	return Result{Status: StatusValid, Event: e}
}

// innerRegistry is the delegate set for container log content. DockerParser is
// excluded so envelope nesting cannot recurse.
func innerRegistry() *Registry {
	return NewRegistry(
		&NginxParser{},
		&SudoParser{},
		&AuthorizedKeysParser{},
		&SSHParser{},
	)
}
