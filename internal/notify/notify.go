// Package notify delivers incident webhooks to an operator-configured URL.
//
// Delivery is advisory and never on the ingestion path: events are enqueued
// without blocking, a bounded worker sends them with a timeout, and every
// failure mode ends in a metric rather than an error surfaced to ingestion.
// A notification outage must look like a notification outage, not a product
// outage — the same principle that governs the AI analyst.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/incidents"
	"github.com/halimi/halimisoc/internal/metrics"
)

// Options configures the notifier.
type Options struct {
	// URL is the webhook endpoint. Empty disables delivery entirely.
	URL string

	// Timeout bounds a single delivery attempt.
	Timeout time.Duration

	// QueueSize bounds pending notifications. When full, Notify drops and
	// counts rather than blocking the caller.
	QueueSize int

	// Secret signs the body with HMAC-SHA256 when set. The receiver verifies
	// X-HalimiSOC-Signature to distinguish our POST from a spoof. Empty
	// disables signing; production deployments should set ≥16 chars.
	Secret string

	// Registry receives sent/error counters. Nil disables metrics.
	Registry *metrics.Registry
}

// DefaultOptions returns safe defaults.
func DefaultOptions() Options {
	return Options{
		Timeout:   5 * time.Second,
		QueueSize: 64,
	}
}

// Validate rejects an unusable configuration at startup rather than
// discovering it on the first incident.
func (o Options) Validate() error {
	if o.URL == "" {
		return nil
	}
	u, err := url.Parse(o.URL)
	if err != nil {
		return fmt.Errorf("notify: invalid webhook url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("notify: webhook url scheme must be http or https")
	}
	if u.User != nil {
		// Credentials in a URL end up in logs, dashboards and error messages.
		// A bearer token belongs in a header the operator controls, not in an
		// address the server is told to call.
		return fmt.Errorf("notify: webhook url must not embed credentials")
	}
	if isCloudMetadataHost(u.Hostname()) {
		return fmt.Errorf("notify: webhook url must not target cloud metadata")
	}
	if o.Secret != "" && len(o.Secret) < 16 {
		return fmt.Errorf("notify: webhook secret must be at least 16 characters")
	}
	if o.Timeout <= 0 {
		return fmt.Errorf("notify: timeout must be positive")
	}
	if o.QueueSize <= 0 {
		return fmt.Errorf("notify: queue size must be positive")
	}
	return nil
}

// isCloudMetadataHost blocks the well-known cloud metadata endpoints that turn
// a webhook URL into a credential-theft SSRF. Private intranet hosts are still
// allowed (e.g. an internal alertmanager) — the operator chose the URL — but
// metadata endpoints are never a legitimate incident receiver.
func isCloudMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "169.254.169.254", "169.254.169.253", "metadata.google.internal", "metadata.google", "metadata":
		return true
	}
	return false
}

// SignBody returns the hex HMAC-SHA256 of body under secret.
func SignBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature compares a presented hex signature in constant time.
func VerifySignature(secret string, body []byte, presented string) bool {
	want := SignBody(secret, body)
	if len(presented) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(want)) == 1
}

// Payload is the fixed webhook body.
//
// It carries incident identity and scope, never raw evidence: the endpoint is
// operator-chosen but still a third party, and raw log lines routinely contain
// usernames, paths and command lines that have no business leaving the
// platform on every incident.
type Payload struct {
	Event    string       `json:"event"`
	Incident IncidentView `json:"incident"`
	SentAt   time.Time    `json:"sent_at"`
}

// IncidentView is the notifier's projection of an incident.
type IncidentView struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Hosts     []string  `json:"hosts"`
	Actors    []string  `json:"actors"`
	SourceIPs []string  `json:"source_ips"`
	Alerts    int       `json:"alerts"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Notifier queues incident notifications and delivers them in the background.
type Notifier struct {
	opts   Options
	client *http.Client
	queue  chan Payload
	reg    *metrics.Registry
	now    func() time.Time
}

// New builds a notifier. A nil registry disables metrics; an empty URL
// disables delivery, in which case Notify is a cheap no-op.
func New(opts Options) *Notifier {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = DefaultOptions().QueueSize
	}
	return &Notifier{
		opts: opts,
		client: &http.Client{
			Timeout: opts.Timeout,
			// Redirects are refused so a 302 cannot reroute the payload to a
			// host the operator did not configure.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		queue: make(chan Payload, opts.QueueSize),
		reg:   opts.Registry,
		now:   func() time.Time { return time.Now().UTC() },
	}
}

// Enabled reports whether delivery is configured.
func (n *Notifier) Enabled() bool { return n != nil && n.opts.URL != "" }

// SetClock overrides the clock. Test-only.
func (n *Notifier) SetClock(f func() time.Time) { n.now = f }

// SetRegistry attaches the metrics registry after construction, so callers
// that build the registry after the notifier do not need a cycle.
func (n *Notifier) SetRegistry(reg *metrics.Registry) { n.reg = reg }

// NotifyIncident queues an incident-created notification. It never blocks:
// a full queue drops the notification and counts it, because stalling
// ingestion behind a slow webhook would turn a notification outage into a
// telemetry outage.
func (n *Notifier) NotifyIncident(inc *incidents.Incident) {
	if n == nil || !n.Enabled() || inc == nil {
		return
	}
	p := Payload{
		Event: "incident.created",
		Incident: IncidentView{
			ID:        inc.ID,
			Title:     inc.Title,
			Severity:  string(inc.Severity),
			Status:    string(inc.Status),
			Hosts:     append([]string(nil), inc.Hosts...),
			Actors:    append([]string(nil), inc.Actors...),
			SourceIPs: append([]string(nil), inc.SourceIPs...),
			Alerts:    len(inc.AlertIDs),
			FirstSeen: inc.FirstSeen,
			LastSeen:  inc.LastSeen,
		},
		SentAt: n.now(),
	}
	select {
	case n.queue <- p:
	default:
		n.inc(metrics.WebhookDroppedTotal)
	}
}

// Run delivers queued notifications until ctx is done. One worker is enough:
// incident creation is rare relative to events, and a single sender keeps
// delivery order stable.
func (n *Notifier) Run(ctx context.Context) {
	if n == nil || !n.Enabled() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-n.queue:
			n.send(ctx, p)
		}
	}
}

func (n *Notifier) send(ctx context.Context, p Payload) {
	body, err := json.Marshal(p)
	if err != nil {
		n.inc(metrics.WebhookErrorTotal)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.opts.URL, bytes.NewReader(body))
	if err != nil {
		n.inc(metrics.WebhookErrorTotal)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "halimisoc-webhook/1")
	if n.opts.Secret != "" {
		req.Header.Set("X-HalimiSOC-Signature", "sha256="+SignBody(n.opts.Secret, body))
	}

	resp, err := n.client.Do(req)
	if err != nil {
		n.inc(metrics.WebhookErrorTotal)
		return
	}
	// The response body is drained to a small bound and discarded: the
	// endpoint's reply is not trusted input and must not accumulate.
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		n.inc(metrics.WebhookErrorTotal)
		return
	}
	n.inc(metrics.WebhookSentTotal)
}

func (n *Notifier) inc(name string) {
	if n.reg != nil {
		n.reg.Inc(name)
	}
}
