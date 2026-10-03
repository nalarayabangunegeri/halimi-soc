package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/halimi/halimisoc/internal/notify"
)

// Load reads configuration from the environment.
//
// Every value has a safe default, so an unconfigured process starts in a
// bounded, non-production mode rather than an unbounded one.
func Load() (*Config, error) {
	c := &Config{
		Environment:       env("HALIMISOC_ENV", "development"),
		ListenAddr:        env("HALIMISOC_LISTEN_ADDR", "127.0.0.1:8080"),
		DatabaseURL:       os.Getenv("HALIMISOC_DATABASE_URL"),
		Retention:         LimitsFromEnv(),
		SessionTTL:        envSeconds("HALIMISOC_SESSION_TTL", 12*time.Hour),
		ClockSkew:         envSeconds("HALIMISOC_CLOCK_SKEW", 5*time.Minute),
		RulesPath:         env("HALIMISOC_RULES_PATH", "rules"),
		AdminUser:         env("HALIMISOC_ADMIN_USER", "admin"),
		AdminPassword:     os.Getenv("HALIMISOC_ADMIN_PASSWORD"),
		AgentEnrollSecret: os.Getenv("HALIMISOC_AGENT_ENROLL_SECRET"),
		AIBaseURL:         strings.TrimSpace(os.Getenv("HALIMISOC_AI_BASE_URL")),
		AIAPIKey:          strings.TrimSpace(os.Getenv("HALIMISOC_AI_API_KEY")),
		AIModel:           strings.TrimSpace(os.Getenv("HALIMISOC_AI_MODEL")),
		WebhookURL:        strings.TrimSpace(os.Getenv("HALIMISOC_WEBHOOK_URL")),
		WebhookTimeout:    envSeconds("HALIMISOC_WEBHOOK_TIMEOUT", 5*time.Second),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Config is the fully resolved runtime configuration.
type Config struct {
	Environment string
	ListenAddr  string
	DatabaseURL string
	RulesPath   string

	AdminUser     string
	AdminPassword string

	// AgentEnrollSecret authorizes agent enrollment. It is intentionally
	// separate from the operator password: compromise of an agent must not
	// grant operator access, and vice versa.
	AgentEnrollSecret string

	SessionTTL time.Duration

	// AI settings. All optional: an empty APIKey and BaseURL mean AI is
	// disabled, which is a supported and fully functional mode.
	AIBaseURL string
	AIAPIKey  string
	AIModel   string

	// WebhookURL receives an incident.created POST per new incident. Empty
	// disables delivery. The payload carries incident scope only, never raw
	// evidence.
	WebhookURL string

	// WebhookTimeout bounds a single webhook delivery attempt.
	WebhookTimeout time.Duration

	// SecureCookies marks session cookies Secure and enables the __Host-
	// cookie prefix. It must be true whenever the API is served over TLS;
	// leaving it false on an HTTPS deployment silently weakens session
	// transport, so Validate refuses that combination in production.
	SecureCookies bool

	// ClockSkew is the accepted tolerance for agent event timestamps.
	ClockSkew time.Duration

	Retention Limits
}

// Validate enforces configuration invariants.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address must not be empty")
	}
	if c.SessionTTL <= 5*time.Minute {
		return errors.New("session ttl must exceed 5 minutes")
	}
	if c.ClockSkew <= 0 || c.ClockSkew > time.Hour {
		return errors.New("clock skew must be within (0, 1h]")
	}
	if err := c.Retention.Validate(); err != nil {
		return fmt.Errorf("retention limits: %w", err)
	}
	if c.IsProduction() && !c.SecureCookies {
		return errors.New("HALIMISOC_SECURE_COOKIES must be enabled in production")
	}
	if c.IsProduction() && c.AdminPassword == "" {
		return errors.New("HALIMISOC_ADMIN_PASSWORD is required in production")
	}
	if c.IsProduction() && len(c.AgentEnrollSecret) < 24 {
		return errors.New("HALIMISOC_AGENT_ENROLL_SECRET must be at least 24 characters in production")
	}
	if err := c.webhookOptions().Validate(); err != nil {
		return err
	}
	return nil
}

// WebhookOptions resolves the notifier configuration from the loaded config.
func (c *Config) WebhookOptions() notify.Options {
	return notify.Options{
		URL:       c.WebhookURL,
		Timeout:   c.WebhookTimeout,
		QueueSize: 64,
	}
}

func (c *Config) webhookOptions() notify.Options { return c.WebhookOptions() }

// IsProduction reports whether strict secret requirements apply.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(c.Environment, "production")
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envSeconds(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		return time.Duration(secs) * time.Second
	}
	return def
}

func envBool(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}
