package auth

import (
	"sync"
	"time"
)

// Limiter throttles authentication attempts.
//
// DESIGN.md §15.2 requires rate limiting and progressive backoff, and explicitly
// warns against permanent account lockout as the only control: an attacker who
// can lock out an operator has turned a security control into a denial of
// service. This limiter therefore slows attempts down instead of disabling the
// account, and the delay decays once attempts stop.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*attempt
	opts    LimiterOptions
}

// LimiterOptions bound the limiter.
type LimiterOptions struct {
	// MaxAttempts is the number of failures tolerated before backoff applies.
	MaxAttempts int

	// BaseDelay is the delay applied after MaxAttempts.
	BaseDelay time.Duration

	// MaxDelay caps the progressive backoff.
	MaxDelay time.Duration

	// ResetAfter is how long a quiet period must last before the counter clears.
	ResetAfter time.Duration

	// MaxEntries bounds the number of tracked keys. When exceeded, the oldest
	// entry is evicted, so an attacker cycling usernames cannot grow memory.
	MaxEntries int
}

// DefaultLimiterOptions returns the shipped defaults.
func DefaultLimiterOptions() LimiterOptions {
	return LimiterOptions{
		MaxAttempts: 5,
		BaseDelay:   time.Second,
		MaxDelay:    5 * time.Minute,
		ResetAfter:  15 * time.Minute,
		MaxEntries:  10_000,
	}
}

type attempt struct {
	failures int
	last     time.Time
}

// NewLimiter returns a limiter with the given options.
func NewLimiter(opts LimiterOptions) *Limiter {
	def := DefaultLimiterOptions()
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = def.MaxAttempts
	}
	if opts.BaseDelay <= 0 {
		opts.BaseDelay = def.BaseDelay
	}
	if opts.MaxDelay <= 0 {
		opts.MaxDelay = def.MaxDelay
	}
	if opts.ResetAfter <= 0 {
		opts.ResetAfter = def.ResetAfter
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = def.MaxEntries
	}
	return &Limiter{entries: map[string]*attempt{}, opts: opts}
}

// RetryAfter reports how long the caller must wait before another attempt is
// accepted. A zero duration means the attempt may proceed.
func (l *Limiter) RetryAfter(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	a, ok := l.entries[key]
	if !ok {
		return 0
	}
	if now.Sub(a.last) > l.opts.ResetAfter {
		delete(l.entries, key)
		return 0
	}
	if a.failures < l.opts.MaxAttempts {
		return 0
	}

	// Progressive backoff: doubling per excess failure, capped.
	excess := a.failures - l.opts.MaxAttempts
	delay := l.opts.BaseDelay
	for i := 0; i < excess && delay < l.opts.MaxDelay; i++ {
		delay *= 2
	}
	if delay > l.opts.MaxDelay {
		delay = l.opts.MaxDelay
	}

	elapsed := now.Sub(a.last)
	if elapsed >= delay {
		return 0
	}
	return delay - elapsed
}

// Fail records a failed attempt.
func (l *Limiter) Fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictIfNeeded()

	a, ok := l.entries[key]
	if !ok || now.Sub(a.last) > l.opts.ResetAfter {
		l.entries[key] = &attempt{failures: 1, last: now}
		return
	}
	a.failures++
	a.last = now
}

// Succeed clears the failure counter for a key.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Prune drops expired entries.
func (l *Limiter) Prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, a := range l.entries {
		if now.Sub(a.last) > l.opts.ResetAfter {
			delete(l.entries, k)
		}
	}
}

// Size returns the number of tracked keys.
func (l *Limiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// evictIfNeeded drops the oldest entry when the map is at its bound.
// Callers must hold l.mu.
func (l *Limiter) evictIfNeeded() {
	if len(l.entries) < l.opts.MaxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, a := range l.entries {
		if oldestKey == "" || a.last.Before(oldest) {
			oldestKey = k
			oldest = a.last
		}
	}
	if oldestKey != "" {
		delete(l.entries, oldestKey)
	}
}
