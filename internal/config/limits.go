package config

import (
	"fmt"
	"os"
	"strconv"
)

// Limit is a bounded configuration value.
//
// DESIGN.md requires every untrusted input path to have both a safe default
// and a maximum allowed value. Modelling them as one type means a caller
// cannot accidentally read the default and skip the bound check.
type Limit struct {
	// Default is the value used when nothing is configured.
	Default int64

	// Max is the largest value an operator may configure.
	Max int64
}

// Resolve returns the effective value: the environment override clamped to
// [0, Max], or Default when unset. Negative overrides are rejected.
func (l Limit) Resolve(envKey string) int64 {
	raw := os.Getenv(envKey)
	if raw == "" {
		return l.Default
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return l.Default
	}
	if v > l.Max {
		return l.Max
	}
	return v
}

// Limits is the full set of resource bounds.
//
// The numbers are deliberately conservative: they are sized for the single
// node MVP described in DESIGN.md, not for a data-centre ingest rate. An
// operator raises them through environment variables up to Max.
type Limits struct {
	HTTPBodyBytes        Limit
	EventBatchSize       Limit
	EventFieldBytes      Limit
	RawLineBytes         Limit
	MultilineBufferBytes Limit
	MemoryQueueSize      Limit
	DiskSpoolBytes       Limit
	DBResultRows         Limit
	PageSize             Limit
	AIContextBytes       Limit
	AIConcurrent         Limit
	SSEConnections       Limit

	// EventRetention and RawRetention are in hours.
	EventRetention Limit
	RawRetention   Limit
}

// DefaultLimits returns the built-in bounded defaults.
func DefaultLimits() Limits {
	return Limits{
		HTTPBodyBytes:        Limit{Default: 4 << 20, Max: 16 << 20}, // 4 MiB / 16 MiB
		EventBatchSize:       Limit{Default: 1000, Max: 5000},        // events per request
		EventFieldBytes:      Limit{Default: 4 << 10, Max: 64 << 10}, // 4 KiB / 64 KiB
		RawLineBytes:         Limit{Default: 8 << 10, Max: 64 << 10}, // 8 KiB / 64 KiB
		MultilineBufferBytes: Limit{Default: 64 << 10, Max: 1 << 20}, // 64 KiB / 1 MiB
		MemoryQueueSize:      Limit{Default: 10_000, Max: 100_000},
		DiskSpoolBytes:       Limit{Default: 100 << 20, Max: 4 << 30}, // 100 MiB / 4 GiB
		DBResultRows:         Limit{Default: 10_000, Max: 100_000},
		PageSize:             Limit{Default: 50, Max: 500},
		AIContextBytes:       Limit{Default: 64 << 10, Max: 256 << 10}, // 64 KiB / 256 KiB
		AIConcurrent:         Limit{Default: 2, Max: 8},
		SSEConnections:       Limit{Default: 100, Max: 1000},
		EventRetention:       Limit{Default: 720, Max: 24 * 365}, // 30 days / 1 year
		RawRetention:         Limit{Default: 72, Max: 24 * 90},   // 3 days / 90 days
	}
}

// LimitsFromEnv builds the effective limits from environment overrides.
func LimitsFromEnv() Limits {
	d := DefaultLimits()
	d.HTTPBodyBytes.Default = d.HTTPBodyBytes.Resolve("HALIMISOC_MAX_HTTP_BODY_BYTES")
	d.EventBatchSize.Default = d.EventBatchSize.Resolve("HALIMISOC_MAX_EVENT_BATCH")
	d.EventFieldBytes.Default = d.EventFieldBytes.Resolve("HALIMISOC_MAX_EVENT_FIELD_BYTES")
	d.RawLineBytes.Default = d.RawLineBytes.Resolve("HALIMISOC_MAX_RAW_LINE_BYTES")
	d.MultilineBufferBytes.Default = d.MultilineBufferBytes.Resolve("HALIMISOC_MAX_MULTILINE_BYTES")
	d.MemoryQueueSize.Default = d.MemoryQueueSize.Resolve("HALIMISOC_MEMORY_QUEUE")
	d.DiskSpoolBytes.Default = d.DiskSpoolBytes.Resolve("HALIMISOC_DISK_SPOOL_BYTES")
	d.DBResultRows.Default = d.DBResultRows.Resolve("HALIMISOC_MAX_DB_ROWS")
	d.PageSize.Default = d.PageSize.Resolve("HALIMISOC_PAGE_SIZE")
	d.AIContextBytes.Default = d.AIContextBytes.Resolve("HALIMISOC_MAX_AI_CONTEXT_BYTES")
	d.AIConcurrent.Default = d.AIConcurrent.Resolve("HALIMISOC_MAX_AI_CONCURRENT")
	d.SSEConnections.Default = d.SSEConnections.Resolve("HALIMISOC_MAX_SSE_CONNECTIONS")
	d.EventRetention.Default = d.EventRetention.Resolve("HALIMISOC_EVENT_RETENTION_HOURS")
	d.RawRetention.Default = d.RawRetention.Resolve("HALIMISOC_RAW_RETENTION_HOURS")
	return d
}

// Validate checks that every limit is positive and within its maximum.
func (l Limits) Validate() error {
	checks := []struct {
		name string
		lim  Limit
	}{
		{"http_body_bytes", l.HTTPBodyBytes},
		{"event_batch_size", l.EventBatchSize},
		{"event_field_bytes", l.EventFieldBytes},
		{"raw_line_bytes", l.RawLineBytes},
		{"multiline_buffer_bytes", l.MultilineBufferBytes},
		{"memory_queue_size", l.MemoryQueueSize},
		{"disk_spool_bytes", l.DiskSpoolBytes},
		{"db_result_rows", l.DBResultRows},
		{"page_size", l.PageSize},
		{"ai_context_bytes", l.AIContextBytes},
		{"ai_concurrent", l.AIConcurrent},
		{"sse_connections", l.SSEConnections},
		{"event_retention", l.EventRetention},
		{"raw_retention", l.RawRetention},
	}
	for _, c := range checks {
		if c.lim.Default <= 0 {
			return fmt.Errorf("%s must be positive, got %d", c.name, c.lim.Default)
		}
		if c.lim.Default > c.lim.Max {
			return fmt.Errorf("%s default %d exceeds max %d", c.name, c.lim.Default, c.lim.Max)
		}
	}
	if l.RawRetention.Default > l.EventRetention.Default {
		return fmt.Errorf("raw retention (%dh) must not exceed event retention (%dh)",
			l.RawRetention.Default, l.EventRetention.Default)
	}
	return nil
}

// PageBounds returns the resolved default and maximum page size.
func (l Limits) PageBounds() (def, max int) {
	return int(l.PageSize.Default), int(l.PageSize.Max)
}
