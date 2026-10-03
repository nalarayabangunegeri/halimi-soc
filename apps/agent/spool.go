package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/halimi/halimisoc/internal/events/model"
)

// spool is a bounded on-disk buffer of events that could not be delivered.
//
// Telemetry must survive a server outage, but a spool that grows without bound
// would fill the disk and take the monitored host down. The spool therefore
// enforces a hard byte limit and, when full, drops the oldest records first and
// records a counter so the loss is visible rather than silent.
type spool struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	log      *slog.Logger

	dropped uint64
}

// spoolRecord is the on-disk envelope.
//
// A record is one JSON object per line so a partially written file can be
// recovered by discarding only the final incomplete line.
type spoolRecord struct {
	Event *model.Event `json:"event"`
}

// newSpool opens or creates the spool directory.
func newSpool(dir string, maxBytes int64, log *slog.Logger) (*spool, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	s := &spool{dir: dir, maxBytes: maxBytes, log: log}
	if err := s.rotate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *spool) currentPath() string { return filepath.Join(s.dir, "spool.ndjson") }

// Append writes a batch of events to the spool.
func (s *spool) Append(events []*model.Event) error {
	if len(events) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.OpenFile(s.currentPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open spool: %w", err)
	}
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(spoolRecord{Event: e}); err != nil {
			_ = f.Close()
			return fmt.Errorf("write spool: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync spool: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close spool: %w", err)
	}

	if err := s.enforceLimitLocked(); err != nil {
		return err
	}
	return nil
}

// Read returns up to max events from the spool, oldest first.
func (s *spool) Read(max int) ([]*model.Event, error) {
	if max <= 0 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.currentPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open spool: %w", err)
	}
	defer f.Close()

	var (
		out []*model.Event
	)
	reader := bufio.NewReader(f)
	for len(out) < max {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && err == nil {
			var rec spoolRecord
			if jsonErr := json.Unmarshal(line, &rec); jsonErr == nil && rec.Event != nil {
				out = append(out, rec.Event)
			}
			continue
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

// Ack removes the first n events from the spool.
//
// The rewrite is atomic: the replacement is written to a temporary file and
// renamed, so a crash mid-rewrite leaves the previous spool intact rather than a
// truncated one.
func (s *spool) Ack(n int) error {
	if n <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackLocked(n)
}

func (s *spool) ackLocked(n int) error {
	f, err := os.Open(s.currentPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("open spool: %w", err)
	}
	defer f.Close()

	tmpPath := s.currentPath() + ".tmp"
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open spool temp: %w", err)
	}

	reader := bufio.NewReader(f)
	skipped := 0
	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 && readErr == nil {
			if skipped < n {
				skipped++
				continue
			}
			if _, err := tmp.Write(line); err != nil {
				_ = tmp.Close()
				_ = os.Remove(tmpPath)
				return fmt.Errorf("rewrite spool: %w", err)
			}
			continue
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				_ = tmp.Close()
				_ = os.Remove(tmpPath)
				return fmt.Errorf("read spool: %w", readErr)
			}
			break
		}
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync spool temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close spool temp: %w", err)
	}
	if err := os.Rename(tmpPath, s.currentPath()); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace spool: %w", err)
	}
	return nil
}

// Size returns the current spool size in bytes.
func (s *spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.currentPath())
	if err != nil {
		return 0
	}
	return info.Size()
}

// Dropped returns the number of events discarded because the spool was full.
func (s *spool) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// enforceLimitLocked drops the oldest records while the spool exceeds its bound.
// Callers must hold s.mu.
func (s *spool) enforceLimitLocked() error {
	for {
		info, err := os.Stat(s.currentPath())
		if err != nil || info.Size() <= s.maxBytes {
			return nil
		}

		// Compute how many leading lines to drop so that roughly half the
		// spool is freed per pass. Dropping half rather than the minimum avoids
		// rewriting the file on every subsequent append.
		target := info.Size() - s.maxBytes/2
		drop, err := s.countLinesToDropping(target)
		if err != nil {
			return err
		}
		if drop == 0 {
			return nil
		}
		if err := s.ackLocked(drop); err != nil {
			return err
		}
		s.dropped += uint64(drop)
		s.log.Warn("spool over limit, oldest events discarded", "dropped", drop, "total_dropped", s.dropped)
	}
}

// countLinesToDropping counts how many leading lines cover at least bytes bytes.
func (s *spool) countLinesToDropping(bytes int64) (int, error) {
	f, err := os.Open(s.currentPath())
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	var (
		covered int64
		count   int
	)
	for covered < bytes {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			covered += int64(len(line))
			count++
		}
		if err != nil {
			break
		}
	}
	return count, nil
}

// Directories returns the spool's directory entries.
func (s *spool) files() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// rotate removes a leftover temporary file from an interrupted rewrite.
func (s *spool) rotate() error {
	tmp := s.currentPath() + ".tmp"
	if _, err := os.Stat(tmp); err == nil {
		// The temporary file is an incomplete rewrite, so the canonical spool
		// is the trustworthy copy and the temporary one is discarded.
		if err := os.Remove(tmp); err != nil {
			return fmt.Errorf("remove stale spool temp: %w", err)
		}
	}
	return nil
}

// Reader offsets.

// offsetStore persists the read position of a log file across restarts.
//
// Without it, a restart would re-send every event in the file, and although the
// server collapses duplicates idempotently, replaying gigabytes of history is a
// self-inflicted load spike.
type offsetStore struct {
	dir string
}

func newOffsetStore(dir string) (*offsetStore, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	return &offsetStore{dir: dir}, nil
}

type offsetState struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

func (o *offsetStore) load(name string) (offsetState, bool) {
	raw, err := os.ReadFile(o.file(name))
	if err != nil {
		return offsetState{}, false
	}
	var state offsetState
	if err := json.Unmarshal(raw, &state); err != nil {
		return offsetState{}, false
	}
	return state, true
}

func (o *offsetStore) save(name string, state offsetState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	tmp := o.file(name) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, o.file(name))
}

func (o *offsetStore) file(name string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, name)
	return filepath.Join(o.dir, safe+".json")
}
