package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// tailer reads a log file incrementally and copes with rotation and truncation.
//
// A log file is not immutable. It can be appended to, truncated in place,
// renamed and recreated (logrotate's default), or replaced by a new inode. The
// tailer therefore tracks both the byte offset and the file identity, and it
// re-reads from the start when the identity changes. Resetting the offset
// casually would either duplicate history or, worse, skip the events written
// during the rotation window.
type tailer struct {
	path  string
	state *offsetStore
	name  string

	file   *os.File
	offset int64
	inode  uint64
}

func newTailer(path string, state *offsetStore) *tailer {
	return &tailer{path: path, state: state, name: path}
}

// Open (re)opens the file, restoring the persisted offset when the file is the
// same one that was being read before.
func (t *tailer) Open() error {
	info, err := os.Stat(t.path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", t.path, err)
	}

	persisted, ok := t.state.load(t.name)
	inode := inodeOf(info)

	f, err := os.Open(t.path)
	if err != nil {
		// A permission error is reported rather than retried silently: an
		// operator needs to know the agent cannot read the file it was told to
		// monitor, otherwise collection stops invisibly.
		return fmt.Errorf("open %s: %w", t.path, err)
	}
	t.file = f
	t.inode = inode

	switch {
	case ok && persisted.Inode == inode && info.Size() >= persisted.Offset:
		// Same file, still at least as long: resume where we stopped.
		if _, err := f.Seek(persisted.Offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek %s: %w", t.path, err)
		}
		t.offset = persisted.Offset
	case ok && persisted.Inode == inode && info.Size() < persisted.Offset:
		// Truncated in place (for example `: > file`). Start over so the new
		// content is not skipped.
		t.offset = 0
	default:
		// New file, or a different inode: this is a fresh stream.
		t.offset = 0
	}
	return nil
}

// Poll reads whatever has been appended since the last call.
//
// It returns the raw bytes read; line assembly happens in the caller so the
// bounded assembler is shared between the live tail and the spool replay paths.
func (t *tailer) Poll(buf []byte) ([]byte, error) {
	if t.file == nil {
		return nil, fmt.Errorf("tailer is not open")
	}

	info, err := os.Stat(t.path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", t.path, err)
	}
	if inodeOf(info) != t.inode {
		// Rotation: the path now points at a new file. Close the old handle and
		// start from the beginning of the new one.
		_ = t.file.Close()
		t.file = nil
		if err := t.Open(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if info.Size() < t.offset {
		// Truncation without inode change.
		if _, err := t.file.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek after truncation: %w", err)
		}
		t.offset = 0
	}

	n, err := t.file.Read(buf)
	if n > 0 {
		t.offset += int64(n)
	}
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read %s: %w", t.path, err)
	}
	return buf[:n], nil
}

// SaveOffset persists the current position.
func (t *tailer) SaveOffset() error {
	return t.state.save(t.name, offsetState{Path: t.path, Offset: t.offset, Inode: t.inode})
}

// Close releases the file handle.
func (t *tailer) Close() error {
	if t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	return err
}

// inodeOf extracts the inode from a FileInfo, returning 0 when the platform
// does not expose one. A zero inode disables identity-based rotation detection
// but never produces a wrong decision: the size comparison still applies.
func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
