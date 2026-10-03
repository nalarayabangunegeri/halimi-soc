package parser

import (
	"strings"
)

// Assembler turns a byte stream into complete logical records.
//
// Log files are not line-oriented in practice: a stack trace or a multi-line
// audit record is a single logical event spread over several physical lines.
// The assembler joins continuation lines (those starting with whitespace) onto
// the record that precedes them, and bounds both the per-record and the
// pending-multiline size so a malformed or hostile stream cannot grow memory
// without limit.
type Assembler struct {
	// MaxLine is the maximum size of one physical line in bytes.
	MaxLine int

	// MaxRecord is the maximum size of an assembled logical record in bytes.
	MaxRecord int

	carry   strings.Builder
	pending strings.Builder
	// truncating is set while a physical line longer than MaxLine is being
	// discarded, so the tail of that line is not mistaken for a new record.
	truncating bool
}

// NewAssembler returns an assembler with the given bounds. Non-positive values
// fall back to conservative defaults.
func NewAssembler(maxLine, maxRecord int) *Assembler {
	if maxLine <= 0 {
		maxLine = 8 << 10
	}
	if maxRecord <= 0 {
		maxRecord = 64 << 10
	}
	if maxRecord < maxLine {
		maxRecord = maxLine
	}
	return &Assembler{MaxLine: maxLine, MaxRecord: maxRecord}
}

// Feed consumes a chunk and returns every complete logical record it produced.
//
// The most recent record is deliberately held back until the next non-continuation
// line arrives, because a record can only be known to be complete once the line
// that follows it is seen. Call Flush when the source has gone idle so the held
// record is not stranded. This mirrors how a tailing collector must behave: an
// immediate emit would make multi-line records impossible.
//
// Records are returned in arrival order. An incomplete trailing line is
// retained until more data arrives.
func (a *Assembler) Feed(chunk string) []string {
	if chunk == "" {
		return nil
	}
	a.carry.WriteString(chunk)
	buffered := a.carry.String()
	a.carry.Reset()

	var records []string
	for len(buffered) > 0 {
		i := strings.IndexByte(buffered, '\n')
		if i < 0 {
			// No newline: retain the remainder, but keep the carry bounded.
			if len(buffered) > a.MaxLine {
				a.truncating = true
				a.appendPending(buffered[:a.MaxLine] + " [line truncated]")
				buffered = ""
				continue
			}
			a.carry.WriteString(buffered)
			break
		}

		line := strings.TrimSuffix(buffered[:i], "\r")
		buffered = buffered[i+1:]

		if a.truncating {
			// Discard the tail of an over-long line.
			a.truncating = false
			continue
		}

		if len(line) > a.MaxLine {
			line = line[:a.MaxLine] + " [line truncated]"
		}

		if isContinuation(line) && a.pending.Len() > 0 {
			a.appendPending(line)
			continue
		}

		if a.pending.Len() > 0 {
			records = append(records, a.pending.String())
			a.pending.Reset()
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		a.pending.WriteString(line)
	}
	return records
}

// Flush returns any buffered records at end of stream.
//
// It emits the held record and any unterminated trailing line, then resets the
// assembler so it can be reused.
func (a *Assembler) Flush() []string {
	var out []string
	if a.pending.Len() > 0 {
		out = append(out, a.pending.String())
		a.pending.Reset()
	}
	if s := a.carry.String(); strings.TrimSpace(s) != "" {
		if len(s) > a.MaxLine {
			s = s[:a.MaxLine] + " [line truncated]"
		}
		out = append(out, s)
	}
	a.carry.Reset()
	a.truncating = false
	return out
}

func (a *Assembler) appendPending(s string) {
	if a.pending.Len()+len(s)+1 > a.MaxRecord {
		// The record is at its bound. Stop growing it; the parser will classify
		// whatever it received as incomplete rather than the process exhausting
		// memory on a hostile input.
		return
	}
	if a.pending.Len() > 0 {
		a.pending.WriteByte('\n')
	}
	a.pending.WriteString(s)
}

// isContinuation reports whether a physical line continues the previous record.
func isContinuation(line string) bool {
	if line == "" {
		return false
	}
	switch line[0] {
	case ' ', '\t':
		return true
	}
	return false
}
