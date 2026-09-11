package jsonl

// Internal test: the short-write path needs to substitute FileSink's
// writer, which is unexported on purpose -- the seam exists for this one
// failure and should not be part of the package's surface.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// shortWriter accepts only the first n bytes of the first write, then
// fails -- the shape of a disk filling up mid-record.
type shortWriter struct {
	buf   bytes.Buffer
	limit int
	used  bool
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if !w.used {
		w.used = true
		n := w.limit
		if n > len(p) {
			n = len(p)
		}
		w.buf.Write(p[:n])
		return n, io.ErrShortWrite
	}
	return w.buf.Write(p)
}

// TestFileSink_AShortWriteDoesNotSwallowTheNextRecord pins what a partial
// write must not cost.
//
// The file is opened O_APPEND, so a write that stops halfway leaves a
// headless JSON stump and the NEXT record begins exactly where it stopped.
// Without a terminator that produces one line containing the tail of a
// broken record followed by the whole of a good one: the parser rejects
// it, and the good record is gone with it. One record was already lost;
// losing the next one silently is the part this prevents.
func TestFileSink_AShortWriteDoesNotSwallowTheNextRecord(t *testing.T) {
	w := &shortWriter{limit: 20}
	s := &FileSink{f: nil, w: w}

	first := Line{Version: 1, Chain: "c", Caller: "ana", Tool: "casemgmt.list_cases", Verdict: "allowed"}
	if err := s.Emit(context.Background(), first); err == nil {
		t.Fatal("expected the short write to be reported")
	}

	second := Line{Version: 1, Chain: "c", Caller: "bea", Tool: "logsearch.search", Verdict: "denied"}
	if err := s.Emit(context.Background(), second); err != nil {
		t.Fatalf("second Emit: %v", err)
	}

	lines := strings.Split(strings.TrimRight(w.buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d line(s), want 2 -- the stump and the good record must not share one: %q",
			len(lines), w.buf.String())
	}
	// The second line must be the whole good record, parseable on its own.
	var got Line
	if err := json.Unmarshal([]byte(lines[1]), &got); err != nil {
		t.Fatalf("the record after a short write does not parse on its own: %v\nline: %q", err, lines[1])
	}
	if got.Caller != "bea" {
		t.Errorf("second line carries caller %q, want %q", got.Caller, "bea")
	}
}
