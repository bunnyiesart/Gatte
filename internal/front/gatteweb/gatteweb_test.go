package gatteweb

import (
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The review is drawn from the backend's segments, never from escaped
// text: a description that says \u{202E} in plain ASCII and one that
// carries a real U+202E must not look the same (design/adr/0040 §3).
func TestReview_ALiteralEscapeAndARealHiddenCodePointAreDrawnApart(t *testing.T) {
	literal := splitLines([]adminapi.Segment{{Kind: adminapi.SegmentText, Text: `a\u{202E}b`}})
	real := splitLines([]adminapi.Segment{{Kind: adminapi.SegmentText, Text: "a"}, {Kind: adminapi.SegmentHidden, CodePoint: "U+202E"}, {Kind: adminapi.SegmentText, Text: "b"}})
	l, r := diffLines([]adminapi.DiffLine{{Op: adminapi.DiffContext, Segments: literal[0]}}), diffLines([]adminapi.DiffLine{{Op: adminapi.DiffContext, Segments: real[0]}})
	if strings.Contains(string(l[0].HTML), "<mark") || !strings.Contains(string(r[0].HTML), "<mark") {
		t.Fatalf("literal %q, real %q: only the real code point is marked", l[0].HTML, r[0].HTML)
	}
}

// A description's line breaks arrive as newline segments (the contract);
// a hidden U+000A, which only a single-line field can carry, stays a mark.
func TestReview_ADescriptionKeepsItsLineBreaks(t *testing.T) {
	if got := splitLines([]adminapi.Segment{{Kind: adminapi.SegmentHidden, CodePoint: "U+000A"}}); len(got) != 1 {
		t.Fatalf("a hidden U+000A split the line: %+v", got)
	}
	lines := splitLines([]adminapi.Segment{{Kind: adminapi.SegmentText, Text: "one"}, {Kind: adminapi.SegmentNewline}, {Kind: adminapi.SegmentText, Text: "two"}})
	if len(lines) != 2 || lines[0][0].Text != "one" || lines[1][0].Text != "two" {
		t.Fatalf("lines = %+v", lines)
	}
}

func TestReview_TheDiffIsDrawnAsToolShowPrintsIt(t *testing.T) {
	got := diffLines([]adminapi.DiffLine{
		{Op: adminapi.DiffDel, Depth: 1, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "<old>"}}},
		{Op: adminapi.DiffAdd, Depth: 1, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "new"}}},
		{Op: adminapi.DiffGap},
		{Op: "moved", Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "x"}}},
	})
	want := []reviewLine{{"del", "-   &lt;old&gt;"}, {"add", "+   new"}, {"gap", "…"}, {"warn", "? x"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestReview_TheSchemaIsTheBlockUnderItsLabel(t *testing.T) {
	text := func(s string) []adminapi.Segment { return []adminapi.Segment{{Kind: adminapi.SegmentText, Text: s}} }
	lines := []adminapi.ReviewLine{
		{Depth: 0, Segments: text("description:")}, {Depth: 1, Segments: text("input schema:")},
		{Depth: 0, Segments: text("input schema:")}, {Depth: 1, Segments: text("{")}, {Depth: 1, Segments: text("}")},
		{Depth: 0, Segments: text("output schema: (none)")},
	}
	if got := schemaBlock(lines, "input schema:"); got != "{\n}" {
		t.Fatalf("input schema = %q; a description line that reads like a label is not one", got)
	}
	if got := schemaBlock(lines, "output schema:"); got != "" {
		t.Fatalf("output schema = %q, want none", got)
	}
}
