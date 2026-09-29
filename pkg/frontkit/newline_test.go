package frontkit

import (
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func TestDrawSegments_ANewlineIsALineBreak(t *testing.T) {
	out := string(DrawSegments([]adminapi.Segment{
		{Kind: adminapi.SegmentText, Text: "a"}, {Kind: adminapi.SegmentNewline}, {Kind: adminapi.SegmentText, Text: "b"},
	}))
	if out != "a<br>b" {
		t.Fatalf("DrawSegments = %q, want a<br>b", out)
	}
	lines := SplitLines([]adminapi.Segment{{Kind: adminapi.SegmentText, Text: "a"}, {Kind: adminapi.SegmentNewline}, {Kind: adminapi.SegmentText, Text: "b"}})
	if len(lines) != 2 || lines[1][0].Text != "b" || strings.Contains(string(DrawSegments(lines[0])), "br") {
		t.Fatalf("SplitLines = %+v", lines)
	}
}
