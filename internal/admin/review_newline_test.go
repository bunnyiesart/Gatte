package admin

import (
	"testing"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// A description's line breaks are its structure. Sent as "hidden", every
// multi-line description looked like an injection to any front that drew
// the contract literally; only the Gatte front had a private rule for it.
func TestMultilineSegments_ALineBreakIsNotAHiddenCharacter(t *testing.T) {
	segs := MultilineSegments("Look up a host.\nArgs:\r\n  host\u202e")
	var kinds []string
	for _, s := range segs {
		kinds = append(kinds, s.Kind)
	}
	want := []string{adminapi.SegmentText, adminapi.SegmentNewline, adminapi.SegmentText, adminapi.SegmentNewline, adminapi.SegmentText, adminapi.SegmentHidden}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("kinds = %v, want %v", kinds, want)
		}
	}
	// A lone carriage return still hides text a terminal would overwrite.
	if s := MultilineSegments("a\rb"); len(s) != 3 || s[1].Kind != adminapi.SegmentHidden {
		t.Fatalf("a lone CR = %+v, want it hidden", s)
	}
	// Single-line fields (a tool name) keep a newline as hidden.
	if s := Segments("a\nb"); len(s) != 3 || s[1].Kind != adminapi.SegmentHidden {
		t.Fatalf("Segments(a\\nb) = %+v, want the newline hidden", s)
	}
}
