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

// A schema's parameter description with a line break is shown as the JSON
// escape \n. Counted as hidden, the warning named a code point the screen
// could not point at (measured: a real backend's decode tool, 30 Sep 2026).
// A real hidden code point in a schema, in either spelling, still counts.
func TestHiddenInJSON_ALineBreakInAStringIsNotHidden(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want int
	}{
		{`{"properties":{"e":{"description":"One of a, b.\n      Default: a."}}}`, 0},
		{`{"d":"first\r\nsecond"}`, 0},
		{`{"d":"a\rb"}`, 1},
		{`{"d":"line\nbreak\u202e"}`, 1},
		{"{\"d\":\"raw \u202e override\"}", 1},
		{`{"k\ney":"v"}`, 1},
		{`{"d":"tab\there"}`, 1},
	} {
		if got := HiddenInJSON([]byte(c.raw)); got != c.want {
			t.Errorf("HiddenInJSON(%s) = %d, want %d", c.raw, got, c.want)
		}
	}
}
