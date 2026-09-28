package visible_test

import (
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/visible"
)

// TestEscape_ShowsEveryInvisibleCodePoint is design/adr/0032 item 3: every
// code point that renders as nothing, moves the cursor, or reorders the text
// around it is printed as \u{XXXX}, so an operator reading a definition in a
// terminal sees what the model will be handed.
func TestEscape_ShowsEveryInvisibleCodePoint(t *testing.T) {
	for _, tc := range []struct {
		name, in, want string
	}{
		{"ESC opening an ANSI sequence", "a\x1b[2Jb", `a\u{001B}[2Jb`},
		{"NUL", "a\x00b", `a\u{0000}b`},
		{"newline, which a table row must not carry", "a\nb", `a\u{000A}b`},
		{"carriage return", "a\rb", `a\u{000D}b`},
		{"tab", "a\tb", `a\u{0009}b`},
		{"DEL", "a\x7fb", `a\u{007F}b`},
		{"C1 CSI", "a\u009bb", `a\u{009B}b`},
		{"zero-width space", "a\u200bb", `a\u{200B}b`},
		{"zero-width joiner", "a\u200db", `a\u{200D}b`},
		{"right-to-left override", "a\u202eb", `a\u{202E}b`},
		{"left-to-right embedding", "a\u202ab", `a\u{202A}b`},
		{"first strong isolate", "a\u2068b", `a\u{2068}b`},
		{"pop directional isolate", "a\u2069b", `a\u{2069}b`},
		{"BOM", "\ufeffa", `\u{FEFF}a`},
		{"tag LATIN CAPITAL A", "a\U000E0041b", `a\u{E0041}b`},
		{"cancel tag", "a\U000E007Fb", `a\u{E007F}b`},
		{"word joiner", "a\u2060b", `a\u{2060}b`},
		{"variation selector", "a\ufe0fb", `a\u{FE0F}b`},
		{"no-break space", "a\u00a0b", `a\u{00A0}b`},
		{"line separator", "a\u2028b", `a\u{2028}b`},
		{"Hangul filler", "a\u3164b", `a\u{3164}b`},
		{"invalid UTF-8 byte", "a\xffb", `a\x{FF}b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := visible.Escape(tc.in); got != tc.want {
				t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got := visible.Hidden(tc.in); got != 1 {
				t.Errorf("Hidden(%q) = %d, want 1", tc.in, got)
			}
		})
	}
}

// TestEscape_LeavesOrdinaryTextAlone: the escaper exists so that what is
// printed is what is there. Mangling accented Portuguese, a plain space or a
// JSON schema would make the output harder to read than the attack.
func TestEscape_LeavesOrdinaryTextAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"list_cases",
		"Lista os casos abertos, com ação e responsável.",
		`{"type":"object","properties":{"q":{"type":"string"}}}`,
		"日本語のテキスト",
		"emoji 🔒 ok",
	} {
		if got := visible.Escape(in); got != in {
			t.Errorf("Escape(%q) = %q, want it unchanged", in, got)
		}
		if n := visible.Hidden(in); n != 0 {
			t.Errorf("Hidden(%q) = %d, want 0", in, n)
		}
	}
}

// TestEscape_OutputIsItselfClean: whatever goes in, nothing invisible comes
// out -- the property the operator's terminal actually depends on.
func TestEscape_OutputIsItselfClean(t *testing.T) {
	var b strings.Builder
	for r := rune(0); r < 0x3000; r++ {
		b.WriteRune(r)
	}
	for r := rune(0xE0000); r <= 0xE01EF; r++ {
		b.WriteRune(r)
	}
	b.WriteString("\xff\xfe\xc0")
	out := visible.Escape(b.String())
	if n := visible.Hidden(out); n != 0 {
		t.Fatalf("Escape's own output still carries %d hidden code points", n)
	}
}
