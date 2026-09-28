// Package visible writes untrusted text so that everything in it can be
// seen (design/adr/0032-quarentena-informada-e-eventos.md item 3).
//
// A tool's description is handed to a model as instructions, and a
// reviewer reads it in a terminal. The two do not see the same thing when
// the text carries a bidi override that reorders what follows, a zero-width
// or tag character the terminal draws as nothing, or an escape sequence the
// terminal executes. The same holds for anything the Operator Console
// prints that a caller or a backend chose: a probe name, a tool name, a
// reason.
//
// Escape replaces each such code point with \u{XXXX} (or \x{XX} for a byte
// that is not valid UTF-8). It escapes rather than deletes: the character
// is evidence, and deleting it would show the reviewer a clean definition
// that is not the one being served.
//
// What it does not do: a backslash is left as it is, so a literal
// "\u{202E}" typed into a description reads the same as an escaped one.
// Both are visible, which is the property this package exists for; telling
// them apart needs the raw bytes (`tool list -json`).
package visible

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Hides reports whether r is a code point Escape rewrites: anything that is
// not graphic (controls C0 and C1, format characters -- zero-width, bidi
// embeddings, overrides and isolates, the BOM, tag characters --
// unassigned and private-use code points, line and paragraph separators),
// every space except U+0020, and the graphic code points that nevertheless
// render as nothing (variation selectors and the other default-ignorable
// ones, such as the Hangul fillers).
func Hides(r rune) bool {
	switch {
	case r == ' ':
		return false
	case r < 0x20, r == 0x7f:
		return true
	case r < 0x7f:
		return false
	case !unicode.IsGraphic(r), unicode.Is(unicode.Co, r):
		return true
	case unicode.Is(unicode.Zs, r):
		return true
	case unicode.Is(unicode.Variation_Selector, r),
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
		return true
	}
	return false
}

// Escape returns s with every code point Hides reports written as
// \u{XXXX}, and every byte that is not valid UTF-8 written as \x{XX}.
// Everything else is copied unchanged.
func Escape(s string) string {
	if Hidden(s) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x{%02X}`, s[i])
		case Hides(r):
			fmt.Fprintf(&b, `\u{%04X}`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// Hidden returns how many code points (and invalid bytes) Escape would
// rewrite in s.
func Hidden(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || Hides(r) {
			n++
		}
		i += size
	}
	return n
}
