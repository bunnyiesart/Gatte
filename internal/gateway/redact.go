package gateway

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
)

// MaskCredentials returns text with every rendering of every non-empty
// value of env masked by the redaction placeholder, and whether anything
// was masked. It is the one masking algorithm of this module: redact (the
// gateway's errors), scrubJSON (tool results) and the stdio dialer's
// scrubDialError all go through it.
//
// Two ways value-by-value replacement slipped (fixed 2026-09-24 in the
// internal tree, ported here), both closed by masking the union of every
// match span in one pass:
//
//   - Overlap. Replacing values one at a time, in map order, meant a short
//     value found inside a longer one ("443" inside an API key) split the
//     long one first, which then no longer matched: both halves of the key
//     stayed in clear.
//   - Escaping. An error renders a string the way Go code usually does --
//     %q, %+q or a json.Marshal'd payload -- and a value with a newline,
//     quote, backslash or <&> then no longer appears as its raw bytes, yet
//     strconv.Unquote or json.Unmarshal gives it straight back. Each value's
//     escaped bodies are masked as well as the raw one.
func MaskCredentials(text string, env map[string]string) (string, bool) {
	forms := make([][]string, 0, len(env))
	for _, value := range env {
		forms = append(forms, renderingsOf(value))
	}
	out, hit := maskSpans(text, forms)
	return out, slices.Contains(hit, true)
}

// maskSpans marks, on a byte mask over text, every occurrence of every
// form, then rewrites text once with each maximal masked run replaced by
// the placeholder. hit[k] reports whether any form of formsByValue[k]
// matched. Because the rewrite happens after all matching, the order in
// which values are tried cannot leave part of one in clear.
func maskSpans(text string, formsByValue [][]string) (string, []bool) {
	hit := make([]bool, len(formsByValue))
	var mask []bool
	for k, forms := range formsByValue {
		for _, form := range forms {
			if form == "" {
				continue
			}
			for from := 0; ; {
				i := strings.Index(text[from:], form)
				if i < 0 {
					break
				}
				if mask == nil {
					mask = make([]bool, len(text))
				}
				start := from + i
				for j := start; j < start+len(form); j++ {
					mask[j] = true
				}
				hit[k] = true
				from = start + 1
			}
		}
	}
	if mask == nil {
		return text, hit
	}
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); {
		if !mask[i] {
			b.WriteByte(text[i])
			i++
			continue
		}
		for i < len(text) && mask[i] {
			i++
		}
		b.WriteString(redacted)
	}
	return b.String(), hit
}

// renderingsOf returns the forms in which value may appear inside an error
// message: the raw bytes, and the bodies (outer quotes dropped) of %q, %+q
// and JSON string encodings, with and without JSON's HTML escaping. An
// empty value has no rendering: masking "" would mask nothing and loop.
func renderingsOf(value string) []string {
	if value == "" {
		return nil
	}
	forms := []string{value}
	add := func(quoted string) {
		if len(quoted) >= 2 {
			if body := quoted[1 : len(quoted)-1]; body != "" && !slices.Contains(forms, body) {
				forms = append(forms, body)
			}
		}
	}
	add(strconv.Quote(value))
	add(strconv.QuoteToASCII(value))
	for _, body := range jsonBodies(value) {
		if !slices.Contains(forms, body) {
			forms = append(forms, body)
		}
	}
	return forms
}

// jsonRenderingsOf returns the forms in which value may appear inside JSON
// text: each rendering of renderingsOf -- the value itself, or a %q/JSON
// rendering of it that a backend put inside a string -- as a JSON encoder
// then writes it inside a string literal, with and without HTML escaping.
//
// The raw form is not listed on its own: when the value holds nothing JSON
// must escape, its unescaped JSON body IS the raw form; when it does, the
// raw bytes cannot occur inside a string literal, and matching them
// anyway could straddle structure and corrupt the document.
func jsonRenderingsOf(value string) []string {
	var forms []string
	for _, r := range renderingsOf(value) {
		for _, body := range jsonBodies(r) {
			if !slices.Contains(forms, body) {
				forms = append(forms, body)
			}
		}
	}
	return forms
}

// jsonBodies returns the JSON string encodings of s with the outer quotes
// dropped, HTML-escaped (json.Marshal's default) and not.
func jsonBodies(s string) []string {
	var out []string
	add := func(quoted string) {
		if len(quoted) >= 2 {
			if body := quoted[1 : len(quoted)-1]; body != "" && !slices.Contains(out, body) {
				out = append(out, body)
			}
		}
	}
	if j, err := json.Marshal(s); err == nil {
		add(string(j))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) == nil {
		add(strings.TrimSuffix(buf.String(), "\n"))
	}
	return out
}
