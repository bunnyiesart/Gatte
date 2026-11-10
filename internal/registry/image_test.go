package registry

import (
	"errors"
	"strings"
	"testing"
)

const pinnedDigest = "@sha256:abababababababababababababababababababababababababababababababab"

// TestOCIImageRefusesHiddenCharacters: the digest pin constrains only the
// part after '@', so a control, format or other invisible code point in the
// repository part used to validate and be signed. It is refused, with the
// image shown escaped so the message itself draws nothing hidden.
func TestOCIImageRefusesHiddenCharacters(t *testing.T) {
	for label, repo := range map[string]string{
		"newline":              "localhost/casemgmt\nforged",
		"tab":                  "localhost/casemgmt\tforged",
		"NUL":                  "localhost/casemgmt\x00",
		"ANSI escape":          "localhost/casemgmt\x1b[2K",
		"DEL":                  "localhost/casemgmt\x7f",
		"C1 control":           "localhost/casemgmt\u0085",
		"zero-width space":     "localhost/case\u200bmgmt",
		"bidi override":        "localhost/casemgmt\u202e",
		"BOM":                  "\ufefflocalhost/casemgmt",
		"no-break space":       "localhost/case\u00a0mgmt",
		"variation selector":   "localhost/casemgmt\ufe0f",
		"tag character":        "localhost/casemgmt\U000E0041",
		"invalid UTF-8 byte":   "localhost/casemgmt\xff",
		"line separator":       "localhost/casemgmt\u2028",
		"private-use":          "localhost/casemgmt\ue000",
		"hidden after a slash": "localhost/\u2066casemgmt",
	} {
		image := repo + pinnedDigest
		err := UpstreamServer{Name: "casemgmt", Transport: TransportOCI, Image: image}.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "hidden character") {
			t.Errorf("%s (%q): Validate = %v, want a hidden-character refusal", label, image, err)
			continue
		}
		if msg := err.Error(); strings.ContainsAny(msg, "\n\t\x00\x1b\x7f\u0085\u200b\u202e\ufeff\u00a0\ufe0f\u2028\ue000\u2066\U000E0041") {
			t.Errorf("%s: the message carries the hidden character itself: %q", label, msg)
		}
	}

	for _, image := range []string{
		"localhost/casemgmt-mcp" + pinnedDigest,
		"registry.example:5000/team/mcp_casemgmt.v2" + pinnedDigest,
		"ghcr.io/org/threatintel-mcp" + pinnedDigest,
	} {
		if err := (UpstreamServer{Name: "casemgmt", Transport: TransportOCI, Image: image}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", image, err)
		}
	}
}

// TestOCIImageIsTheASCIIReferenceGrammar: some code points draw as blank
// or as another letter without being hidden, so the image is held to the
// OCI reference grammar, which is ASCII only.
func TestOCIImageIsTheASCIIReferenceGrammar(t *testing.T) {
	for label, repo := range map[string]string{
		"braille blank":      "localhost/case⠀mgmt",
		"cyrillic homoglyph": "lоcalhost/casemgmt",
		"combining mark":     "localhost/casémgmt",
		"typed backslash":    `localhost/case\u{200B}mgmt`,
		"uppercase path":     "localhost/CaseMgmt",
		"empty path segment": "localhost//casemgmt",
	} {
		image := repo + pinnedDigest
		err := UpstreamServer{Name: "casemgmt", Transport: TransportOCI, Image: image}.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "not a valid OCI image reference") {
			t.Errorf("%s (%+q): Validate = %v, want a reference-grammar refusal", label, image, err)
			continue
		}
		for _, r := range err.Error() {
			if r > 0x7e {
				t.Errorf("%s: the message carries the non-ASCII code point %U itself: %v", label, r, err)
				break
			}
		}
	}

	for _, image := range []string{
		"mcp-casemgmt" + pinnedDigest,
		"host:5000/a/b:tag" + pinnedDigest,
		"Registry.Example.COM/team/mcp" + pinnedDigest,
		"localhost/casemgmt__mcp:v1.2-rc_3" + pinnedDigest,
		"127.0.0.1:5000/casemgmt" + pinnedDigest,
	} {
		if err := (UpstreamServer{Name: "casemgmt", Transport: TransportOCI, Image: image}).Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", image, err)
		}
	}
}
