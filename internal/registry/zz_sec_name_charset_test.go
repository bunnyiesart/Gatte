package registry

import (
	"errors"
	"testing"
)

// TestSecUpstreamNameCharset: only non-blank and separator-free used to be
// checked, so a name could carry a newline or tab (a forged row in
// `upstream list`, "signed: valid" included), whitespace, control
// characters, terminal escapes, shell metacharacters, '/', NUL, or a
// leading '-' that reads as a flag in `sign NAME` / `deregister NAME`.
// Ported from the internal tree's security pass of 24 Sep 2026.
func TestSecUpstreamNameCharset(t *testing.T) {
	for label, name := range map[string]string{
		"slash":           "../casemgmt",
		"leading space":   " casemgmt",
		"trailing space":  "casemgmt ",
		"inner space":     "case mgmt",
		"newline":         "casemgmt\nforged",
		"tab":             "casemgmt\tforged",
		"ANSI escape":     "casemgmt\x1b[2K",
		"shell metachars": "casemgmt;$(id)`id`",
		"leading dash":    "-casemgmt",
		"leading under":   "_casemgmt",
		"NUL":             "casemgmt\x00x",
		"non-ASCII":       "casemgmt\u202e",
		"forged row":      "x\nfakecase\tstdio\t/usr/bin/fake\t-\tvalid",
	} {
		s := UpstreamServer{Name: name, Transport: TransportStdio, Command: "/usr/local/bin/x"}
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s (%q): Validate = %v, want ErrInvalid", label, name, err)
		}
	}
	// Every name the lab, the examples and the deploy scripts register.
	for _, name := range []string{"casemgmt", "logsearch", "docsearch", "threatintel", "ioc-sweep", "cloudposture", "edr", "siem", "vulnscan", "intel", "cases", "a", "9lives", "threatintel_staging", "UPPER-Case_09"} {
		s := UpstreamServer{Name: name, Transport: TransportStdio, Command: "/usr/local/bin/x"}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", name, err)
		}
	}
}
