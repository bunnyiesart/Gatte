package fitness

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// leakPatterns are the values that tie this public tree to the real SOC
// deployment it was sanitised from: its jail, service and VPN subnets, its
// jail host on the LAN, its internal DNS zone, and the organisation names.
// They are written as fragments so this file does not match itself.
//
// # Why a fitness function
//
// 24 Sep 2026: 321 lines in about 40 tracked files carried the real
// addresses -- runbooks, pf rules, config templates, test fixtures -- after
// c871a7d/9bed596 had sanitised the upstream NAMES and nothing else. Each
// one was an innocent example when written; together they mapped the
// network. They were replaced with RFC 5737 / RFC 2544 stand-ins and the
// example.internal zone, and this check keeps a new runbook from bringing
// them back. It needs no domain knowledge: a string either is one of these
// or is not.
//
// It checks the tree only. The same values are in pushed history and in
// commit messages, which no test can undo (see CLOSEOUT.md).
//
// Each dot accepts an optional backslash before it, because a sed or grep
// pattern in a runbook carries the address with every dot escaped, and the
// plain form would walk past it. The whole /16 prefix of the jail network
// is a leak on its own, hence the first pattern stops before the host part.
// The patterns are split so this file does not match itself.
var leakPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b1` + `0\\?\.17\\?\.`),
	regexp.MustCompile(`\b1` + `0\\?\.8\\?\.0\\?\.\d`),
	regexp.MustCompile(`\b19` + `2\\?\.168\\?\.1\\?\.\d`),
	regexp.MustCompile(`\b1` + `0\\?\.69\\?\.71\\?\.\d`),
	regexp.MustCompile(`soc` + `\\?\.internal`),
	regexp.MustCompile("`b" + "un`"),
	regexp.MustCompile(`(?i)bsd` + `trust|freebsd` + `brasil`),
	regexp.MustCompile(`Gabriels-` + `MacBook`),
}

func TestTreeCarriesNoDeploymentTopology(t *testing.T) {
	root := repoRoot(t)
	// Tracked plus untracked-but-not-ignored: a file about to be added is
	// exactly the one that should be caught before it is.
	out, err := exec.Command("git", "-C", root, "ls-files", "-z", "-co", "--exclude-standard").Output()
	if err != nil {
		// A source tarball has no .git. That is a skip, and a skip proves
		// nothing -- `make test` runs from a checkout.
		t.Skipf("git ls-files unavailable (%v); this check needs a checkout", err)
	}
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // listed but deleted in the working tree
		}
		if bytes.IndexByte(data, 0) >= 0 {
			continue // binary; the same rule grep -I applies
		}
		for n, line := range strings.Split(string(data), "\n") {
			for _, re := range leakPatterns {
				if m := re.FindString(line); m != "" {
					t.Errorf("%s:%d carries %q, a value from the real deployment; use a documentation stand-in (deploy/README.md)", rel, n+1, m)
				}
			}
		}
	}
}
