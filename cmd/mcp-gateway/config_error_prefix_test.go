package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadConfig_PrefixPrintedOnce pins a correction made on 24 Sep 2026.
// The refusal for an unedited examples/base.toml -- the first error most
// newcomers see -- read "config: config: <path>: config: invalid": main
// added a "config: " that config.Load's errors already carry, and Load
// wrapped Validate's "config: invalid" behind another "config: <path>: ".
func TestLoadConfig_PrefixPrintedOnce(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"invalid (validate)": "[signer]\ntrusted_keys = [\"not-base64\"]\n",
		"unknown key":        "bogus_key = 1\n",
		"syntax error":       "this is not toml\n",
		"missing file":       "",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".toml")
			if body != "" {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}
			var stderr bytes.Buffer
			if _, ok := loadConfig(path, &stderr); ok {
				t.Fatalf("loadConfig accepted %q", body)
			}
			out := stderr.String()
			if !strings.HasPrefix(out, "config: ") {
				t.Errorf("stderr does not start with %q:\n%s", "config: ", out)
			}
			first := strings.SplitN(out, "\n", 2)[0]
			if n := strings.Count(first, "config: "); n != 1 {
				t.Errorf("%q appears %d times in the first line, want 1:\n%s", "config: ", n, first)
			}
			if !strings.Contains(first, path) {
				t.Errorf("first line does not name %s:\n%s", path, first)
			}
		})
	}
}
