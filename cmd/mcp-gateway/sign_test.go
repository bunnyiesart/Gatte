package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// TestRunSign_WithoutAKeyCannotRun covers the two ways there is no usable
// key: none configured, and one configured that LoadKey refuses. Both are
// exitCannotRun -- the command did not run and found nothing, it could not
// run at all -- and both must say what to do about it.
func TestRunSign_WithoutAKeyCannotRun(t *testing.T) {
	tests := []struct {
		name    string
		keyFile func(t *testing.T) string
		want    []string
	}{
		{
			name:    "no key file configured",
			keyFile: func(*testing.T) string { return "" },
			want:    []string{"signer.key_file is empty", "[signer]", "key_file ="},
		},
		{
			name:    "configured key file does not exist",
			keyFile: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.key") },
			want:    []string{"cannot open key file"},
		},
		{
			name:    "key file is group-readable",
			keyFile: func(t *testing.T) string { return writeSigningKey(t, 0o640) },
			want:    []string{"group- or world-readable", "chmod 600"},
		},
		{
			name: "key file is not a key",
			keyFile: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "notakey")
				if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
					t.Fatalf("writing file: %v", err)
				}
				return path
			},
			want: []string{"not a PEM"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			e.cfg.Signer.KeyFile = tc.keyFile(t)
			mustRegister(t, e, stdioEntry("casemgmt"))

			requireExit(t, runSign(e.opEnv, "casemgmt"), exitCannotRun, tc.name)
			for _, want := range tc.want {
				requireContains(t, e.stderrText(), want, tc.name)
			}

			// Nothing may have been stored on a failed sign.
			if _, err := e.signatures().Get(context.Background(), "casemgmt"); err == nil {
				t.Error("a signature was stored despite the key being unusable")
			}
		})
	}
}

// TestRunSign_ThenListShowsTheEntryAsSigned is the round-trip the whole
// component exists for.
func TestRunSign_ThenListShowsTheEntryAsSigned(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Signer.KeyFile = writeSigningKey(t, 0o600)
	entry := stdioEntry("casemgmt")
	mustRegister(t, e, entry)

	requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")
	for _, want := range []string{`Signed "casemgmt"`, "public key", "sha256:", "docker run --rm casemgmt-mcp", "CASEMGMT_API_KEY", "first signature"} {
		requireContains(t, e.stdoutText(), want, "sign")
	}

	// The stored signature really verifies against the stored entry.
	sig, err := e.signatures().Get(context.Background(), "casemgmt")
	if err != nil {
		t.Fatalf("reading back the signature: %v", err)
	}
	if err := signer.Verify(entry, sig); err != nil {
		t.Errorf("stored signature does not verify: %v", err)
	}

	e.out.Reset()
	requireExit(t, runUpstreamList(e.opEnv, false), exitOK, "list")
	requireContains(t, e.stdoutText(), string(sigValid), "list")
	if bytes.Contains(e.out.Bytes(), []byte("unsigned")) {
		t.Errorf("list still reports an unsigned entry\n%s", e.stdoutText())
	}
}

// TestRunSign_ResigningIsNormalAndSaysWhatItDid: re-signing happens
// whenever an entry legitimately changes, so it must work -- and the three
// situations it can find itself in read very differently to an operator.
func TestRunSign_ResigningIsNormalAndSaysWhatItDid(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, e opTestEnv, entry registry.UpstreamServer)
		want  string
	}{
		{
			name:  "no previous signature",
			setup: func(*testing.T, opTestEnv, registry.UpstreamServer) {},
			want:  "This is the first signature stored",
		},
		{
			name: "previous signature by the same key, still valid",
			setup: func(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
				requireExit(t, runSign(e.opEnv, entry.Name), exitOK, "first sign")
				e.out.Reset()
			},
			want: "still-valid signature made with the same key",
		},
		{
			name: "previous signature by a different key",
			setup: func(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
				other, err := signer.GenerateKey()
				if err != nil {
					t.Fatalf("generating key: %v", err)
				}
				s, err := signer.NewSigner(other)
				if err != nil {
					t.Fatalf("new signer: %v", err)
				}
				if err := e.signatures().Put(context.Background(), entry.Name, s.Sign(entry)); err != nil {
					t.Fatalf("storing signature: %v", err)
				}
			},
			want: "made with a DIFFERENT key",
		},
		{
			name: "previous signature no longer matched the entry",
			setup: func(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
				key, err := signer.LoadKey(e.cfg.Signer.KeyFile)
				if err != nil {
					t.Fatalf("loading key: %v", err)
				}
				s, err := signer.NewSigner(key)
				if err != nil {
					t.Fatalf("new signer: %v", err)
				}
				// A signature over a different definition than the one
				// stored: what an edited -- or tampered-with -- entry
				// leaves behind.
				stale := entry
				stale.Command = "curl"
				if err := e.signatures().Put(context.Background(), entry.Name, s.Sign(stale)); err != nil {
					t.Fatalf("storing signature: %v", err)
				}
			},
			want: "did NOT match the entry",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			e.cfg.Signer.KeyFile = writeSigningKey(t, 0o600)
			entry := stdioEntry("casemgmt")
			mustRegister(t, e, entry)
			tc.setup(t, e, entry)

			requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, tc.name)
			requireContains(t, e.stdoutText(), tc.want, tc.name)

			// Whatever it found, the signature now stored must be the
			// valid one this key just made.
			sig, err := e.signatures().Get(context.Background(), "casemgmt")
			if err != nil {
				t.Fatalf("reading back: %v", err)
			}
			if err := signer.Verify(entry, sig); err != nil {
				t.Errorf("signature after re-signing does not verify: %v", err)
			}
		})
	}
}

func TestRunSign_UnknownEntryIsAProblem(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Signer.KeyFile = writeSigningKey(t, 0o600)

	requireExit(t, runSign(e.opEnv, "ghost"), exitProblem, "sign unknown")
	requireContains(t, e.stderrText(), `no upstream named "ghost"`, "sign unknown")
}

func TestCmdSign_BadUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no entry name", nil},
		{"two entry names", []string{"casemgmt", "logsearch"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			requireExit(t, cmdSign(tc.args, &out, &errBuf), exitCannotRun, tc.name)
			requireContains(t, errBuf.String(), "exactly one argument", tc.name)
		})
	}
}

// TestCmdSign_EndToEndThroughAConfigFile exercises the outer half,
// including reading signer.key_file out of a real configuration file.
func TestCmdSign_EndToEndThroughAConfigFile(t *testing.T) {
	keyFile := writeSigningKey(t, 0o600)
	configPath := writeOperatorConfig(t, "\n[signer]\nkey_file = \""+keyFile+"\"\nrequire_signed = true\n")

	var out, errBuf bytes.Buffer
	requireExit(t, cmdUpstream([]string{
		"register", "-config", configPath, "-name", "casemgmt",
		"-transport", "stdio", "-command", "docker",
	}, &out, &errBuf), exitOK, "register")
	// require_signed = true, so register must say the entry will not be
	// served until it is signed.
	requireContains(t, out.String(), "will NOT be served until it is signed", "register")

	out.Reset()
	errBuf.Reset()
	requireExit(t, cmdSign([]string{"-config", configPath, "casemgmt"}, &out, &errBuf), exitOK, "sign")

	out.Reset()
	errBuf.Reset()
	requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errBuf), exitOK, "list")
	requireContains(t, out.String(), string(sigValid), "list")
}
