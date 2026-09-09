package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// useSigningKey sets up the two halves an operator has to set up before
// the gateway will serve a signed entry: a private key to sign with, and
// its public half in signer.trusted_keys so the signature counts for
// anything (ADR-0010).
//
// Both, not one, because since ADR-0010 signing alone changes nothing an
// operator can observe -- `upstream list` reports INVALID for an entry
// signed by a key the configuration does not name. Tests that want the
// happy path have to model the paste step, and tests that want to see the
// paste step *not* done use writeSigningKey directly.
func useSigningKey(t *testing.T, e opTestEnv) string {
	t.Helper()

	path := writeSigningKey(t, 0o600)
	e.cfg.Signer.KeyFile = path
	e.cfg.Signer.TrustedKeys = append(e.cfg.Signer.TrustedKeys, trustedKeyFor(t, path))
	return path
}

// trustedKeyFor returns the trusted_keys value for the key file at path:
// the base64 of its public half.
func trustedKeyFor(t *testing.T, path string) string {
	t.Helper()

	key, err := signer.LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey(%s): %v", path, err)
	}
	s, err := signer.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return base64.StdEncoding.EncodeToString(s.PublicKey())
}

// mustVerifier builds the trust anchor the console would build from e's
// configuration -- the same one the gateway builds at boot.
func mustVerifier(t *testing.T, e opTestEnv) *signer.Verifier {
	t.Helper()

	v, err := opVerifier(e.opEnv)
	if err != nil {
		t.Fatalf("opVerifier: %v", err)
	}
	return v
}

// signerSection renders the [signer] block a configuration file needs in
// order to load at all now that require_signed defaults to true: the key
// to sign with, and its public half in trusted_keys.
func signerSection(t *testing.T, keyFile string) string {
	t.Helper()

	return "\n[signer]\nkey_file = \"" + keyFile + "\"\n" +
		"require_signed = true\ntrusted_keys = [\"" + trustedKeyFor(t, keyFile) + "\"]\n"
}

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
	useSigningKey(t, e)
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
	if err := mustVerifier(t, e).Verify(entry, sig); err != nil {
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
			useSigningKey(t, e)
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
			if err := mustVerifier(t, e).Verify(entry, sig); err != nil {
				t.Errorf("signature after re-signing does not verify: %v", err)
			}
		})
	}
}

// TestRunSign_PrintsThePasteReadyTrustedKeysLine is ADR-0010 item 4: a
// control that gives an operator work to turn on stays off.
//
// Signing with a key that is not in signer.trusted_keys stores a signature
// the gateway will refuse. Nothing about that is visible from the sign
// command's other output -- it says "Signed" and looks like success. So the
// command that creates the gap prints the line that closes it, in the exact
// encoding the field wants, and says plainly that the entry is not being
// served yet.
func TestRunSign_PrintsThePasteReadyTrustedKeysLine(t *testing.T) {
	t.Run("key not yet trusted", func(t *testing.T) {
		e := newOpTestEnv(t)
		keyFile := writeSigningKey(t, 0o600)
		e.cfg.Signer.KeyFile = keyFile // ...and deliberately NOT trusted.
		entry := stdioEntry("casemgmt")
		mustRegister(t, e, entry)

		requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")

		out := e.stdoutText()
		for _, want := range []string{"will NOT serve", "trusted_keys", trustedKeyFor(t, keyFile)} {
			requireContains(t, out, want, "sign with an untrusted key")
		}
		// And it must not claim success it is about to retract. A command
		// that says "the gateway will now serve it" and then explains that
		// it will not has taught the operator to stop reading.
		if strings.Contains(out, "will now serve it") {
			t.Errorf("sign claims the entry is now served while also saying it is not:\n%s", out)
		}

		// The printed value must be exactly what the field accepts, with no
		// editing: a line the operator has to fix up before it works is a
		// line they will get wrong at 3am. Pasting it must also be
		// *sufficient* -- the entry goes from refused to served with that
		// one edit and nothing else.
		e.cfg.Signer.TrustedKeys = []string{trustedKeyFor(t, keyFile)}
		if _, err := e.cfg.Signer.TrustedPublicKeys(); err != nil {
			t.Fatalf("the printed trusted_keys value is not accepted by the config parser: %v", err)
		}
		e.out.Reset()
		requireExit(t, runUpstreamList(e.opEnv, false), exitOK, "list")
		requireContains(t, e.stdoutText(), string(sigValid), "list after pasting the key")
	})

	t.Run("key already trusted", func(t *testing.T) {
		e := newOpTestEnv(t)
		useSigningKey(t, e)
		mustRegister(t, e, stdioEntry("casemgmt"))

		requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")

		// No nagging when there is nothing to do. An instruction that
		// prints every time is an instruction nobody reads the day it
		// matters.
		if strings.Contains(e.stdoutText(), "trusted_keys") {
			t.Errorf("sign told the operator to add a key that is already trusted:\n%s", e.stdoutText())
		}
	})
}

// TestRunSign_UntrustedKeyMakesTheEntryINVALIDNotUnsigned pins the
// distinction ADR-0010 item 2 insists on. An entry signed by a key this
// gateway does not know is not "not signed yet": somebody signed it, with
// something, and the console must not round that down to a benign state.
func TestRunSign_UntrustedKeyMakesTheEntryINVALIDNotUnsigned(t *testing.T) {
	e := newOpTestEnv(t)
	e.cfg.Signer.KeyFile = writeSigningKey(t, 0o600)
	mustRegister(t, e, stdioEntry("casemgmt"))

	requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")

	// Asserted through the JSON form rather than the table: sigUnsigned is
	// the string "no", which occurs inside half the prose the table prints
	// ("not", "names only"), so a substring check against the table would
	// pass or fail for reasons unrelated to the signature column.
	e.out.Reset()
	requireExit(t, runUpstreamList(e.opEnv, true), exitOK, "list -json")

	var got []upstreamJSON
	if err := json.Unmarshal(e.out.Bytes(), &got); err != nil {
		t.Fatalf("parsing list -json: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 1 {
		t.Fatalf("listed %d entries, want 1", len(got))
	}
	if got[0].Signature != string(sigInvalid) {
		t.Errorf("signature state = %q, want %q -- somebody signed this entry with a key this gateway does not know, which is not the same as nobody having signed it", got[0].Signature, sigInvalid)
	}
}

func TestRunSign_UnknownEntryIsAProblem(t *testing.T) {
	e := newOpTestEnv(t)
	useSigningKey(t, e)

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
	configPath := writeOperatorConfig(t, signerSection(t, keyFile))

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
