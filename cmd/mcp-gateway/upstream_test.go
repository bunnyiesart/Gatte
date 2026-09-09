package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

func TestRunUpstreamRegisterThenList_RoundTrips(t *testing.T) {
	tests := []struct {
		name  string
		entry registry.UpstreamServer
		want  []string
	}{
		{
			name:  "stdio entry with args and env var names",
			entry: stdioEntry("casemgmt"),
			want:  []string{"casemgmt", "stdio", "docker run --rm casemgmt-mcp", "CASEMGMT_URL, CASEMGMT_API_KEY"},
		},
		{
			name: "http entry",
			entry: registry.UpstreamServer{
				Name:      "logsearch",
				Transport: registry.TransportHTTP,
				URL:       "https://logsearch.internal/mcp",
			},
			want: []string{"logsearch", "http", "https://logsearch.internal/mcp"},
		},
		{
			name: "stdio entry with a whitespace-containing argument is quoted",
			entry: registry.UpstreamServer{
				Name:      "threatintel",
				Transport: registry.TransportStdio,
				Command:   "/usr/local/bin/threatintel",
				Args:      []string{"--flag", "two words"},
			},
			want: []string{`/usr/local/bin/threatintel --flag "two words"`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)

			requireExit(t, runUpstreamRegister(e.opEnv, tc.entry), exitOK, "register")
			e.out.Reset()
			requireExit(t, runUpstreamList(e.opEnv, false), exitOK, "list")

			for _, want := range tc.want {
				requireContains(t, e.stdoutText(), want, "list")
			}
			// A freshly registered entry has no signature, and the table
			// must say so rather than leave the column ambiguous.
			requireContains(t, e.stdoutText(), "SIGNED", "list")
			requireContains(t, e.stdoutText(), "unsigned", "list")
		})
	}
}

// TestRunUpstreamRegister_SaysTheEntryIsNotSigned pins the behaviour that
// makes register safe to run: it never signs, and it never lets that be a
// surprise discovered at the next restart.
func TestRunUpstreamRegister_SaysTheEntryIsNotSigned(t *testing.T) {
	tests := []struct {
		name          string
		requireSigned bool
		want          string
	}{
		{
			name:          "require_signed false: the gateway warns",
			requireSigned: false,
			want:          "still be served",
		},
		{
			name:          "require_signed true: the gateway refuses",
			requireSigned: true,
			want:          "will NOT be served until it is signed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			e.cfg.Signer.RequireSigned = &tc.requireSigned

			requireExit(t, runUpstreamRegister(e.opEnv, stdioEntry("casemgmt")), exitOK, "register")
			requireContains(t, e.stdoutText(), "NOT SIGNED", "register")
			requireContains(t, e.stdoutText(), "mcp-gateway sign casemgmt", "register")
			requireContains(t, e.stdoutText(), tc.want, "register")
		})
	}
}

// TestUpstreamRegister_InvalidEntryIsRejected drives the real flag surface:
// validation happens before the config is even read, so a malformed entry
// costs nothing and reports the rule it broke.
func TestUpstreamRegister_InvalidEntryIsRejected(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no name",
			args: []string{"register", "-transport", "stdio", "-command", "docker"},
			want: "name must not be empty",
		},
		{
			name: "unknown transport",
			args: []string{"register", "-name", "casemgmt", "-transport", "carrier-pigeon", "-command", "docker"},
			want: `transport must be "stdio" or "http"`,
		},
		{
			name: "stdio without a command",
			args: []string{"register", "-name", "casemgmt", "-transport", "stdio"},
			want: "command must not be empty for stdio transport",
		},
		{
			name: "http without a url",
			args: []string{"register", "-name", "casemgmt", "-transport", "http"},
			want: "url must not be empty for http transport",
		},
		{
			name: "env var name with whitespace",
			args: []string{"register", "-name", "casemgmt", "-transport", "stdio", "-command", "docker", "-env", "CASEMGMT KEY"},
			want: `env var name must not contain "=" or whitespace`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			// No -config: an invalid entry must be refused before anything
			// tries to open a database.
			code := cmdUpstream(tc.args, &out, &errBuf)
			requireExit(t, code, exitCannotRun, tc.name)
			requireContains(t, errBuf.String(), tc.want, tc.name)
		})
	}
}

func TestRunUpstreamRegister_DuplicateNameIsAProblem(t *testing.T) {
	e := newOpTestEnv(t)
	mustRegister(t, e, stdioEntry("casemgmt"))

	requireExit(t, runUpstreamRegister(e.opEnv, stdioEntry("casemgmt")), exitProblem, "duplicate register")
	requireContains(t, e.stderrText(), "already registered", "duplicate register")
}

func TestRunUpstreamDeregister(t *testing.T) {
	t.Run("unknown name is a problem, not a crash", func(t *testing.T) {
		e := newOpTestEnv(t)

		requireExit(t, runUpstreamDeregister(e.opEnv, "ghost"), exitProblem, "deregister unknown")
		requireContains(t, e.stderrText(), `no upstream named "ghost"`, "deregister unknown")
	})

	t.Run("removes the entry", func(t *testing.T) {
		e := newOpTestEnv(t)
		mustRegister(t, e, stdioEntry("casemgmt"))

		requireExit(t, runUpstreamDeregister(e.opEnv, "casemgmt"), exitOK, "deregister")
		if _, err := e.upstreams().Get(context.Background(), "casemgmt"); !errors.Is(err, registry.ErrNotFound) {
			t.Errorf("after deregister, Get returned %v, want registry.ErrNotFound", err)
		}
	})

	t.Run("removes the stored signature with it", func(t *testing.T) {
		// A signature keyed by name would otherwise outlive the entry and
		// authenticate whatever is registered under that name next.
		e := newOpTestEnv(t)
		useSigningKey(t, e)
		mustRegister(t, e, stdioEntry("casemgmt"))
		requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")
		e.out.Reset()

		requireExit(t, runUpstreamDeregister(e.opEnv, "casemgmt"), exitOK, "deregister")
		requireContains(t, e.stdoutText(), "signature was removed", "deregister")
		if _, err := e.signatures().Get(context.Background(), "casemgmt"); !errors.Is(err, signer.ErrNotFound) {
			t.Errorf("after deregister, signature Get returned %v, want signer.ErrNotFound", err)
		}
	})
}

func TestRunUpstreamList_EmptyRegistryIsAProblem(t *testing.T) {
	e := newOpTestEnv(t)

	requireExit(t, runUpstreamList(e.opEnv, false), exitProblem, "list empty")
	requireContains(t, e.stdoutText(), "No upstream servers are registered", "list empty")
}

func TestRunUpstreamList_JSONCarriesNamesAndSignatureState(t *testing.T) {
	e := newOpTestEnv(t)
	mustRegister(t, e, stdioEntry("casemgmt"))

	requireExit(t, runUpstreamList(e.opEnv, true), exitOK, "list -json")

	var got []upstreamJSON
	if err := json.Unmarshal(e.out.Bytes(), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, e.stdoutText())
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if want := []string{"CASEMGMT_URL", "CASEMGMT_API_KEY"}; strings.Join(got[0].EnvVarNames, ",") != strings.Join(want, ",") {
		t.Errorf("env var names = %v, want %v", got[0].EnvVarNames, want)
	}
	if got[0].Signature != string(sigUnsigned) {
		t.Errorf("signature = %q, want %q", got[0].Signature, sigUnsigned)
	}
}

// TestRunUpstreamList_SignatureStates covers the three distinguishable
// answers to "will the gateway trust this entry". The invalid case is set
// up the way reality would produce it: a signature that was made over
// different bytes than the entry now holds.
func TestRunUpstreamList_SignatureStates(t *testing.T) {
	tests := []struct {
		name       string
		sign       func(t *testing.T, e opTestEnv, entry registry.UpstreamServer)
		wantColumn string
		wantNote   string
	}{
		{
			name:       "unsigned",
			sign:       func(*testing.T, opTestEnv, registry.UpstreamServer) {},
			wantColumn: string(sigUnsigned),
			wantNote:   "1 unsigned entry",
		},
		{
			name: "signed and valid",
			sign: func(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
				useSigningKey(t, e)
				requireExit(t, runSign(e.opEnv, entry.Name), exitOK, "sign")
				e.out.Reset()
			},
			wantColumn: string(sigValid),
			wantNote:   "1 entry.",
		},
		{
			name: "stored signature does not match the entry",
			sign: func(t *testing.T, e opTestEnv, entry registry.UpstreamServer) {
				key, err := signer.GenerateKey()
				if err != nil {
					t.Fatalf("generating key: %v", err)
				}
				s, err := signer.NewSigner(key)
				if err != nil {
					t.Fatalf("new signer: %v", err)
				}
				tampered := entry
				tampered.Command = "curl"
				if err := e.signatures().Put(context.Background(), entry.Name, s.Sign(tampered)); err != nil {
					t.Fatalf("storing signature: %v", err)
				}
			},
			wantColumn: string(sigInvalid),
			wantNote:   "will NOT serve",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpTestEnv(t)
			entry := stdioEntry("casemgmt")
			mustRegister(t, e, entry)
			tc.sign(t, e, entry)

			requireExit(t, runUpstreamList(e.opEnv, false), exitOK, "list")
			requireContains(t, e.stdoutText(), tc.wantColumn, "list")
			requireContains(t, e.stdoutText(), tc.wantNote, "list")
		})
	}
}

func TestCmdUpstream_BadUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"unknown subcommand", []string{"delete"}},
		{"list with a stray argument", []string{"list", "casemgmt"}},
		{"deregister without a name", []string{"deregister"}},
		{"deregister with two names", []string{"deregister", "casemgmt", "logsearch"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			requireExit(t, cmdUpstream(tc.args, &out, &errBuf), exitCannotRun, tc.name)
			if errBuf.Len() == 0 {
				t.Errorf("%s: nothing was written to stderr", tc.name)
			}
		})
	}
}

// TestCmdUpstream_EndToEndThroughAConfigFile proves the outer half works:
// flags parsed, config read, database opened and migrated, entry
// persisted across two separate command invocations.
func TestCmdUpstream_EndToEndThroughAConfigFile(t *testing.T) {
	configPath := writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))

	var out, errBuf bytes.Buffer
	code := cmdUpstream([]string{
		"register", "-config", configPath, "-name", "casemgmt",
		"-transport", "stdio", "-command", "docker",
		"-arg", "run", "-arg", "--rm", "-arg", "casemgmt-mcp",
		"-env", "CASEMGMT_API_KEY",
	}, &out, &errBuf)
	requireExit(t, code, exitOK, "register")

	out.Reset()
	errBuf.Reset()
	requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errBuf), exitOK, "list")
	requireContains(t, out.String(), "docker run --rm casemgmt-mcp", "list")
	requireContains(t, out.String(), "CASEMGMT_API_KEY", "list")

	out.Reset()
	errBuf.Reset()
	requireExit(t, cmdUpstream([]string{"deregister", "-config", configPath, "casemgmt"}, &out, &errBuf), exitOK, "deregister")

	out.Reset()
	errBuf.Reset()
	requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errBuf), exitProblem, "list after deregister")
}
