package vault_test

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/vault"
)

// probeSecret is the canary value. It is deliberately shaped like a real
// threat-intel API key so that a failure message reads like the incident it
// is standing in for.
const probeSecret = "vt-l3ak-check-9f8e7d6c5b4a"

// TestSecretNeverRendersPlaintext is the guard behind the sentence in
// vault.go that calls Value() "the only path to the plaintext". Without
// String/GoString/LogValue/MarshalText, fmt and slog reflect over the
// unexported field and print the credential -- Value() is then one of six
// paths, not one. No in-tree call site formats a Secret today, so this test
// exists to fail the build the first time someone writes
// slog.Any("cred", secret) or fmt.Errorf("resolving %v: %w", secret, err),
// rather than to catch a leak already shipped.
func TestSecretNeverRendersPlaintext(t *testing.T) {
	s := vault.NewSecret(probeSecret)

	// dialArgs stands in for the realistic accident: a Secret carried as a
	// field of some request/dial struct that a caller prints whole. Both
	// field cases are covered because fmt treats them differently -- it
	// honours String() on an exported field but cannot call a method on an
	// unexported one, so the exported case tests the method and the
	// unexported case tests that the stored representation is not the
	// plaintext either.
	type dialArgs struct {
		Upstream string
		Cred     vault.Secret
		cred     vault.Secret
	}
	args := dialArgs{Upstream: "threatintel", Cred: s, cred: s}

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	logger.Info("dialing", slog.Any("secret", s))
	logLine := logBuf.String()

	jsonBytes, err := json.Marshal(struct {
		Cred vault.Secret `json:"cred"`
	}{Cred: s})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	cases := []struct {
		name string
		got  string
	}{
		{"fmt %v", fmt.Sprintf("%v", s)},
		{"fmt %+v", fmt.Sprintf("%+v", s)},
		{"fmt %#v", fmt.Sprintf("%#v", s)},
		//lint:ignore S1025 Calling String() is exactly what this must NOT do: the
		// test verifies Secret stays redacted when rendered through the fmt verbs a
		// careless caller reaches for. Substituting String() tests the safe path.
		{"fmt %s", fmt.Sprintf("%s", s)},
		{"fmt %q", fmt.Sprintf("%q", s)},
		{"fmt %v on pointer", fmt.Sprintf("%v", &s)},
		{"fmt %+v on pointer", fmt.Sprintf("%+v", &s)},
		{"fmt.Errorf %v", fmt.Errorf("resolving %v: boom", s).Error()},
		{"enclosing struct %v", fmt.Sprintf("%v", args)},
		{"enclosing struct %+v", fmt.Sprintf("%+v", args)},
		{"enclosing struct %#v", fmt.Sprintf("%#v", args)},
		{"slog.Any", logLine},
		{"encoding/json", string(jsonBytes)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.got, probeSecret) {
				t.Fatalf("LEAK: %s rendered the plaintext secret: %s", tc.name, tc.got)
			}
		})
	}

	// Positive control: the probe value really is findable by the check
	// above, so a green run means redaction happened and not that the
	// assertion was looking for the wrong string.
	if !strings.Contains(fmt.Sprintf("%v", probeSecret), probeSecret) {
		t.Fatal("positive control failed: strings.Contains cannot find the probe value at all")
	}

	// And the carrier still carries: redaction must not have been achieved
	// by dropping the value.
	if s.Value() != probeSecret {
		t.Fatalf("Value() = %q, want %q", s.Value(), probeSecret)
	}
}

// TestSecretImplementsRedactionInterfaces pins the mechanism, not just the
// outcome. The four interfaces below are the only hooks fmt and slog
// consult before falling back to reflecting over unexported fields; a
// future edit that drops one of them would reopen exactly one of the leak
// paths above, and this test names which.
func TestSecretImplementsRedactionInterfaces(t *testing.T) {
	var s any = vault.NewSecret(probeSecret)

	if _, ok := s.(fmt.Stringer); !ok {
		t.Error("vault.Secret does not implement fmt.Stringer: the v and s verbs print the plaintext")
	}
	if _, ok := s.(fmt.GoStringer); !ok {
		t.Error("vault.Secret does not implement fmt.GoStringer: the sharp-v verb prints the plaintext")
	}
	if _, ok := s.(slog.LogValuer); !ok {
		t.Error("vault.Secret does not implement slog.LogValuer: slog.Any prints the plaintext")
	}
	if _, ok := s.(encoding.TextMarshaler); !ok {
		t.Error("vault.Secret does not implement encoding.TextMarshaler")
	}
}

// TestZeroSecretIsSafeToRender covers the zero value, which Provider
// implementations return on every error path (`return vault.Secret{}, err`).
// Redaction must not panic there.
func TestZeroSecretIsSafeToRender(t *testing.T) {
	var s vault.Secret

	if got := s.Value(); got != "" {
		t.Errorf("zero Secret Value() = %q, want empty", got)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(verb, s); got == "" {
			t.Errorf("zero Secret rendered with %s produced empty output", verb)
		}
	}
}
