package signer

// Signed-registry tampering tests (public Gatte). signer_test.go covers
// command, args-replaced and env-name-added; these cover every other field
// Canonical claims to bind, boundary-shifting edits that a naive encoding
// would miss, signature transplant between entries, bit flips, and Ed25519
// S-malleability.

import (
	"crypto/ed25519"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

func TestSecVerifyDetectsEveryBoundFieldTamper(t *testing.T) {
	tamper := map[string]func(registry.UpstreamServer) registry.UpstreamServer{
		"name changed":           func(s registry.UpstreamServer) registry.UpstreamServer { s.Name = "casemgmt2"; return s },
		"transport changed":      func(s registry.UpstreamServer) registry.UpstreamServer { s.Transport = "http"; return s },
		"url set":                func(s registry.UpstreamServer) registry.UpstreamServer { s.URL = "https://evil.example/mcp"; return s },
		"command trailing space": func(s registry.UpstreamServer) registry.UpstreamServer { s.Command += " "; return s },
		"env var name removed":   func(s registry.UpstreamServer) registry.UpstreamServer { s.EnvVarNames = s.EnvVarNames[:1]; return s },
		"env var name renamed": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.EnvVarNames = []string{"CASEMGMT_API_KEY", "LD_PRELOAD"}
			return s
		},
		"env var names cleared": func(s registry.UpstreamServer) registry.UpstreamServer { s.EnvVarNames = nil; return s },
		"env var name duplicated": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.EnvVarNames = append(slices.Clone(s.EnvVarNames), "CASEMGMT_URL")
			return s
		},
		"args reordered": func(s registry.UpstreamServer) registry.UpstreamServer {
			a := slices.Clone(s.Args)
			a[0], a[1] = a[1], a[0]
			s.Args = a
			return s
		},
		"two args joined": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.Args = []string{"run --rm", "-i", "casemgmt-mcp:latest"}
			return s
		},
		"arg split in two": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.Args = []string{"run", "--rm", "-i", "casemgmt-mcp", ":latest"}
			return s
		},
		"empty arg appended": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.Args = append(slices.Clone(s.Args), "")
			return s
		},
		"args cleared": func(s registry.UpstreamServer) registry.UpstreamServer { s.Args = nil; return s },
		"arg moved into command": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.Command = "docker run"
			s.Args = s.Args[1:]
			return s
		},
		"env name moved to arg": func(s registry.UpstreamServer) registry.UpstreamServer {
			s.Args = append(slices.Clone(s.Args), "CASEMGMT_URL")
			s.EnvVarNames = s.EnvVarNames[:1]
			return s
		},
	}
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := irisEntry()
	sig := s.Sign(entry)
	if err := v.Verify(entry, sig); err != nil {
		t.Fatalf("baseline Verify: %v", err)
	}
	for name, f := range tamper {
		t.Run(name, func(t *testing.T) {
			if err := v.Verify(f(irisEntry()), sig); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("Verify(%s) = %v, want ErrInvalidSignature", name, err)
			}
		})
	}
}

// TestSecSignatureCannotBeTransplantedBetweenEntries: an attacker who can
// write the registry DB copies the valid signature of a benign entry onto
// another row whose content is otherwise identical.
func TestSecSignatureCannotBeTransplantedBetweenEntries(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	benign := irisEntry()
	sig := s.Sign(benign)
	target := irisEntry()
	target.Name = "edr" // same command/args/env, different name
	if err := v.Verify(target, sig); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("signature of %q accepted for %q: %v", benign.Name, target.Name, err)
	}
}

func TestSecEverySingleBitFlipIsRejected(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := irisEntry()
	sig := s.Sign(entry)
	for i := range sig.Bytes {
		for bit := 0; bit < 8; bit++ {
			b := slices.Clone(sig.Bytes)
			b[i] ^= 1 << bit
			if err := v.Verify(entry, Signature{Bytes: b, PublicKey: sig.PublicKey}); err == nil {
				t.Fatalf("signature with byte %d bit %d flipped verified", i, bit)
			}
		}
	}
	// Truncated / extended signatures and keys.
	for _, bad := range []Signature{
		{Bytes: sig.Bytes[:len(sig.Bytes)-1], PublicKey: sig.PublicKey},
		{Bytes: append(slices.Clone(sig.Bytes), 0), PublicKey: sig.PublicKey},
		{Bytes: sig.Bytes, PublicKey: sig.PublicKey[:len(sig.PublicKey)-1]},
		{Bytes: make([]byte, ed25519.SignatureSize), PublicKey: sig.PublicKey},
		{},
	} {
		if err := v.Verify(entry, bad); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("malformed signature %x/%x accepted: %v", bad.Bytes, bad.PublicKey, err)
		}
	}
}

// TestSecMalleatedSignatureIsRejected: S' = S + L is the classic Ed25519
// malleability. A verifier that accepted it would let an attacker mint a
// second, different-looking valid signature row.
func TestSecMalleatedSignatureIsRejected(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := irisEntry()
	sig := s.Sign(entry)

	// L = 2^252 + 27742317777372353535851937790883648493
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	sBytes := slices.Clone(sig.Bytes[32:])
	slices.Reverse(sBytes) // little endian -> big endian
	sInt := new(big.Int).SetBytes(sBytes)
	sInt.Add(sInt, l)
	out := sInt.FillBytes(make([]byte, 32))
	slices.Reverse(out)
	mall := append(slices.Clone(sig.Bytes[:32]), out...)
	if err := v.Verify(entry, Signature{Bytes: mall, PublicKey: sig.PublicKey}); err == nil {
		t.Fatal("malleated (S+L) signature verified")
	}
}
