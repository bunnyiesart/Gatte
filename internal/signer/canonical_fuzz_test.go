package signer

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

// fuzzEntry builds an UpstreamServer from flat fuzz inputs. Args and
// EnvVarNames are split on NUL so the fuzzer can move bytes across list
// element boundaries, which is exactly the shift a naive concatenation
// encoding would fail to distinguish.
func fuzzEntry(name, transport, command, url, args, env string) registry.UpstreamServer {
	s := registry.UpstreamServer{
		Name:      name,
		Transport: registry.Transport(transport),
		Command:   command,
		URL:       url,
	}
	if args != "" {
		s.Args = strings.Split(args, "\x00")
	}
	if env != "" {
		s.EnvVarNames = strings.Split(env, "\x00")
	}
	return s
}

// sameSigned reports whether a and b agree on every field Canonical is
// documented to cover (EnvVarNames compared as a set-with-multiplicity,
// since Canonical sorts it).
func sameSigned(a, b registry.UpstreamServer) bool {
	ea, eb := slices.Clone(a.EnvVarNames), slices.Clone(b.EnvVarNames)
	slices.Sort(ea)
	slices.Sort(eb)
	return a.Name == b.Name && a.Transport == b.Transport &&
		a.Command == b.Command && a.URL == b.URL &&
		slices.Equal(a.Args, b.Args) && slices.Equal(ea, eb)
}

// FuzzCanonicalInjective checks the property the signer's forgery
// resistance rests on: two entries that differ in any covered field never
// produce the same canonical bytes, and therefore a signature made for one
// never verifies for the other. It also checks Canonical does not mutate
// its input.
func FuzzCanonicalInjective(f *testing.F) {
	f.Add("casemgmt", "stdio", "ab", "", "c", "K", "casemgmt", "stdio", "a", "", "bc", "K")
	f.Add("a", "stdio", "cmd", "", "x\x00y", "B\x00A", "a", "stdio", "cmd", "", "x\x00y", "A\x00B")
	f.Add("n", "stdio", "c", "", "", "", "n", "stdio", "c", "", "\x00", "")
	f.Add("n", "stdio", "c", "u", "", "", "n", "stdio", "cu", "", "", "")

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	sg, err := NewSigner(priv)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewVerifier([]ed25519.PublicKey{sg.PublicKey()})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, n1, t1, c1, u1, a1, e1, n2, t2, c2, u2, a2, e2 string) {
		a := fuzzEntry(n1, t1, c1, u1, a1, e1)
		b := fuzzEntry(n2, t2, c2, u2, a2, e2)

		envBefore := slices.Clone(a.EnvVarNames)
		ca := Canonical(a)
		if !slices.Equal(envBefore, a.EnvVarNames) {
			t.Fatalf("Canonical mutated EnvVarNames: %q -> %q", envBefore, a.EnvVarNames)
		}
		cb := Canonical(b)

		equalBytes := bytes.Equal(ca, cb)
		equalEntries := sameSigned(a, b)
		if equalBytes != equalEntries {
			t.Fatalf("canonical collision mismatch: bytesEqual=%v entriesEqual=%v\na=%#v\nb=%#v", equalBytes, equalEntries, a, b)
		}
		if !equalEntries {
			if err := v.Verify(b, sg.Sign(a)); err == nil {
				t.Fatalf("signature for a verified for a different entry b\na=%#v\nb=%#v", a, b)
			}
		}
	})
}

// FuzzVerifyArbitrarySignature checks that Verify neither panics nor
// accepts on attacker-controlled signature and public-key bytes.
func FuzzVerifyArbitrarySignature(f *testing.F) {
	f.Add([]byte{}, []byte{})
	f.Add(bytes.Repeat([]byte{0}, ed25519.SignatureSize), bytes.Repeat([]byte{0}, ed25519.PublicKeySize))

	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	sg, err := NewSigner(priv)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewVerifier([]ed25519.PublicKey{sg.PublicKey()})
	if err != nil {
		f.Fatal(err)
	}
	entry := registry.UpstreamServer{Name: "x", Transport: registry.TransportStdio, Command: "/bin/true"}
	good := sg.Sign(entry)

	f.Fuzz(func(t *testing.T, sigBytes, pub []byte) {
		err := v.Verify(entry, Signature{Bytes: sigBytes, PublicKey: pub})
		if err == nil && !bytes.Equal(sigBytes, good.Bytes) {
			t.Fatalf("Verify accepted a signature that is not the one the trusted key made: %x", sigBytes)
		}
	})
}
