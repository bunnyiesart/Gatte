package signer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
)

func ociEntry() registry.UpstreamServer {
	return registry.UpstreamServer{
		Name:        "casemgmt",
		Transport:   registry.TransportOCI,
		Args:        []string{"--network=none"},
		Image:       "localhost/casemgmt-mcp@sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)),
		EnvVarNames: []string{"CASEMGMT_API_KEY"},
	}
}

// The digest IS the code that runs: re-pointing an oci entry at other bytes
// must break its signature.
func TestVerify_OCIEntryDetectsImageSwap(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := ociEntry()
	sig := s.Sign(entry)
	if err := v.Verify(entry, sig); err != nil {
		t.Fatalf("Verify(untouched oci entry): %v", err)
	}
	swapped := entry
	swapped.Image = "localhost/casemgmt-mcp@sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32))
	if err := v.Verify(swapped, sig); err == nil {
		t.Fatal("Verify accepted an oci entry whose image digest was swapped under its signature")
	}
}

// Entries without an image keep the v1 encoding byte for byte, so every
// signature made before the oci transport existed still verifies. The
// golden hash pins those bytes: if it moves, every deployed stdio
// signature just stopped verifying.
func TestCanonical_StdioEntryKeepsV1Bytes(t *testing.T) {
	c := Canonical(irisEntry())
	if !bytes.Contains(c, []byte(canonicalTag)) || bytes.Contains(c, []byte(canonicalTagImage)) {
		t.Fatalf("a stdio entry without an image must use %q only", canonicalTag)
	}
	const golden = "3917b8a3a9299a222e199e0ea88de1edd0f2f966e4789718b4b05fe9faa28daa" // computed from the pre-oci encoder (Gatte d1aa079)
	sum := sha256.Sum256(c)
	if got := hex.EncodeToString(sum[:]); got != golden {
		t.Fatalf("v1 canonical bytes moved: sha256 %s, want %s", got, golden)
	}
}

// A stdio row that acquires an image (a direct database write; Validate
// refuses it at registration) must stop verifying rather than keep its old
// signature.
func TestVerify_ImageInjectedIntoStdioRowBreaksSignature(t *testing.T) {
	s := newSigner(t)
	v := newVerifier(t, s)
	entry := irisEntry()
	sig := s.Sign(entry)
	entry.Image = ociEntry().Image
	if err := v.Verify(entry, sig); err == nil {
		t.Fatal("Verify accepted a stdio entry with an injected image under its v1 signature")
	}
}

// The same fields under oci and under stdio never encode alike.
func TestCanonical_OCIAndStdioNeverCoincide(t *testing.T) {
	o := ociEntry()
	st := o
	st.Transport = registry.TransportStdio
	st.Image = ""
	if bytes.Equal(Canonical(o), Canonical(st)) {
		t.Fatal("oci and stdio entries produced identical canonical bytes")
	}
}
