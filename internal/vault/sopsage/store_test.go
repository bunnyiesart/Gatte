package sopsage_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/vault/sopsage"
)

// TestStore_SetNamesDeleteRoundTripThroughSopsAndServeReadsIt is the write
// side of design/adr/0050 §2 against the real sops and age: a value set is
// what the read side (serve's Provider) resolves, the file keeps its mode,
// and the value is in no error and no file in clear.
func TestStore_SetNamesDeleteRoundTripThroughSopsAndServeReadsIt(t *testing.T) {
	const marker = "vault-marker-7f3e9a1c-not-a-real-secret"
	secretsFile, ageKeyFile := newFixture(t, map[string]string{"EXISTING": "keep-me"})
	if err := os.Chmod(secretsFile, 0o640); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := sopsage.NewStore(secretsFile, ageKeyFile)

	existed, err := st.Set(ctx, "NEW_KEY", []byte(marker))
	if err != nil || existed {
		t.Fatalf("Set: existed %v, %v", existed, err)
	}
	names, err := st.Names(ctx)
	if err != nil || !slices.Equal(names, []string{"EXISTING", "NEW_KEY"}) {
		t.Fatalf("Names = %v, %v", names, err)
	}
	raw, _ := os.ReadFile(secretsFile)
	if strings.Contains(string(raw), marker) || strings.Contains(string(raw), "keep-me") {
		t.Fatal("a value is in the secrets file in clear")
	}
	if fi, _ := os.Stat(secretsFile); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640 kept", fi.Mode().Perm())
	}
	p, err := sopsage.New(ctx, secretsFile, ageKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.Resolve(ctx, "NEW_KEY"); err != nil || got.Value() != marker {
		t.Fatalf("serve's read side does not see the value set: %v", err)
	}
	if got, err := p.Resolve(ctx, "EXISTING"); err != nil || got.Value() != "keep-me" {
		t.Fatalf("the value that was there is gone: %v", err)
	}

	if existed, err := st.Set(ctx, "NEW_KEY", []byte(marker+"-2")); err != nil || !existed {
		t.Fatalf("replace: existed %v, %v", existed, err)
	}
	if existed, err := st.Delete(ctx, "NEW_KEY"); err != nil || !existed {
		t.Fatalf("Delete: existed %v, %v", existed, err)
	}
	if existed, err := st.Delete(ctx, "NEW_KEY"); err != nil || existed {
		t.Fatalf("Delete again: existed %v, %v", existed, err)
	}
	if names, _ := st.Names(ctx); !slices.Equal(names, []string{"EXISTING"}) {
		t.Fatalf("after delete: %v", names)
	}
	if s := st.String(); strings.Contains(s, marker) {
		t.Fatal("String carries a value")
	}
}

// TestStore_AWrongIdentityChangesNothingAndSaysNoValue: a key that does
// not open the file is an error, the file is untouched, and the error
// carries no value.
func TestStore_AWrongIdentityChangesNothingAndSaysNoValue(t *testing.T) {
	const marker = "vault-marker-2b8d-not-a-real-secret"
	secretsFile, _ := newFixture(t, map[string]string{"A": marker})
	_, otherKey := newFixture(t, map[string]string{"B": "x"})
	before, _ := os.ReadFile(secretsFile)
	_, err := sopsage.NewStore(secretsFile, otherKey).Set(context.Background(), "C", []byte(marker))
	if err == nil {
		t.Fatal("a vault the identity cannot open was written")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("the error carries a value: %v", err)
	}
	if after, _ := os.ReadFile(secretsFile); string(after) != string(before) {
		t.Fatal("the secrets file changed")
	}
}
