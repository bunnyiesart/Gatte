package quarantine

import "testing"

// A tool that declares no output schema keeps its v1 fingerprint byte for
// byte, so adding OutputSchema to the identity re-quarantines only the
// tools that declare one. The golden value was computed with the encoder
// before the change (Gatte 317d8be).
func TestHash_WithoutOutputSchemaKeepsTheV1Fingerprint(t *testing.T) {
	const golden = "bc771454a67d9a0f8442967cebd6e92cc20a049a00b4877b201d802980f32a53"
	got := Hash(ToolIdentity{Name: "list_cases", Description: "List cases.", InputSchema: []byte(`{"type":"object"}`)})
	if got != golden {
		t.Fatalf("v1 fingerprint moved: %s, want %s -- every approval of a tool without an output schema would be lost", got, golden)
	}
}

func TestHash_CoversTheOutputSchema(t *testing.T) {
	base := ToolIdentity{Name: "list_cases", Description: "List cases.", InputSchema: []byte(`{"type":"object"}`)}
	strict, loose := base, base
	strict.OutputSchema = []byte(`{"type":"object","required":["id"]}`)
	loose.OutputSchema = []byte(`{"type":"object"}`)
	if Hash(strict) == Hash(loose) {
		t.Fatal("loosening the output schema did not change the fingerprint")
	}
	if Hash(strict) == Hash(base) {
		t.Fatal("dropping the output schema did not change the fingerprint")
	}
}
