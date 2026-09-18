package gateway

// Negative paths the rest of the suite states in prose but never exercises
// end to end through Connect.
//
// Two of them, both chosen because the "obvious" reading of the code is the
// wrong one:
//
//   - ADR-0010 item 4 says, in as many words, that with an empty trusted
//     set a SIGNED entry stops being served while an UNSIGNED one keeps
//     working -- "signing an entry makes it stop being served". That
//     inversion is asserted in internal/signer against the Verifier alone
//     (TestVerify_WithNoTrustedKeysRefusesEverything); nothing asserted it
//     where an operator actually meets it, which is a gateway that starts,
//     serves some upstreams and silently drops one.
//
//   - A credential the vault cannot resolve must stop the upstream BEFORE
//     the process is spawned, not after. TestConnect_OneBrokenUpstreamDoesNotStopTheOthers
//     shows such an upstream is not routed; it does not show that nothing
//     was executed, and "spawned, then judged" is the failure mode that
//     matters here -- a backend running without the credential it was told
//     to run with is a backend that will do something, just not the thing
//     the operator authorised.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// TestConnect_WithNoTrustedKeyASignedEntryIsRefusedAndAnUnsignedOneIsServed
// is ADR-0010 item 4 at the boundary where it bites.
//
// The configuration under test is coherent and not exotic: require_signed
// = false and signer.trusted_keys empty is what "we are not using signing
// yet" looks like, and config.Validate accepts it deliberately (it refuses
// only the opposite combination). What the ADR then decides, and what this
// asserts, is that a signature that cannot be checked is treated as
// invalid rather than as absent -- so the entry somebody signed is the one
// that stops being served, while the entry nobody signed keeps working.
//
// Both halves are asserted in one run, against one gateway, because either
// alone is satisfiable by a bug: refusing everything would pass the first
// half, and verifying nothing would pass the second.
func TestConnect_WithNoTrustedKeyASignedEntryIsRefusedAndAnUnsignedOneIsServed(t *testing.T) {
	h := newHarness(t, "casemgmt.list_cases", "logsearch.search")
	h.register("casemgmt")
	h.register("logsearch")
	h.serve("casemgmt", def("list_cases", "list cases"))
	h.serve("logsearch", def("search", "search logs"))

	// Whoever signed casemgmt used a real key. It is simply not one this
	// gateway was told to trust, because this gateway was told to trust
	// nobody.
	sgn := newTestSigner(t)
	signed := registry.UpstreamServer{
		Name:      "casemgmt",
		Transport: registry.TransportStdio,
		Command:   "/usr/bin/casemgmt",
	}
	h.gw.signatures = &signatureStore{sigs: map[string]signer.Signature{"casemgmt": sgn.Sign(signed)}}
	h.gw.verifier = trusting(t) // signer.trusted_keys = []
	h.gw.requireSig = false     // require_signed = false

	if n := h.gw.verifier.TrustedCount(); n != 0 {
		t.Fatalf("precondition: the verifier trusts %d keys, want 0", n)
	}

	err := h.connect()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Connect = %v, want ErrUpstreamUnavailable: a signature that cannot be checked is invalid, not absent (ADR-0010 item 4)", err)
	}
	if !errors.Is(err, signer.ErrInvalidSignature) {
		t.Errorf("Connect = %v, want the signer cause to remain inspectable as ErrInvalidSignature", err)
	}
	// The message is the mitigation the ADR names: the operator has to be
	// able to get from this line to the one-line fix.
	if !strings.Contains(err.Error(), "trusted_keys") {
		t.Errorf("the refusal does not name signer.trusted_keys, so it does not say what to do:\n%v", err)
	}

	if h.dialer.wasDialed("casemgmt") {
		t.Error("the signed entry was DIALED although its signature could not be checked")
	}
	if !h.dialer.wasDialed("logsearch") {
		t.Fatal("the unsigned entry was not dialed; with require_signed = false it must still be served")
	}

	// The unsigned one is fully usable. This is the half that reads
	// backwards on first encounter and is the reason the ADR wrote it down.
	h.approve("logsearch", "search")
	if got := h.listNames(analyst); len(got) != 1 || got[0] != "logsearch.search" {
		t.Errorf("ListTools = %v, want only logsearch.search: the entry nobody signed is the one that works", got)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "logsearch.search", json.RawMessage(`{}`)); err != nil {
		t.Errorf("Dispatch to the unsigned upstream: %v", err)
	}
	if _, err := h.gw.Dispatch(context.Background(), fromAnalyst, "casemgmt.list_cases", json.RawMessage(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Errorf("Dispatch to the refused upstream = %v, want ErrUnknownTool", err)
	}
}

// TestConnect_AnUnresolvableCredentialStopsTheUpstreamBeforeItIsSpawned
// answers "does the backend come up without the credential, or does the
// spawn fail with an error that says which one?" -- with: neither half of
// that is left to chance.
//
// The ordering claim is the load-bearing one. resolveEnv runs before
// Dialer.Dial, so an entry naming a variable the vault does not hold is
// never executed at all. If the two were the other way round, the upstream
// would be running -- with an empty environment, against whatever it does
// when its API key is missing -- while the gateway decided not to route it.
func TestConnect_AnUnresolvableCredentialStopsTheUpstreamBeforeItIsSpawned(t *testing.T) {
	const secretValue = "sk-live-must-never-appear"

	h := newHarness(t, "threatintel.lookup_ip", "logsearch.search")
	// TYPO_TOKEN is the realistic shape: an operator registered the entry
	// with a variable name that does not exist in secrets.json.
	h.register("threatintel", "TYPO_TOKEN")
	h.register("logsearch")
	h.serve("threatintel", def("lookup_ip", "look an address up"))
	h.serve("logsearch", def("search", "search logs"))
	// The vault holds a credential -- under a different name. So the
	// failure is a lookup miss and not an empty vault, and the value below
	// is in scope to leak if anything decides to be helpful about it.
	h.vault.values["VT_API_KEY"] = secretValue
	h.vault.errs["TYPO_TOKEN"] = vault.ErrNotFound

	err := h.connect()
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("Connect = %v, want ErrUpstreamUnavailable", err)
	}
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Connect = %v, want the vault cause to remain inspectable", err)
	}

	// Never spawned. This is the assertion the existing coverage is
	// missing: "not routed" and "not running" are different claims.
	if h.dialer.wasDialed("threatintel") {
		t.Error("an upstream whose credential could not be resolved was SPAWNED anyway; the process would be running without the credential it was authorised with")
	}

	// The error names the variable, because the name is not a secret and is
	// the only thing that turns this into a two-minute fix...
	if !strings.Contains(err.Error(), "TYPO_TOKEN") {
		t.Errorf("the refusal does not name the variable that could not be resolved:\n%v", err)
	}
	// ...and names nothing else.
	if strings.Contains(err.Error(), secretValue) {
		t.Error("the refusal carries a resolved credential value")
	}

	// One bad credential is not a fleet outage.
	if !h.dialer.wasDialed("logsearch") {
		t.Error("the healthy upstream was not dialed; one unresolvable credential must not stop the others")
	}
	h.approve("logsearch", "search")
	if got := h.listNames(analyst); len(got) != 1 || got[0] != "logsearch.search" {
		t.Errorf("ListTools = %v, want only logsearch.search", got)
	}
}
