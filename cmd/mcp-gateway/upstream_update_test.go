package main

import (
	"context"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

const ociTestImageNext = "localhost/casemgmt-mcp@sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// TestRunUpstreamUpdate_KeepsTheApprovalsOfUnchangedDefinitionsOnly is
// design/adr/0043 item 2: a new image digest keeps the quarantine, so a
// tool the new image advertises byte for byte stays approved and served,
// a rewritten one becomes changed the ordinary way, a new one is pending;
// the old signature stops verifying, so root has to sign again; and the
// update is an operator row.
func TestRunUpstreamUpdate_KeepsTheApprovalsOfUnchangedDefinitionsOnly(t *testing.T) {
	e := newOpTestEnv(t)
	e.opEnv.actor.Name, e.opEnv.actor.Front = "ana.ops", "cli"
	useSigningKey(t, e)
	ctx := context.Background()
	mustRegister(t, e, registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportOCI, Image: ociTestImage,
		Args: []string{"--network=none"}, EnvVarNames: []string{"CASEMGMT_API_KEY"}})
	requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign")
	getCase := quarantine.ToolIdentity{Name: "get_case", Description: "Get a case."}
	mustObserve(t, e, "casemgmt", irisListCases)
	mustApprove(t, e, "casemgmt", "list_cases")
	mustObserve(t, e, "casemgmt", getCase)
	mustApprove(t, e, "casemgmt", "get_case")

	e.out.Reset()
	requireExit(t, runUpstreamUpdate(e.opEnv, "casemgmt", ociTestImageNext), exitOK, "upstream update")
	out := e.stdoutText()
	for _, want := range []string{ociTestImage, ociTestImageNext, "2 approved, 0 pending, 0 changed", "does not verify this entry", "mcp-gateway sign casemgmt", "tool review -server casemgmt"} {
		requireContains(t, out, want, "upstream update")
	}
	entry, err := e.upstreams().Get(ctx, "casemgmt")
	if err != nil || entry.Image != ociTestImageNext || entry.Args[0] != "--network=none" {
		t.Fatalf("entry %+v, %v", entry, err)
	}
	if state, err := entrySignatureState(e.opEnv, entry); err != nil || state != sigInvalid {
		t.Fatalf("signature state %s, %v; want the old signature refused until root signs again", state, err)
	}
	for _, name := range []string{"list_cases", "get_case"} {
		if got, _ := e.tools().Get(ctx, "casemgmt", name); !got.Usable() {
			t.Fatalf("%s lost its approval to the update: %+v", name, got)
		}
	}

	// The new image's first discovery: one definition unchanged, one
	// rewritten, one new.
	mustObserve(t, e, "casemgmt", irisListCases)
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "get_case", Description: "Get a case, and its attachments."})
	mustObserve(t, e, "casemgmt", quarantine.ToolIdentity{Name: "export_case", Description: "Export."})
	for name, want := range map[string]quarantine.Status{"list_cases": quarantine.StatusApproved, "get_case": quarantine.StatusChanged, "export_case": quarantine.StatusPending} {
		got, _ := e.tools().Get(ctx, "casemgmt", name)
		if got.Status != want || got.Usable() != (want == quarantine.StatusApproved) {
			t.Errorf("%s after the new image's discovery: %+v, want %s", name, got, want)
		}
	}

	recs, err := e.auditTrail().List(ctx)
	if err != nil || len(recs) != 1 || recs[0].Tool != "(upstream update)" || recs[0].AnalystIdentity != "(operator:ana.ops)" ||
		!strings.Contains(recs[0].Reason, ociTestImage+" -> "+ociTestImageNext) || !strings.Contains(recs[0].Reason, "[cli]") {
		t.Fatalf("rows %+v, %v; want one (upstream update) row naming both images", recs, err)
	}

	e.out.Reset()
	requireExit(t, runSign(e.opEnv, "casemgmt"), exitOK, "sign the new image")
	if state, _ := entrySignatureState(e.opEnv, entry); state != sigValid {
		t.Fatalf("after re-signing: %s", state)
	}
}

func TestRunUpstreamUpdate_Refusals(t *testing.T) {
	e := newOpTestEnv(t)
	mustRegister(t, e, stdioEntry("logsearch"))
	mustRegister(t, e, registry.UpstreamServer{Name: "casemgmt", Transport: registry.TransportOCI, Image: ociTestImage})

	requireExit(t, runUpstreamUpdate(e.opEnv, "ghost", ociTestImageNext), exitProblem, "unknown name")
	requireExit(t, runUpstreamUpdate(e.opEnv, "logsearch", ociTestImageNext), exitCannotRun, "stdio entry")
	requireContains(t, e.stderrText(), "only an oci entry runs an image", "stdio entry")
	requireExit(t, runUpstreamUpdate(e.opEnv, "casemgmt", "localhost/casemgmt-mcp:latest"), exitCannotRun, "a tag")
	requireExit(t, runUpstreamUpdate(e.opEnv, "casemgmt", ociTestImage), exitOK, "the same image")
	requireContains(t, e.stdoutText(), "Nothing to do", "the same image")
	if got, _ := e.upstreams().Get(context.Background(), "casemgmt"); got.Image != ociTestImage {
		t.Fatalf("a refused update changed the image: %q", got.Image)
	}
	if recs, _ := e.auditTrail().List(context.Background()); len(recs) != 0 {
		t.Fatalf("refusals wrote rows: %+v", recs)
	}
	var out, errBuf strings.Builder
	if code := cmdUpstream([]string{"update", "casemgmt"}, &out, &errBuf); code != exitCannotRun {
		t.Errorf("update without -image: %d", code)
	}
}
