package gateway

// Tests of design/adr/0048 Decisão 5, the gateway half: the security class
// reaches the quarantine as metadata outside the fingerprint, and the
// class-aware gate at the dispatch edge refuses a sensitive tool that a
// caller reaches only by wildcard or from a read role -- on every call, in
// the listing too, and across a reload.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
)

// sensitiveDef is def with the class a Dialer derives from a method that
// acts (POST, PUT, DELETE ...). Nothing else differs, which is the point of
// TestIdentityOf_SecurityClassIsOutsideTheFingerprint.
func sensitiveDef(name, description string) ToolDef {
	d := def(name, description)
	d.SecurityClass = quarantine.ClassSensitive
	return d
}

// approveAndClear gives a sensitive tool both operator decisions, through
// the quarantine's own transitions, and asserts the second was needed.
func (h *harness) approveAndClear(server, tool string) {
	h.t.Helper()
	got, err := h.quarantine.Approve(context.Background(), server, tool)
	if err != nil {
		h.t.Fatalf("Approve(%q, %q): %v", server, tool, err)
	}
	if got.Usable() {
		h.t.Fatalf("Approve(%q, %q) alone made a sensitive tool usable: %+v", server, tool, got)
	}
	got, err = h.quarantine.Clear(context.Background(), server, tool)
	if err != nil {
		h.t.Fatalf("Clear(%q, %q): %v", server, tool, err)
	}
	if !got.Usable() {
		h.t.Fatalf("Clear(%q, %q) did not yield a usable tool: %+v", server, tool, got)
	}
}

// applyRoles swaps the policy in force for one holding exactly roles, the
// way a reload does (ADR-0044). A single role is mapped from the harness
// analyst's own group; several are mapped from one group each, and
// callerWithRoles builds the identity that carries them all.
func (h *harness) applyRoles(roles ...access.Role) {
	h.t.Helper()
	mapping := map[string]string{}
	if len(roles) == 1 {
		mapping["soc-n1"] = roles[0].Name
	}
	for _, r := range roles {
		mapping["g-"+r.Name] = r.Name
	}
	p, err := access.NewPolicy(roles, mapping)
	if err != nil {
		h.t.Fatalf("NewPolicy: %v", err)
	}
	if err := h.gw.ApplyPolicy(context.Background(), p, mustGate(h.t, nil, nil)); err != nil {
		h.t.Fatalf("ApplyPolicy: %v", err)
	}
}

// callerWithRoles is the harness analyst carrying one group per role name,
// for policies applyRoles built from several roles.
func callerWithRoles(roles ...access.Role) Caller {
	id := analyst
	id.Groups = nil
	for _, r := range roles {
		id.Groups = append(id.Groups, "g-"+r.Name)
	}
	return Caller{Identity: id, SourceAddress: analystSource}
}

func reasonsOf(rows []audit.Record) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Reason)
	}
	return out
}

// TestIdentityOf_SecurityClassIsOutsideTheFingerprint pins the "by
// construction" of ADR-0048 Decisão 5: identityOf never reads the field, so
// two definitions differing only in class hash the same, and a method
// change can never flip an approved tool to changed.
func TestIdentityOf_SecurityClassIsOutsideTheFingerprint(t *testing.T) {
	safe := def("submit", "submit a sample")
	sensitive := sensitiveDef("submit", "submit a sample")
	if quarantine.Hash(identityOf(safe)) != quarantine.Hash(identityOf(sensitive)) {
		t.Fatal("SecurityClass moved the quarantine fingerprint: it must be metadata beside the identity, not inside it")
	}
}

// TestRoutesFor_ObservesTheRealClass: the class on the ToolDef is what the
// quarantine records, and an approval alone does not serve it -- Layer 1's
// default-deny, now fed by the real value rather than ClassSafe.
func TestRoutesFor_ObservesTheRealClass(t *testing.T) {
	h := newHarness(t, "casemgmt.close_case", "casemgmt.list_cases")
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"), sensitiveDef("close_case", "close"))
	h.mustConnect()

	if got := h.quarantineStatus("casemgmt", "close_case"); got.Class != quarantine.ClassSensitive {
		t.Fatalf("close_case observed with class %q, want %q", got.Class, quarantine.ClassSensitive)
	}
	if got := h.quarantineStatus("casemgmt", "list_cases"); got.Class != quarantine.ClassSafe {
		t.Fatalf("list_cases observed with class %q, want safe", got.Class)
	}

	// Approved but not cleared: invisible and uncallable, opaque to the
	// caller, "quarantined" in the trail -- the role here is a flat list
	// without the non-read marking, so this caller would be refused by
	// the class gate first; see the next test for a role that passes it.
	if _, err := h.quarantine.Approve(context.Background(), "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	if listed := h.listNames(analyst); slices.Contains(listed, "casemgmt.close_case") {
		t.Fatalf("an approved, uncleared sensitive tool is listed: %v", listed)
	}
}

// TestDispatch_SensitiveToolCoveredOnlyByGrantAllInAReadRoleIsRefused is
// the bypass the ADR's review caught, and the central test of this layer.
//
// The tool is approved AND cleared, so Usable is true. The role reaches it
// by name through `grants = {casemgmt = ["*"]}` -- Authorize passes. Before
// the gate, the call went out. Now: refused with the forbidden class, the
// upstream never reached, one row in the trail with the distinct reason,
// and the safe tool on the same backend served under the same role.
func TestDispatch_SensitiveToolCoveredOnlyByGrantAllInAReadRoleIsRefused(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"), sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.approveAndClear("casemgmt", "close_case")
	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})

	// Precondition: by name alone the role reaches the tool. This is what
	// made the bypass a bypass.
	if err := h.gw.Policy().Authorize(analyst, "casemgmt.close_case"); err != nil {
		t.Fatalf("precondition: Authorize by name = %v, want allowed through the wildcard", err)
	}

	_, err := h.dispatch("casemgmt.close_case")
	if !errors.Is(err, access.ErrForbidden) || !errors.Is(err, ErrSensitiveNotGranted) {
		t.Fatalf("Dispatch(close_case) = %v, want ErrSensitiveNotGranted wrapping access.ErrForbidden", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Fatalf("upstream was reached on a refused sensitive call: %+v", calls)
	}
	rows := h.auditRows()
	if len(rows) != 1 || rows[0].Outcome != audit.OutcomeDenied || rows[0].Reason != reasonSensitiveNotGranted {
		t.Fatalf("trail = %+v, want one denied row with reason %q", rows, reasonSensitiveNotGranted)
	}
	if rows[0].Tool != "casemgmt.close_case" || rows[0].TargetUpstream != "casemgmt" {
		t.Fatalf("row names %q -> %q", rows[0].Tool, rows[0].TargetUpstream)
	}

	// The listing agrees with the call path, for this caller.
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Fatalf("ListTools = %v, want only the safe tool", got)
	}
	// And the safe tool is served as before: the gate touches only the
	// sensitive class.
	if _, err := h.dispatch("casemgmt.list_cases"); err != nil {
		t.Fatalf("Dispatch(list_cases) under the same wildcard: %v", err)
	}
}

// TestDispatch_SensitiveToolExplicitlyGrantedInANonReadRoleIsServed is the
// one shape that passes: the marking and the explicit name on one role.
func TestDispatch_SensitiveToolExplicitlyGrantedInANonReadRoleIsServed(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")
	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})

	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("Dispatch(close_case) from a non-read role naming it: %v", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 1 {
		t.Fatalf("upstream calls = %+v, want exactly one", calls)
	}
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.close_case"}) {
		t.Fatalf("ListTools = %v, want the sensitive tool listed for the role that may call it", got)
	}
	rows := h.auditRows()
	if len(rows) != 1 || rows[0].Outcome != audit.OutcomeAllowed {
		t.Fatalf("trail = %+v, want one allowed row", rows)
	}
}

// TestDispatch_SensitiveToolExplicitlyGrantedInAReadRoleIsRefused: naming
// the tool is half; the role must also be marked. A read role that lists a
// tool that acts was written by someone not thinking about acting.
func TestDispatch_SensitiveToolExplicitlyGrantedInAReadRoleIsRefused(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")
	h.applyRoles(access.Role{Name: "n1-triage", Tools: []string{"casemgmt.close_case"}})

	_, err := h.dispatch("casemgmt.close_case")
	if !errors.Is(err, ErrSensitiveNotGranted) || !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("Dispatch(close_case) from a read role naming it = %v, want ErrSensitiveNotGranted", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Fatalf("upstream was reached: %+v", calls)
	}
	if got := reasonsOf(h.auditRows()); !slices.Equal(got, []string{reasonSensitiveNotGranted}) {
		t.Fatalf("trail reasons = %v", got)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Fatalf("ListTools = %v, want nothing", got)
	}
}

// TestDispatch_TheTwoHalvesOnTwoRolesDoNotCompose: a non-read role with a
// wildcard plus a read role with the explicit name is the union Allows
// would accept and the gate must not. Both halves, one role.
func TestDispatch_TheTwoHalvesOnTwoRolesDoNotCompose(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")
	roles := []access.Role{
		{Name: "dfir-lead", Grants: map[string][]string{"casemgmt": {access.GrantAll}}, NonRead: true},
		{Name: "n1-triage", Tools: []string{"casemgmt.close_case"}},
	}
	h.applyRoles(roles...)
	c := callerWithRoles(roles...)
	if len(h.gw.Policy().RolesFor(c.Identity)) != 2 {
		t.Fatalf("precondition: caller holds %v, want both roles", h.gw.Policy().RolesFor(c.Identity))
	}

	_, err := h.gw.Dispatch(context.Background(), c, "casemgmt.close_case", nil)
	if !errors.Is(err, ErrSensitiveNotGranted) {
		t.Fatalf("Dispatch with the marking on one role and the name on another = %v, want ErrSensitiveNotGranted", err)
	}
}

// TestDispatch_TheClassGateRunsOnEveryCallAndSurvivesAReload: the gate
// reads the roles in force now, not the ones in force when the tool was
// cleared. A reload that narrows the role narrows the reach, and one that
// marks it widens it, with the clearance untouched either way.
func TestDispatch_TheClassGateRunsOnEveryCallAndSurvivesAReload(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")

	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})
	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("under the non-read role: %v", err)
	}
	// The same role, reloaded without the marking: the clearance is still
	// there, and the next call is refused anyway.
	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}})
	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, ErrSensitiveNotGranted) {
		t.Fatalf("after a reload dropped the marking = %v, want ErrSensitiveNotGranted", err)
	}
	if !h.quarantineStatus("casemgmt", "close_case").Usable() {
		t.Fatal("the reload touched the quarantine: the clearance should be intact")
	}
	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})
	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("after the marking came back: %v", err)
	}
	if got := reasonsOf(h.auditRows()); !slices.Equal(got, []string{"", reasonSensitiveNotGranted, ""}) {
		t.Fatalf("trail reasons = %v", got)
	}
}

// TestDispatch_AReadRoleLearnsNothingAboutClearance: for a tool approved
// as advertised, the class gate answers before the clearance, so a
// read-role caller gets the same refusal for a cleared and an uncleared
// sensitive tool. Were it the other way round, "forbidden" versus "unknown
// tool" would say which sensitive tools are cleared today. (For a tool NOT
// approved as advertised the quarantine answers first instead --
// TestDispatch_AReadRoleCannotEnumerateUnreviewedSensitiveTools.)
func TestDispatch_AReadRoleLearnsNothingAboutClearance(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"), sensitiveDef("delete_case", "delete"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")
	if _, err := h.quarantine.Approve(context.Background(), "casemgmt", "delete_case"); err != nil {
		t.Fatal(err)
	}
	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})

	_, errCleared := h.dispatch("casemgmt.close_case")
	_, errUncleared := h.dispatch("casemgmt.delete_case")
	for name, err := range map[string]error{"cleared": errCleared, "uncleared": errUncleared} {
		// Same class both times -- forbidden -- and never the opaque
		// unknown-tool answer that would mark the uncleared one out.
		if !errors.Is(err, ErrSensitiveNotGranted) || !errors.Is(err, access.ErrForbidden) || errors.Is(err, ErrUnknownTool) {
			t.Errorf("%s sensitive tool from a read role = %v, want the forbidden class only", name, err)
		}
	}
	if got := reasonsOf(h.auditRows()); !slices.Equal(got, []string{reasonSensitiveNotGranted, reasonSensitiveNotGranted}) {
		t.Fatalf("trail reasons = %v", got)
	}
}

// TestDispatch_AnUnclearedSensitiveToolIsOpaqueEvenToANonReadRole: past the
// class gate, the default-deny still holds, and holds the way the quarantine
// always has -- unknown tool to the caller, quarantined in the trail.
func TestDispatch_AnUnclearedSensitiveToolIsOpaqueEvenToANonReadRole(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	if _, err := h.quarantine.Approve(context.Background(), "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})

	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("approved-not-cleared = %v, want ErrUnknownTool", err)
	}
	if got := reasonsOf(h.auditRows()); !slices.Equal(got, []string{reasonQuarantined}) {
		t.Fatalf("trail reasons = %v", got)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Fatalf("ListTools = %v, want nothing", got)
	}
}

// TestDispatch_SafeToolsAreUntouchedByTheClassGate: a safe tool under a
// wildcard in a read role is served exactly as it was before ADR-0048.
func TestDispatch_SafeToolsAreUntouchedByTheClassGate(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", def("list_cases", "list"))
	h.mustConnect()
	h.approve("casemgmt", "list_cases")
	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})

	if _, err := h.dispatch("casemgmt.list_cases"); err != nil {
		t.Fatalf("Dispatch(list_cases): %v", err)
	}
	if got := h.listNames(analyst); !slices.Equal(got, []string{"casemgmt.list_cases"}) {
		t.Fatalf("ListTools = %v", got)
	}
}

// TestDispatch_AReadRoleCannotEnumerateUnreviewedSensitiveTools pins the
// order inside admit: the quarantine answers before the class gate for
// every tool that is not approved as advertised. A wildcard read role
// probing names gets the one opaque unknown-tool answer for a pending
// sensitive tool, a changed one and a name that exists nowhere -- so the
// forbidden/unknown pair cannot be used to list, by trying, which
// sensitive operations a backend advertises before anyone reviewed them.
func TestDispatch_AReadRoleCannotEnumerateUnreviewedSensitiveTools(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"), sensitiveDef("delete_case", "delete"), def("list_cases", "list"))
	h.mustConnect()
	// delete_case: approved, cleared, then rewritten -- changed.
	h.approveAndClear("casemgmt", "delete_case")
	if got, err := h.quarantine.Observe(context.Background(), "casemgmt", identityOf(sensitiveDef("delete_case", "delete (rewritten)")), quarantine.ClassSensitive); err != nil || got.Status != quarantine.StatusChanged {
		t.Fatalf("rewriting delete_case: %+v, %v; want changed", got, err)
	}
	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})

	_, errPending := h.dispatch("casemgmt.close_case")
	_, errChanged := h.dispatch("casemgmt.delete_case")
	_, errSafePending := h.dispatch("casemgmt.list_cases")
	_, errAbsent := h.dispatch("casemgmt.no_such_tool")
	for name, err := range map[string]error{"pending sensitive": errPending, "changed sensitive": errChanged, "pending safe": errSafePending, "nonexistent": errAbsent} {
		if !errors.Is(err, ErrUnknownTool) || errors.Is(err, access.ErrForbidden) || errors.Is(err, ErrSensitiveNotGranted) {
			t.Errorf("%s from a read role = %v, want exactly ErrUnknownTool", name, err)
		}
	}
	// The trail still tells the three apart: that is where the distinction
	// belongs.
	if got := reasonsOf(h.auditRows()); !slices.Equal(got, []string{reasonQuarantined, reasonQuarantined, reasonQuarantined, reasonUnknownTool}) {
		t.Fatalf("trail reasons = %v", got)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Fatalf("ListTools = %v, want nothing", got)
	}
}

// TestAdmit_TheRoutesSignedClassGatesWhenTheRowReadsSafe: "sensitive" is
// the OR of the quarantine row's class and the route's def.SecurityClass
// (the one with a signed origin). A row blanked to safe under a route that
// says sensitive -- a direct write to the database -- does not make the
// tool reachable through a wildcard: the gate still runs, fails closed,
// and the one role that passes it is a non-read role naming the tool.
func TestAdmit_TheRoutesSignedClassGatesWhenTheRowReadsSafe(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", sensitiveDef("close_case", "close"))
	h.mustConnect()
	h.approveAndClear("casemgmt", "close_case")

	// The row drifts to safe at the same fingerprint, the route untouched
	// (no Refresh): what an UPDATE quarantined_tools SET class='' leaves.
	drifted, err := h.quarantine.Observe(context.Background(), "casemgmt", identityOf(sensitiveDef("close_case", "close")), quarantine.ClassSafe)
	if err != nil {
		t.Fatal(err)
	}
	if drifted.Class != quarantine.ClassSafe || !drifted.Usable() {
		t.Fatalf("precondition: the row should read safe and usable on its own: %+v", drifted)
	}

	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})
	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, ErrSensitiveNotGranted) {
		t.Fatalf("Dispatch with the row blanked to safe = %v, want ErrSensitiveNotGranted from the route's class", err)
	}
	if calls := h.dialer.upstream("casemgmt").callLog(); len(calls) != 0 {
		t.Fatalf("upstream was reached: %+v", calls)
	}
	if got := h.listNames(analyst); len(got) != 0 {
		t.Fatalf("ListTools = %v, want nothing", got)
	}

	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})
	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("Dispatch from a non-read role naming it: %v", err)
	}
}

// TestAdmit_TheRowsClassGatesWhenTheRouteReadsSafe is the other direction
// of the OR: a safe route over a row that turned sensitive (the operation's
// method changed and discovery recorded it) is gated by the row, held until
// cleared, and then served only to the non-read role.
func TestAdmit_TheRowsClassGatesWhenTheRouteReadsSafe(t *testing.T) {
	h := newHarness(t)
	h.register("casemgmt")
	h.serve("casemgmt", def("close_case", "close"))
	h.mustConnect()
	h.approve("casemgmt", "close_case")

	turned, err := h.quarantine.Observe(context.Background(), "casemgmt", identityOf(def("close_case", "close")), quarantine.ClassSensitive)
	if err != nil {
		t.Fatal(err)
	}
	if turned.Usable() || !turned.ApprovedAsAdvertised() {
		t.Fatalf("precondition: approved, sensitive and held: %+v", turned)
	}

	h.applyRoles(access.Role{Name: "n1-triage", Grants: map[string][]string{"casemgmt": {access.GrantAll}}})
	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, ErrSensitiveNotGranted) {
		t.Fatalf("read role on a tool that turned sensitive = %v, want ErrSensitiveNotGranted", err)
	}
	h.applyRoles(access.Role{Name: "dfir-lead", Tools: []string{"casemgmt.close_case"}, NonRead: true})
	if _, err := h.dispatch("casemgmt.close_case"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("non-read role before the clearance = %v, want ErrUnknownTool", err)
	}
	if _, err := h.quarantine.Clear(context.Background(), "casemgmt", "close_case"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.dispatch("casemgmt.close_case"); err != nil {
		t.Fatalf("non-read role after the clearance: %v", err)
	}
}
