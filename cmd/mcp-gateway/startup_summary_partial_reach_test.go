package main

// GAB-30 item 3, in the shape it survives in.
//
// The ticket's complaint is that a role naming a tool that does not exist
// authorizes less than the file says, with "no error, no log line, and the
// first report of it is an analyst denied mid-incident". Two of the three
// ways to write that are now closed at load time -- config.Validate
// refuses an un-namespaced name and refuses `backend.*` in the flat list --
// and the all-or-nothing case is warned about at boot: a role that reaches
// NOTHING lands in the dead-role warning.
//
// What is not closed is the case in between, which is also the likeliest
// one: a role naming several tools where ONE name is wrong. A renamed
// backend tool, a typo inside the namespace, an upstream that came up with
// one tool missing. The role still reaches something, so it is not dead,
// so it is not warned about -- and the only trace is a ratio inside an
// Info line that reads `n1-triage 1/2`.
//
// This test pins what is actually true today rather than what one might
// hope: the ratio IS emitted (so the evidence exists and cannot regress
// away), and no warning accompanies it (so nobody reading this file
// believes the case is covered). If a later change starts warning here,
// this test fails and should be rewritten to assert the warning -- that is
// the intended direction of travel, not a regression.
//
// These need no vault and no issuer, so they never skip.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
)

func TestStartupSummary_ARoleNamingOneMissingToolAmongRealOnesIsNotWarnedAbout(t *testing.T) {
	db := summaryDB(t)
	reg := registrysqlite.New(db)
	quar := quarantinesqlite.New(db)
	ctx := context.Background()

	entry := registry.UpstreamServer{
		Name:      "casemgmt",
		Transport: registry.TransportStdio,
		Command:   "/usr/bin/true",
	}
	if err := reg.Register(ctx, entry); err != nil {
		t.Fatalf("register: %v", err)
	}

	startedAt := time.Now()
	// The backend advertises list_cases. It does NOT advertise
	// get_case_notes -- renamed, removed, or never spelled that way.
	if _, err := quar.Observe(ctx, "casemgmt", quarantine.ToolIdentity{
		Name:        "list_cases",
		Description: "list open cases",
		InputSchema: []byte(`{"type":"object"}`),
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}

	cfg := &config.Config{Roles: []config.Role{{
		Name: "n1-triage",
		// Both names are well-formed and namespaced, so config.Validate
		// accepts the file. One of them refers to nothing.
		Tools: []string{"casemgmt.list_cases", "casemgmt.get_case_notes"},
	}}}

	s := newStartupSummary(ctx, cfg, "127.0.0.1:8080", reg, quar, startedAt, nil)

	if len(s.Roles) != 1 {
		t.Fatalf("Roles = %+v, want one entry", s.Roles)
	}
	if got := s.Roles[0]; got.Granted != 2 || got.Observed != 1 {
		t.Fatalf("roleReach = %+v, want Granted 2 and Observed 1: the file names two tools and one of them exists", got)
	}

	logger, logs := serveTestLogger()
	s.log(logger)
	out := logs.String()
	// Printed under -v because the whole subject of this test is what an
	// operator does and does not see, and reading it beats reconstructing
	// it from the assertions.
	t.Logf("what the operator sees at boot:\n%s", out)

	// The evidence that exists: the ratio. An operator who reads this line
	// and knows the file can see that one name in it refers to nothing.
	if !strings.Contains(out, "n1-triage 1/2") {
		t.Errorf("the role reach line does not carry the observed/granted ratio, which is the ONLY trace of the missing tool:\n%s", out)
	}

	// The evidence that does not exist: any warning. Asserted so that this
	// gap is a stated property of the build rather than something a reader
	// has to reconstruct from three functions in serve.go.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "n1-triage") {
			t.Errorf("a warning now names the role with a missing tool -- that is an IMPROVEMENT, and this test should be rewritten to require it:\n%s", line)
		}
	}
	if strings.Contains(out, "authorizes nothing") {
		t.Error("the dead-role warning fired for a role that does reach something; it is documented to fire only at zero reach")
	}
}

// TestStartupSummary_ARoleThatReachesNothingIsWarnedAbout is the boundary
// on the other side of the same rule, asserted in the same file so the two
// are read together: at zero reach the warning does fire, and it names the
// role. Without this, the test above could pass against a build where the
// dead-role warning was deleted entirely.
func TestStartupSummary_ARoleThatReachesNothingIsWarnedAbout(t *testing.T) {
	db := summaryDB(t)
	reg := registrysqlite.New(db)
	quar := quarantinesqlite.New(db)
	ctx := context.Background()

	if err := reg.Register(ctx, registry.UpstreamServer{
		Name:      "casemgmt",
		Transport: registry.TransportStdio,
		Command:   "/usr/bin/true",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	startedAt := time.Now()
	if _, err := quar.Observe(ctx, "casemgmt", quarantine.ToolIdentity{
		Name:        "list_cases",
		Description: "list open cases",
		InputSchema: []byte(`{"type":"object"}`),
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}

	cfg := &config.Config{Roles: []config.Role{{
		Name:  "typo-squad",
		Tools: []string{"casemgmt.get_case_notes"},
	}}}

	logger, logs := serveTestLogger()
	newStartupSummary(ctx, cfg, "127.0.0.1:8080", reg, quar, startedAt, nil).log(logger)

	out := logs.String()
	var warned string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "WARN") && strings.Contains(line, "authorizes nothing") {
			warned = line
		}
	}
	if warned == "" {
		t.Fatalf("a role whose every tool name refers to nothing was not warned about:\n%s", out)
	}
	if !strings.Contains(warned, "typo-squad") {
		t.Errorf("the warning does not name the role, so an operator cannot act on it:\n%s", warned)
	}
}
