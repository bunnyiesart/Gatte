package admin_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// design/adr/0046: audit search, blocks that end, account deletion and
// offboarding.

// clockedService is h's service with a settable clock, for the service
// and the blocklist alike, and a directory the test can make fail.
func clockedService(t *testing.T, h *harness, now *time.Time, dir func(idp.Directory) idp.Directory) *admin.Service {
	t.Helper()
	blocks := accesssqlite.New(h.db).WithClock(func() time.Time { return *now })
	h.blocks = blocks
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return h.cfg, nil },
		Tools:  h.tools, Blocks: blocks, Trail: h.trail,
		Record: func(ctx context.Context, _ *config.Config, rec audit.Record) error {
			if h.failRecord != nil {
				return h.failRecord
			}
			return h.trail.Record(ctx, rec)
		},
		Accounts: func(cfg *config.Config) (idp.Directory, error) {
			d := idp.Directory(autheliafile.New(cfg.IdP.UsersFile))
			if dir != nil {
				d = dir(d)
			}
			return d, nil
		},
		IsBusy: store.IsBusy,
		Now:    func() time.Time { return *now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (h *harness) record(t *testing.T, rec audit.Record) {
	t.Helper()
	if err := h.trail.Record(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
}

// TestAudit_FiltersByToolServerAndUntil: the three filters reach the
// store, and an until that is not after since is refused.
func TestAudit_FiltersByToolServerAndUntil(t *testing.T) {
	h := newHarness(t)
	base := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	for i, call := range []struct{ tool, server string }{
		{"casemgmt.list_cases", "casemgmt"}, {"logsearch.search", "logsearch"}, {"casemgmt.get_case", "casemgmt"}, {"logsearch.search", "logsearch"},
	} {
		h.record(t, audit.Record{AnalystIdentity: "ana", Tool: call.tool, TargetUpstream: call.server, Timestamp: base.Add(time.Duration(i) * time.Hour), Outcome: audit.OutcomeAllowed})
	}
	ctx := context.Background()
	count := func(q adminapi.AuditQuery) int {
		t.Helper()
		p, err := h.svc.Audit(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Records)
	}
	if n := count(adminapi.AuditQuery{Tool: "logsearch.search"}); n != 2 {
		t.Errorf("tool filter: %d, want 2", n)
	}
	if n := count(adminapi.AuditQuery{Server: "casemgmt"}); n != 2 {
		t.Errorf("server filter: %d, want 2", n)
	}
	if n := count(adminapi.AuditQuery{Since: base.Add(time.Hour), Until: base.Add(3 * time.Hour)}); n != 2 {
		t.Errorf("[since, until): %d, want 2", n)
	}
	if n := count(adminapi.AuditQuery{Server: "logsearch", Until: base.Add(3 * time.Hour)}); n != 1 {
		t.Errorf("server and until: %d, want 1", n)
	}
	_, err := h.svc.Audit(ctx, adminapi.AuditQuery{Since: base, Until: base})
	requireCode(t, err, adminapi.CodeBadRequest)
}

// TestBlock_AnEndIsInTheFutureIsRecordedAndStopsCountingWhenPassed.
func TestBlock_AnEndIsInTheFutureIsRecordedAndStopsCountingWhenPassed(t *testing.T) {
	h := newHarness(t)
	now := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	svc := clockedService(t, h, &now, nil)
	ctx := context.Background()
	h.record(t, audit.Record{AnalystIdentity: "sub-ana", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt", Timestamp: now.Add(-time.Hour), Outcome: audit.OutcomeAllowed})

	past := now.Add(-time.Minute)
	_, err := svc.Block(ctx, alice, adminapi.BlockRequest{Subject: "sub-ana", Until: &past})
	requireCode(t, err, adminapi.CodeInvalidArgument)
	if n := len(h.rows(t)); n != 1 {
		t.Fatalf("a refused block wrote %d rows", n-1)
	}

	end := now.Add(8 * time.Hour)
	res, err := svc.Block(ctx, alice, adminapi.BlockRequest{Subject: "sub-ana", Reason: "on leave", Until: &end})
	if err != nil || !res.Changed || !res.Recorded {
		t.Fatalf("block with an end: %+v, %v", res, err)
	}
	if !strings.Contains(res.Audit.Reason, "until 2026-09-30T16:00:00Z") || !strings.Contains(strings.Join(res.Messages, " "), admin.AccessBlockExpired) {
		t.Fatalf("the row or the answer does not state the end: %+v", res)
	}
	list, _ := svc.ListBlocks(ctx)
	if len(list.Blocks) != 1 || list.Blocks[0].Until == nil || !list.Blocks[0].Until.Equal(end) || list.Blocks[0].Expired {
		t.Fatalf("blocklist %+v", list)
	}
	ov, _ := svc.Overview(ctx)
	people, _ := svc.People(ctx)
	if ov.Counts.Blocked != 1 || len(people.Seen) != 1 || !people.Seen[0].Blocked {
		t.Fatalf("before the end: blocked count %d, seen %+v", ov.Counts.Blocked, people.Seen)
	}

	now = end
	list, _ = svc.ListBlocks(ctx)
	ov, _ = svc.Overview(ctx)
	people, _ = svc.People(ctx)
	if len(list.Blocks) != 1 || !list.Blocks[0].Expired || ov.Counts.Blocked != 0 || people.Seen[0].Blocked {
		t.Fatalf("after the end: blocklist %+v, count %d, seen %+v; want listed as expired and counted nowhere", list, ov.Counts.Blocked, people.Seen)
	}
	// An expired block may be cleared by hand, and that is recorded.
	un, err := svc.Unblock(ctx, alice, adminapi.BlockRequest{Subject: "sub-ana"})
	if err != nil || !un.Changed || !un.Recorded {
		t.Fatalf("unblock of an expired block: %+v, %v", un, err)
	}
}

// TestDeleteAccount_RemovesAManagedAccountAndRecordsIt, within the reach
// of design/adr/0040 §1.
func TestDeleteAccount_RemovesAManagedAccountAndRecordsIt(t *testing.T) {
	h := newHarness(t)
	h.addForeignAccounts(t)
	ctx := context.Background()
	_, err := h.svc.DeleteAccount(ctx, alice, "sso-admin")
	requireCode(t, err, adminapi.CodeAccountNotManaged)
	res, err := h.svc.DeleteAccount(ctx, alice, "ana")
	if err != nil || !res.Changed || !res.Recorded || res.Audit.Tool != admin.AccountDelete || res.Account.Username != "ana" {
		t.Fatalf("delete ana: %+v, %v", res, err)
	}
	if !strings.Contains(strings.Join(res.Messages, " "), "same username") {
		t.Fatalf("the answer does not warn about the username being reused: %v", res.Messages)
	}
	_, err = h.svc.Account(ctx, "ana")
	requireCode(t, err, adminapi.CodeNotFound)
	_, err = h.svc.DeleteAccount(ctx, alice, "ana")
	requireCode(t, err, adminapi.CodeNotFound)
	root := admin.Actor{Name: "alice", Via: "root", Front: "api", Root: true}
	if _, err := h.svc.DeleteAccount(ctx, root, "sso-admin"); err != nil {
		t.Fatalf("root delete of an unmanaged account: %v", err)
	}
}

// TestOffboard_BlocksThenDisablesRecordsEachAndSaysWhatIsLeft is item 2.
func TestOffboard_BlocksThenDisablesRecordsEachAndSaysWhatIsLeft(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	op := admin.Actor{Name: "alice", Front: "ui", Operator: true}
	res, err := h.svc.Offboard(ctx, op, "ana", adminapi.OffboardRequest{Subject: "sub-ana", Reason: "left the company"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.Recorded || !res.Blocked || !res.Disabled || !res.Account.Disabled {
		t.Fatalf("offboard: %+v", res)
	}
	var tools []string
	for _, r := range res.Rows {
		tools = append(tools, r.Tool)
	}
	if strings.Join(tools, ",") != strings.Join([]string{admin.AccessBlock, admin.AccountDisable, admin.AccountOffboard}, ",") {
		t.Fatalf("rows %v", tools)
	}
	if rows := h.rows(t); len(rows) != 3 || !strings.Contains(rows[0].Reason, `offboard of account "ana"`) || !strings.Contains(rows[2].Reason, "left the company") {
		t.Fatalf("trail %+v", rows)
	}
	if blocked, _ := h.blocks.Blocked(ctx, "sub-ana"); !blocked {
		t.Fatal("the subject is not blocked")
	}
	if a, _ := h.svc.Account(ctx, "ana"); !a.Disabled {
		t.Fatal("the account is not disabled")
	}
	if len(res.Remaining) == 0 || !strings.Contains(res.Remaining[0], "identity provider") {
		t.Fatalf("remaining %v; want the IdP sessions first", res.Remaining)
	}
	again, err := h.svc.Offboard(ctx, op, "ana", adminapi.OffboardRequest{Subject: "sub-ana"})
	if err != nil || again.Changed || len(again.Rows) != 0 || len(h.rows(t)) != 3 {
		t.Fatalf("second offboard: %+v, %v; want nothing changed or recorded", again, err)
	}
}

// TestOffboard_ADelegatedPeerOutsideTheOperatorGroupMayNotBlock: the
// accounts socket does not hand the kill switch to [admin] account_group.
func TestOffboard_ADelegatedPeerOutsideTheOperatorGroupMayNotBlock(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	before, _ := os.ReadFile(h.usersFile)
	_, err := h.svc.Offboard(ctx, alice, "ana", adminapi.OffboardRequest{Subject: "sub-ana"})
	requireCode(t, err, adminapi.CodeForbiddenPeer)
	after, _ := os.ReadFile(h.usersFile)
	if blocked, _ := h.blocks.Blocked(ctx, "sub-ana"); blocked || !bytes.Equal(before, after) || len(h.rows(t)) != 0 {
		t.Fatal("a refused offboard changed something")
	}
	// Without a subject it only disables, and says there is no block.
	res, err := h.svc.Offboard(ctx, alice, "ana", adminapi.OffboardRequest{})
	if err != nil || !res.Changed || res.Blocked || !res.Disabled || len(res.Rows) != 2 {
		t.Fatalf("offboard without a subject: %+v, %v", res, err)
	}
	if !strings.Contains(strings.Join(res.Remaining, " "), "No gateway block") {
		t.Fatalf("remaining %v; want the missing block named", res.Remaining)
	}
}

// failingDisable is a directory whose SetDisabled fails.
type failingDisable struct{ idp.Directory }

func (failingDisable) SetDisabled(string, bool) error { return errors.New("disk full") }

// TestOffboard_ABlockInForceIsNotHiddenByAFailedDisable: 200, changed,
// warning offboard_incomplete.
func TestOffboard_ABlockInForceIsNotHiddenByAFailedDisable(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	svc := clockedService(t, h, &now, func(d idp.Directory) idp.Directory { return failingDisable{d} })
	op := admin.Actor{Name: "alice", Front: "ui", Operator: true}
	res, err := svc.Offboard(context.Background(), op, "ana", adminapi.OffboardRequest{Subject: "sub-ana"})
	if err != nil {
		t.Fatalf("a half-done offboard answered an error: %v", err)
	}
	if !res.Changed || !res.Blocked || res.Disabled || !res.HasWarning(adminapi.WarnOffboardIncomplete) {
		t.Fatalf("offboard with a failing disable: %+v", res)
	}
	// Without a block placed first, the failure is an error and nothing
	// is recorded.
	h2 := newHarness(t)
	svc2 := clockedService(t, h2, &now, func(d idp.Directory) idp.Directory { return failingDisable{d} })
	if _, err := svc2.Offboard(context.Background(), op, "ana", adminapi.OffboardRequest{}); err == nil || len(h2.rows(t)) != 0 {
		t.Fatalf("offboard with nothing done: %v, rows %d", err, len(h2.rows(t)))
	}
}
