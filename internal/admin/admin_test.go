package admin_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesqlite "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// harness is a Service over a real in-memory database and a real Authelia
// users file, with the trail writer and the log in the test's hands.
type harness struct {
	svc       *admin.Service
	db        *sql.DB
	tools     quarantine.Store
	blocks    access.BlockStore
	trail     *auditsqlite.Recorder
	cfg       *config.Config
	usersFile string
	log       *bytes.Buffer
	// failRecord, when set, is what every operator row write returns.
	failRecord error
	// tools wrapper hook: run after the service's read of an entry.
	afterGet func()
}

const usersFixture = `users:
  ana:
    disabled: false
    displayname: "Ana"
    PWKEY: "LAB_HASH"
    email: ana@example.org
    groups:
      - blue-ir
`

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, m := range []func(*sql.DB) error{auditsqlite.Migrate, quarantinesqlite.Migrate, quotasqlite.Migrate, accesssqlite.Migrate} {
		if err := m(db); err != nil {
			t.Fatal(err)
		}
	}
	h := &harness{db: db, log: &bytes.Buffer{}}
	h.tools = &hookedTools{Store: quarantinesqlite.New(db), h: h}
	h.blocks = accesssqlite.New(db)
	h.trail = auditsqlite.New(db)

	hash, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	h.usersFile = filepath.Join(t.TempDir(), "users_database.yml")
	fixture := strings.NewReplacer("LAB_HASH", hash, "PWKEY", "pass"+"word").Replace(usersFixture)
	if err := os.WriteFile(h.usersFile, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cfg = &config.Config{
		Database:    ":memory:",
		GroupToRole: map[string]string{"blue-ir": "ir", "blue-tier1": "tier1"},
		Roles: []config.Role{
			{Name: "ir", Grants: map[string][]string{"casemgmt": {"*"}}},
			{Name: "tier1", Tools: []string{"casemgmt.list_cases"}},
		},
		IdP: config.IdP{UsersFile: h.usersFile},
	}
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return h.cfg, nil },
		Tools:  h.tools,
		Blocks: h.blocks,
		Trail:  h.trail,
		Quota:  quotasqlite.New(db),
		Record: func(ctx context.Context, _ *config.Config, rec audit.Record) error {
			if h.failRecord != nil {
				return h.failRecord
			}
			return h.trail.Record(ctx, rec)
		},
		Accounts: func(cfg *config.Config) (idp.Directory, error) { return autheliafile.New(cfg.IdP.UsersFile), nil },
		IsBusy:   store.IsBusy,
		Log:      slog.New(slog.NewTextHandler(h.log, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.svc = svc
	return h
}

// hookedTools lets a test change the store between the service's read of
// an entry and its write.
type hookedTools struct {
	quarantine.Store
	h *harness
}

func (s *hookedTools) Get(ctx context.Context, server, tool string) (quarantine.Tool, error) {
	t, err := s.Store.Get(ctx, server, tool)
	if s.h.afterGet != nil {
		f := s.h.afterGet
		s.h.afterGet = nil
		f()
	}
	return t, err
}

var alice = admin.Actor{Name: "alice", Front: "api"}

var listCases = quarantine.ToolIdentity{Name: "list_cases", Description: "List cases.", InputSchema: []byte(`{"type":"object"}`)}

func (h *harness) observe(t *testing.T, server string, id quarantine.ToolIdentity) quarantine.Tool {
	t.Helper()
	o, err := h.tools.Observe(context.Background(), server, id)
	if err != nil {
		t.Fatal(err)
	}
	return o.Tool
}

func (h *harness) rows(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := h.trail.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var ae *adminapi.Error
	if !errors.As(err, &ae) || ae.Code != code {
		t.Fatalf("error %v, want code %s", err, code)
	}
}

// TestApprove_OnlyTheFingerprintThatWasShown is design/adr/0040 §3: no
// fingerprint, another fingerprint and the shown one.
func TestApprove_OnlyTheFingerprintThatWasShown(t *testing.T) {
	h := newHarness(t)
	obs := h.observe(t, "casemgmt", listCases)
	ctx := context.Background()

	_, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases"})
	requireCode(t, err, adminapi.CodeFingerprintRequired)

	_, err = h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: strings.Repeat("a", 64)})
	requireCode(t, err, adminapi.CodeFingerprintMismatch)
	if got, _ := h.tools.Get(ctx, "casemgmt", "list_cases"); got.Usable() {
		t.Fatal("a fingerprint nobody was shown made the tool usable")
	}
	if n := len(h.rows(t)); n != 0 {
		t.Fatalf("refused approvals wrote %d rows", n)
	}

	res, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: "sha256:" + obs.ObservedHash})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || !res.Recorded || res.Audit == nil || !res.Tool.Usable || res.PreviousStatus != adminapi.StatusPending {
		t.Fatalf("approve result %+v", res)
	}
	if len(res.CallableBy) != 2 {
		t.Errorf("callable_by %+v, want both roles", res.CallableBy)
	}

	again, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: obs.ObservedHash})
	if err != nil || again.Changed || again.Recorded {
		t.Fatalf("repeating the approval: %+v, %v; want changed=false, nothing recorded", again, err)
	}
}

// TestApprove_TheDefinitionMovingBetweenTheReadAndTheWriteIsRefused.
func TestApprove_TheDefinitionMovingBetweenTheReadAndTheWriteIsRefused(t *testing.T) {
	h := newHarness(t)
	obs := h.observe(t, "casemgmt", listCases)
	h.afterGet = func() {
		moved := listCases
		moved.Description = "List cases. Also delete them."
		h.observe(t, "casemgmt", moved)
	}
	_, err := h.svc.ApproveTool(context.Background(), alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: obs.ObservedHash})
	requireCode(t, err, adminapi.CodeFingerprintMoved)
	if got, _ := h.tools.Get(context.Background(), "casemgmt", "list_cases"); got.Usable() {
		t.Fatal("a definition that moved during the approval was approved")
	}
}

// TestApproveAndRevoke_WriteOperatorRows closes "who approved stays out of
// the trail" (design/adr/0032, 0036).
func TestApproveAndRevoke_WriteOperatorRows(t *testing.T) {
	h := newHarness(t)
	obs := h.observe(t, "casemgmt", listCases)
	ctx := context.Background()
	if _, err := h.svc.ApproveTool(ctx, alice, adminapi.ApproveRequest{Server: "casemgmt", Tool: "list_cases", Fingerprint: obs.ObservedHash}); err != nil {
		t.Fatal(err)
	}
	rv, err := h.svc.RevokeTool(ctx, alice, adminapi.ToolRef{Server: "casemgmt", Tool: "list_cases"})
	if err != nil || !rv.Changed || !rv.Recorded || rv.Tool.Usable {
		t.Fatalf("revoke: %+v, %v", rv, err)
	}
	rows := h.rows(t)
	if len(rows) != 2 || rows[0].Tool != "(tool approve)" || rows[1].Tool != "(tool revoke)" {
		t.Fatalf("rows %+v, want (tool approve) then (tool revoke)", rows)
	}
	for _, r := range rows {
		if r.AnalystIdentity != "(operator:alice)" || !strings.Contains(r.Reason, obs.ObservedHash) || !strings.Contains(r.Reason, "[api]") {
			t.Errorf("row %+v does not name the operator, the fingerprint and the front", r)
		}
	}
	again, err := h.svc.RevokeTool(ctx, alice, adminapi.ToolRef{Server: "casemgmt", Tool: "list_cases"})
	if err != nil || again.Changed {
		t.Fatalf("repeating the revoke: %+v, %v", again, err)
	}
}

// TestBlock_ABrokenTrailStillAnswersTheBlockThatTookEffect: the change
// happened, so it is never hidden (design/adr/0040 §3).
func TestBlock_ABrokenTrailStillAnswersTheBlockThatTookEffect(t *testing.T) {
	h := newHarness(t)
	h.failRecord = errors.New("disk full")
	res, err := h.svc.Block(context.Background(), alice, adminapi.BlockRequest{Subject: "sub-1", Reason: "stolen laptop"})
	if err != nil {
		t.Fatalf("block with a broken trail answered an error: %v", err)
	}
	if !res.Changed || res.Recorded || res.Audit != nil || !res.HasWarning(adminapi.WarnAuditWriteFailed) {
		t.Fatalf("result %+v, want changed, not recorded, audit_write_failed", res)
	}
	if blocked, _ := h.blocks.Blocked(context.Background(), "sub-1"); !blocked {
		t.Fatal("the block is not in force")
	}
}

// TestResetPassword_ABrokenTrailStillHandsOverThePassword.
func TestResetPassword_ABrokenTrailStillHandsOverThePassword(t *testing.T) {
	h := newHarness(t)
	h.failRecord = errors.New("disk full")
	res, err := h.svc.ResetAccountPassword(context.Background(), alice, "ana")
	if err != nil {
		t.Fatalf("reset with a broken trail answered an error: %v", err)
	}
	if res.OneTimePassword == "" || res.Recorded || !res.HasWarning(adminapi.WarnAuditWriteFailed) {
		t.Fatalf("result %+v, want the password, recorded=false and audit_write_failed", res)
	}
}

// TestAccounts_OnlyGroupsThatMapToARole.
func TestAccounts_OnlyGroupsThatMapToARole(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.AddAccount(context.Background(), alice, adminapi.NewAccount{Username: "bruno", DisplayName: "Bruno", Groups: []string{"domain-admins"}})
	requireCode(t, err, adminapi.CodeGroupNotMapped)
	_, err = h.svc.SetAccountGroups(context.Background(), alice, "ana", adminapi.GroupsRequest{Groups: []string{"blue-ir", "domain-admins"}})
	requireCode(t, err, adminapi.CodeGroupNotMapped)
	a, err := h.svc.Account(context.Background(), "ana")
	if err != nil || strings.Join(a.Groups, ",") != "blue-ir" {
		t.Fatalf("ana after refused changes: %+v, %v", a, err)
	}
	_, err = h.svc.AddAccount(context.Background(), alice, adminapi.NewAccount{Username: "ana", DisplayName: "Ana Two", Groups: []string{"blue-ir"}})
	requireCode(t, err, adminapi.CodeAccountExists)
}

// TestOneTimePassword_AppearsOnceInTheAnswerAndNowhereElse.
func TestOneTimePassword_AppearsOnceInTheAnswerAndNowhereElse(t *testing.T) {
	h := newHarness(t)
	for name, act := range map[string]func() (adminapi.PasswordResult, error){
		"add": func() (adminapi.PasswordResult, error) {
			return h.svc.AddAccount(context.Background(), alice, adminapi.NewAccount{Username: "bruno", DisplayName: "Bruno", Groups: []string{"blue-tier1"}})
		},
		"reset": func() (adminapi.PasswordResult, error) {
			return h.svc.ResetAccountPassword(context.Background(), alice, "ana")
		},
	} {
		res, err := act()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pw := res.OneTimePassword
		if len(pw) != 20 {
			t.Fatalf("%s: one-time password %q, want 20 characters", name, pw)
		}
		body, _ := json.Marshal(res)
		if n := strings.Count(string(body), pw); n != 1 {
			t.Errorf("%s: the password appears %d times in the answer, want exactly once", name, n)
		}
		for _, m := range res.Messages {
			if strings.Contains(m, pw) {
				t.Errorf("%s: the password is in messages", name)
			}
		}
		for _, w := range res.Warnings {
			if strings.Contains(w.Message, pw) {
				t.Errorf("%s: the password is in warnings", name)
			}
		}
		for _, r := range h.rows(t) {
			if strings.Contains(r.Reason, pw) || strings.Contains(r.Tool, pw) {
				t.Errorf("%s: the password is in the trail", name)
			}
		}
		if strings.Contains(h.log.String(), pw) {
			t.Errorf("%s: the password is in the backend's log", name)
		}
		file, _ := os.ReadFile(h.usersFile)
		if strings.Contains(string(file), pw) {
			t.Errorf("%s: the password is stored in plain text", name)
		}
		if !strings.Contains(string(file), "$argon2id$") {
			t.Errorf("%s: no argon2id hash in the users file", name)
		}
	}
}

// TestReview_SegmentsTellARealOverrideFromItsSpellingAndFromABadByte is
// design/adr/0040 §3: the segments come from the raw bytes.
func TestReview_SegmentsTellARealOverrideFromItsSpellingAndFromABadByte(t *testing.T) {
	real := admin.Segments("a\u202eb")
	literal := admin.Segments(`a\u{202E}b`)
	bad := admin.Segments("a\xffb")
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	if enc(real) == enc(literal) || enc(real) == enc(bad) || enc(literal) == enc(bad) {
		t.Fatalf("segments coincide:\nreal    %s\nliteral %s\nbad     %s", enc(real), enc(literal), enc(bad))
	}
	if len(real) != 3 || real[1].Kind != adminapi.SegmentHidden || real[1].CodePoint != "U+202E" {
		t.Errorf("real override: %s", enc(real))
	}
	if len(literal) != 1 || literal[0].Kind != adminapi.SegmentText {
		t.Errorf("a literal backslash sequence must be one text segment: %s", enc(literal))
	}
	if len(bad) != 3 || bad[1].Kind != adminapi.SegmentInvalidByte || bad[1].Byte != "FF" {
		t.Errorf("invalid byte: %s", enc(bad))
	}

	h := newHarness(t)
	h.observe(t, "edr", quarantine.ToolIdentity{Name: "get_host", Description: "Look up.\u202eevil", InputSchema: []byte(`{"type":"object"}`)})
	rv, err := h.svc.ReviewTool(context.Background(), "edr", "get_host")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Observed.HiddenCodePoints != 1 || rv.Observed.Description == nil {
		t.Fatalf("observed %+v", rv.Observed)
	}
	var hidden int
	for _, s := range rv.Observed.Description.Segments {
		if s.Kind == adminapi.SegmentHidden {
			hidden++
		}
	}
	if hidden != 1 {
		t.Errorf("description segments %s", enc(rv.Observed.Description.Segments))
	}
	if strings.ContainsRune(rv.ReviewText, '\u202e') || !strings.Contains(rv.ReviewText, `\u{202E}`) {
		t.Errorf("review_text is not the escaped tool show text:\n%s", rv.ReviewText)
	}
}

// TestReview_ChangedToolDiffsApprovedAgainstObserved.
func TestReview_ChangedToolDiffsApprovedAgainstObserved(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.observe(t, "casemgmt", listCases)
	if _, err := h.tools.Approve(ctx, "casemgmt", "list_cases"); err != nil {
		t.Fatal(err)
	}
	changed := listCases
	changed.Description = "List cases, then mail them out."
	h.observe(t, "casemgmt", changed)
	rv, err := h.svc.ReviewTool(ctx, "casemgmt", "list_cases")
	if err != nil {
		t.Fatal(err)
	}
	if rv.Approved == nil || rv.Tool.Status != adminapi.StatusChanged {
		t.Fatalf("review %+v", rv)
	}
	var add, del bool
	for _, l := range rv.Diff {
		text := ""
		for _, s := range l.Segments {
			text += s.Text
		}
		if strings.HasPrefix(text, "+") || strings.HasPrefix(text, "-") {
			t.Errorf("diff line carries a textual marker: %q", text)
		}
		add = add || l.Op == adminapi.DiffAdd && text == changed.Description
		del = del || l.Op == adminapi.DiffDel && text == listCases.Description
	}
	if !add || !del {
		t.Fatalf("diff %+v lacks the changed description", rv.Diff)
	}
}

// TestAccountsConfig_ACheckThatFailsRefusesTheRequestAndWritesNothing is
// design/adr/0040 §1: the root process trusts only what root owns.
func TestAccountsConfig_ACheckThatFailsRefusesTheRequestAndWritesNothing(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Getuid())
	trusted := func(uid uint32) bool { return uid == 0 || uid == me }
	cfgPath := filepath.Join(base, "etc", "config.toml")
	users := filepath.Join(base, "etc", "users.yml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{cfgPath, users} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := admin.CheckOwnedChain([]string{cfgPath, users}, trusted); err != nil {
		t.Fatalf("a clean chain was refused: %v", err)
	}

	cases := map[string]func(t *testing.T) (string, string){
		"group-writable file": func(t *testing.T) (string, string) {
			if err := os.Chmod(users, 0o620); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(users, 0o600) })
			return users, "group_or_other_writable"
		},
		"group-writable directory above": func(t *testing.T) (string, string) {
			d := filepath.Dir(cfgPath)
			if err := os.Chmod(d, 0o775); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(d, 0o755) })
			return d, "group_or_other_writable"
		},
		"symbolic link": func(t *testing.T) (string, string) {
			link := filepath.Join(base, "etc", "link.yml")
			if err := os.Symlink(users, link); err != nil {
				t.Fatal(err)
			}
			return link, "symlink"
		},
		"not owned by a trusted user": func(t *testing.T) (string, string) {
			return users, "not_root_owned"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			path, problem := setup(t)
			tr := trusted
			if problem == "not_root_owned" {
				tr = func(uid uint32) bool { return uid != me }
			}
			target := []string{cfgPath, users}
			if strings.HasSuffix(path, "link.yml") {
				target = []string{cfgPath, path}
			}
			err := admin.CheckOwnedChain(target, tr)
			var ae *adminapi.Error
			if !errors.As(err, &ae) || ae.Code != adminapi.CodeConfigUnavailable {
				t.Fatalf("error %v, want config_unavailable", err)
			}
			// With every uid of this test untrusted, the first directory
			// the test user owns is reported, which may be above path.
			if (problem != "not_root_owned" && ae.Details["path"] != path) || ae.Details["problem"] != problem {
				t.Errorf("details %v, want path %s problem %s", ae.Details, path, problem)
			}
		})
	}

	// And the service refuses the request when its loader does.
	h := newHarness(t)
	before, _ := os.ReadFile(h.usersFile)
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) {
			return nil, adminapi.NewError(adminapi.CodeConfigUnavailable, "config.toml is writable by group").With("path", cfgPath)
		},
		Tools: h.tools, Blocks: h.blocks, Trail: h.trail,
		Record:   func(context.Context, *config.Config, audit.Record) error { return nil },
		Accounts: func(cfg *config.Config) (idp.Directory, error) { return autheliafile.New(h.usersFile), nil },
		IsBusy:   store.IsBusy,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ResetAccountPassword(context.Background(), alice, "ana")
	requireCode(t, err, adminapi.CodeConfigUnavailable)
	after, _ := os.ReadFile(h.usersFile)
	if !bytes.Equal(before, after) {
		t.Fatal("the users file was written although the configuration check failed")
	}
}

// TestAudit_PagesByPosition: the newest `limit` records, oldest first, and
// next_before walks back.
func TestAudit_PagesByPosition(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		if err := h.trail.Record(context.Background(), audit.Record{AnalystIdentity: "ana", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt",
			Timestamp: now.Add(time.Duration(i) * time.Second), Outcome: audit.OutcomeAllowed}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := h.svc.Audit(context.Background(), adminapi.AuditQuery{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Records) != 2 || p.Records[0].Position != 4 || p.Records[1].Position != 5 || !p.More || p.NextBefore != 4 {
		t.Fatalf("first page %+v", p)
	}
	p, err = h.svc.Audit(context.Background(), adminapi.AuditQuery{Limit: 10, Before: p.NextBefore})
	if err != nil || len(p.Records) != 3 || p.Records[2].Position != 3 || p.More {
		t.Fatalf("second page %+v, %v", p, err)
	}
	p, err = h.svc.Audit(context.Background(), adminapi.AuditQuery{Limit: 100000})
	if err != nil || p.Limit != 5000 {
		t.Fatalf("limit not clamped: %+v, %v", p, err)
	}
}

// addForeignAccounts appends to the users file two accounts Gatte does not
// manage: one with a group outside [group_to_role] (an IdP admin of other
// applications) and one with no group at all.
func (h *harness) addForeignAccounts(t *testing.T) {
	t.Helper()
	hash, err := idp.HashPassword("lab-only")
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.NewReplacer("LAB_HASH", hash, "PWKEY", "pass"+"word").Replace(`  sso-admin:
    disabled: false
    displayname: "SSO Admin"
    PWKEY: "LAB_HASH"
    email: sso-admin@example.org
    groups:
      - blue-ir
      - idp-admins
  plain:
    disabled: false
    displayname: "Plain"
    PWKEY: "LAB_HASH"
    email: plain@example.org
    groups: []
`)
	f, err := os.OpenFile(h.usersFile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestAccounts_ADelegatedOperatorReachesOnlyAccountsGatteManages is
// design/adr/0040 §1: a member of [admin] account_group, who is not root,
// resets, disables and regroups only accounts whose every group is in
// [group_to_role]. An IdP account with another group, or none, is out of
// reach: resetting it would hand over a login to every other application
// behind the IdP.
func TestAccounts_ADelegatedOperatorReachesOnlyAccountsGatteManages(t *testing.T) {
	h := newHarness(t)
	h.addForeignAccounts(t)
	before, _ := os.ReadFile(h.usersFile)
	for _, user := range []string{"sso-admin", "plain"} {
		res, err := h.svc.ResetAccountPassword(context.Background(), alice, user)
		requireCode(t, err, adminapi.CodeAccountNotManaged)
		if res.OneTimePassword != "" {
			t.Fatalf("reset of %s handed over a password", user)
		}
		_, err = h.svc.SetAccountDisabled(context.Background(), alice, user, true)
		requireCode(t, err, adminapi.CodeAccountNotManaged)
		_, err = h.svc.SetAccountGroups(context.Background(), alice, user, adminapi.GroupsRequest{Groups: []string{"blue-ir"}})
		requireCode(t, err, adminapi.CodeAccountNotManaged)
	}
	after, _ := os.ReadFile(h.usersFile)
	if !bytes.Equal(before, after) {
		t.Fatal("the users file was written for an account Gatte does not manage")
	}
	if rows := h.rows(t); len(rows) != 0 {
		t.Fatalf("refused changes were recorded: %+v", rows)
	}
	// A managed account is still reachable.
	if res, err := h.svc.ResetAccountPassword(context.Background(), alice, "ana"); err != nil || res.OneTimePassword == "" {
		t.Fatalf("reset of a managed account: %+v, %v", res, err)
	}
}

// failingChainOrder is a trail whose whole-table read fails: the pages the
// fronts load routinely must not need it.
type failingChainOrder struct{ *auditsqlite.Recorder }

func (failingChainOrder) ChainOrder(context.Context) ([]audit.Record, error) {
	return nil, errors.New("the whole trail was read into memory")
}

// TestAuditAndPeople_DoNotReadTheWholeTrail: GET /v1/audit and /v1/people
// page and aggregate in the database; neither materialises every row.
func TestAuditAndPeople_DoNotReadTheWholeTrail(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := h.trail.Record(context.Background(), audit.Record{AnalystIdentity: "ana", AnalystName: "Ana", Tool: "casemgmt.list_cases", TargetUpstream: "casemgmt",
			Timestamp: now.Add(time.Duration(i) * time.Second), Outcome: audit.OutcomeAllowed}); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return h.cfg, nil },
		Tools:  h.tools, Blocks: h.blocks, Trail: failingChainOrder{h.trail},
		Record: func(context.Context, *config.Config, audit.Record) error { return nil },
		IsBusy: store.IsBusy,
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Audit(context.Background(), adminapi.AuditQuery{Limit: 1})
	if err != nil || len(p.Records) != 1 || p.Records[0].Position != 3 || !p.More {
		t.Fatalf("audit page %+v, %v", p, err)
	}
	people, err := svc.People(context.Background())
	if err != nil || len(people.Seen) != 1 || people.Seen[0].Calls != 3 || people.Seen[0].Name != "Ana" || !people.Seen[0].LastCall.Equal(now.Add(2*time.Second)) {
		t.Fatalf("people %+v, %v", people, err)
	}
}

// TestAccounts_ARootPeerReachesEveryAccount: root could edit the users
// file anyway, and design/adr/0038 let it; the limit is the delegation's.
func TestAccounts_ARootPeerReachesEveryAccount(t *testing.T) {
	h := newHarness(t)
	h.addForeignAccounts(t)
	root := admin.Actor{Name: "alice", Via: "root", Front: "api", Root: true}
	if res, err := h.svc.ResetAccountPassword(context.Background(), root, "sso-admin"); err != nil || res.OneTimePassword == "" {
		t.Fatalf("root reset of an unmanaged account: %+v, %v", res, err)
	}
	if _, err := h.svc.SetAccountDisabled(context.Background(), root, "plain", true); err != nil {
		t.Fatalf("root disable of an account with no group: %v", err)
	}
}
