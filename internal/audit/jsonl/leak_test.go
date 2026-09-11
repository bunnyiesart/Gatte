package jsonl_test

// The leak test for the SIEM sink, modelled on
// internal/vault/sopsage/leak_test.go -- the test WORKFLOW.md Phase 2
// calls "the single most important test in the whole project".
//
// The shape is the same and the target is different. There, the question
// was whether a resolved credential could be observed by the CLIENT side
// of a tool call. Here it is whether anything sensitive can reach the
// GRAYLOG side of one: a real dispatch runs through a real Gateway whose
// Audit port is the JSONL decorator, the upstream is handed the secret
// inside its tool arguments AND echoes it back inside its error text, and
// the on-disk sink is then searched for every form of it.
//
// The gateway is real on purpose. Asserting on a Line built by hand would
// prove only that the struct I wrote contains the fields I put in it; the
// thing worth proving is that no value survives the trip from an
// analyst's arguments or a backend's error message all the way to the
// file a shipper forwards.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/audit/jsonl"
	auditsql "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	quarantinesql "github.com/bunnyiesart/Gatte/internal/quarantine/sqlite"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// ------------------------------------------------------- gateway fakes

// echoUpstream is the hostile backend: it keeps whatever arguments it was
// handed and fails with an error that quotes them back. Both halves
// matter -- an implementation could leak arguments without leaking error
// text, or the reverse.
type echoUpstream struct {
	mu      sync.Mutex
	defs    []gateway.ToolDef
	secret  string
	lastArg string
}

func (u *echoUpstream) ListTools(context.Context) ([]gateway.ToolDef, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return slices.Clone(u.defs), nil
}

func (u *echoUpstream) CallTool(_ context.Context, tool string, args json.RawMessage) (gateway.Result, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastArg = string(args)
	// The upstream saw the secret in its arguments and puts it in its
	// error. This is what a chatty backend, or a deliberately hostile one,
	// actually does.
	return gateway.Result{}, fmt.Errorf("backend %q exploded while handling %s: token=%s", tool, args, u.secret)
}

func (u *echoUpstream) Close() error { return nil }

func (u *echoUpstream) argsSeen() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastArg
}

type oneDialer struct{ up *echoUpstream }

func (d *oneDialer) Dial(context.Context, gateway.UpstreamSpec, map[string]string) (gateway.Upstream, error) {
	return d.up, nil
}

type oneRegistry struct{ entries []registry.UpstreamServer }

func (r *oneRegistry) List(context.Context) ([]registry.UpstreamServer, error) {
	return slices.Clone(r.entries), nil
}
func (r *oneRegistry) Register(context.Context, registry.UpstreamServer) error {
	return errors.New("not used in these tests")
}
func (r *oneRegistry) Get(context.Context, string) (registry.UpstreamServer, error) {
	return registry.UpstreamServer{}, registry.ErrNotFound
}
func (r *oneRegistry) Deregister(context.Context, string) error { return registry.ErrNotFound }

type oneVault struct{ values map[string]string }

func (v *oneVault) Resolve(_ context.Context, name string) (vault.Secret, error) {
	value, ok := v.values[name]
	if !ok {
		return vault.Secret{}, vault.ErrNotFound
	}
	return vault.NewSecret(value), nil
}

var (
	_ gateway.Upstream    = (*echoUpstream)(nil)
	_ gateway.Dialer      = (*oneDialer)(nil)
	_ registry.Repository = (*oneRegistry)(nil)
	_ vault.Provider      = (*oneVault)(nil)
)

// --------------------------------------------------------- leak harness

const (
	leakUpstream = "threatintel"
	leakTool     = "lookup_ioc"
	leakEnvVar   = "THREATINTEL_VT_KEY"
)

type leakHarness struct {
	t        *testing.T
	gw       *gateway.Gateway
	upstream *echoUpstream
	sinkPath string
}

// newLeakHarness wires a real Gateway whose Audit port is the JSONL
// decorator over the real sqlite adapter over a real FileSink. Only the
// registry, vault, dialer and upstream are fakes, and each of those is a
// fake because the test needs to control what the backend does, not
// because the real one is inconvenient.
//
// secret is planted in three places at once: as the vault-resolved value
// for the upstream's credential, inside the tool arguments the analyst
// sends, and inside the error text the backend returns.
func newLeakHarness(t *testing.T, secret string) *leakHarness {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quarantinesql.Migrate(db); err != nil {
		t.Fatalf("quarantine migrate: %v", err)
	}
	if err := auditsql.Migrate(db); err != nil {
		t.Fatalf("audit migrate: %v", err)
	}

	sinkPath := t.TempDir() + "/audit.jsonl"
	sink, err := jsonl.OpenFile(sinkPath)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { sink.Close() })

	auditor, err := jsonl.New(auditsql.New(db), sink, testChain, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("jsonl.New: %v", err)
	}

	namespaced := gateway.Namespaced(leakUpstream, leakTool)
	policy, err := access.NewPolicy(
		[]access.Role{{Name: "n1-triage", Tools: []string{namespaced}}},
		map[string]string{"soc-n1": "n1-triage"},
	)
	if err != nil {
		t.Fatalf("access.NewPolicy: %v", err)
	}

	up := &echoUpstream{
		secret: secret,
		defs: []gateway.ToolDef{{
			Name:        leakTool,
			Description: "look up an indicator",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"ioc":{"type":"string"}}}`),
		}},
	}

	entry := registry.UpstreamServer{
		Name:        leakUpstream,
		Transport:   registry.TransportStdio,
		Command:     "/usr/bin/" + leakUpstream,
		EnvVarNames: []string{leakEnvVar},
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("test registry entry is invalid: %v", err)
	}

	gw, err := gateway.New(gateway.Config{
		Registry:   &oneRegistry{entries: []registry.UpstreamServer{entry}},
		Vault:      &oneVault{values: map[string]string{leakEnvVar: secret}},
		Quarantine: quarantinesql.New(db),
		Audit:      auditor,
		Policy:     policy,
		Dialer:     &oneDialer{up: up},
		Now:        func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	t.Cleanup(func() { gw.Close() })

	if err := gw.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	q := quarantinesql.New(db)
	got, err := q.Approve(context.Background(), leakUpstream, leakTool)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.Status != quarantine.StatusApproved {
		t.Fatalf("Approve left the tool %q", got.Status)
	}

	return &leakHarness{t: t, gw: gw, upstream: up, sinkPath: sinkPath}
}

// dispatch runs one call whose arguments carry the secret, and requires it
// to fail -- the failure is the point, because it is what puts the
// upstream's error text (which quotes the secret) into the gateway's
// failure-classification path.
func (h *leakHarness) dispatch(secret string) {
	h.t.Helper()

	caller := gateway.Caller{
		Identity:      access.Identity{Subject: "sub-analyst-1", Name: "Ana Lyst", Groups: []string{"soc-n1"}},
		SourceAddress: "198.51.100.77",
	}
	args := json.RawMessage(fmt.Sprintf(`{"ioc":%q}`, secret))

	_, err := h.gw.Dispatch(context.Background(), caller, gateway.Namespaced(leakUpstream, leakTool), args)
	if err == nil {
		h.t.Fatal("dispatch succeeded; this harness's upstream always fails, so the wiring is broken")
	}
	if !strings.Contains(h.upstream.argsSeen(), secret) {
		h.t.Fatal("the upstream never received the secret in its arguments -- nothing below would prove anything")
	}
	if !strings.Contains(err.Error(), secret) {
		h.t.Fatal("the error returned to the caller does not carry the secret -- the leak this test looks for was never created")
	}
}

// sink returns the raw bytes a shipper would forward.
func (h *leakHarness) sink() string {
	h.t.Helper()
	raw, err := os.ReadFile(h.sinkPath)
	if err != nil {
		h.t.Fatalf("read sink: %v", err)
	}
	return string(raw)
}

// requireTwoLines proves the sink is not empty for a boring reason. A
// "the secret is not in the file" assertion against an empty file is the
// confident wrong answer this project has been bitten by twice; every
// negative below runs only after this positive control holds.
func (h *leakHarness) requireTwoLines() []map[string]any {
	h.t.Helper()

	var lines []map[string]any
	for i, l := range strings.Split(strings.TrimSuffix(h.sink(), "\n"), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			h.t.Fatalf("line %d is not valid JSON (%v): %s", i, err, l)
		}
		lines = append(lines, m)
	}
	if len(lines) != 2 {
		h.t.Fatalf("sink holds %d lines, want 2 (allowed then failed); the emitter did not run", len(lines))
	}
	if lines[0]["verdict"] != "allowed" || lines[1]["verdict"] != "failed" {
		h.t.Fatalf("verdicts = %v, %v; want allowed then failed", lines[0]["verdict"], lines[1]["verdict"])
	}
	// Positive control on the search itself: the file demonstrably
	// contains values this test can find, so a later "not found" is
	// evidence rather than an artefact of looking in the wrong place.
	for _, want := range []string{"sub-analyst-1", "threatintel.lookup_ioc", "198.51.100.77", testChain} {
		if !strings.Contains(h.sink(), want) {
			h.t.Fatalf("control value %q is missing from the sink; the search below cannot be trusted", want)
		}
	}
	return lines
}

// ---------------------------------------------------------------- tests

// TestDispatchDoesNotLeakASecretIntoTheSIEMSink is the sink's counterpart
// to internal/vault/sopsage's leak test: a real secret is the upstream's
// vault-resolved credential, is inside the analyst's tool arguments, and
// is quoted back inside the backend's error text -- and must appear
// nowhere in the file a shipper forwards to Graylog.
func TestDispatchDoesNotLeakASecretIntoTheSIEMSink(t *testing.T) {
	const secret = "vt-fake-l3ak-check-9f8e7d6c5b4a"

	h := newLeakHarness(t, secret)
	h.dispatch(secret)
	lines := h.requireTwoLines()

	if strings.Contains(h.sink(), secret) {
		t.Fatalf("LEAK: the emitted JSONL contains the raw secret:\n%s", h.sink())
	}
	// The arguments as a whole, not just the secret inside them: tool
	// arguments carry indicators and PII even when they carry no
	// credential, and ADR-0017 excludes them wholesale.
	if strings.Contains(h.sink(), `"ioc"`) {
		t.Fatalf("LEAK: the emitted JSONL contains the tool arguments:\n%s", h.sink())
	}
	// And the upstream's own words. `rule` is drawn from the gateway's
	// closed classification set; an implementation that put cause.Error()
	// there would put backend-controlled text into the SIEM.
	if strings.Contains(h.sink(), "exploded") {
		t.Fatalf("LEAK: the emitted JSONL contains the upstream's error text:\n%s", h.sink())
	}

	// The failure IS recorded -- narrowed to the gateway's own vocabulary.
	// Without this the test would pass just as well if the emitter wrote
	// nothing at all about the failure.
	rule, _ := lines[1]["rule"].(string)
	if rule == "" {
		t.Fatal("the failed line carries no rule; the failure was recorded without saying anything about itself")
	}
	if strings.Contains(rule, secret) || strings.Contains(rule, "exploded") {
		t.Fatalf("LEAK: rule = %q", rule)
	}
}

// TestDispatchDoesNotLeakABearerTokenIntoTheSIEMSink is the JWT variant.
//
// Each of the three segments is asserted separately, not just the whole
// token: a truncated token is still a credential (ADR-0012 says so in as
// many words), and an implementation that logged "the first 20 characters"
// or "everything up to the signature" would sail past a whole-string
// check.
func TestDispatchDoesNotLeakABearerTokenIntoTheSIEMSink(t *testing.T) {
	// Shaped like a real compact JWS: three base64url segments. Not a
	// valid signature over anything -- what matters is that each segment
	// is a long, distinctive string that could not appear by accident.
	const (
		header    = "eyJhbGciOiJSUzI1NiIsImtpZCI6Imdhc3RlLTIwMjYtMDktMTEifQ"
		payload   = "eyJzdWIiOiJzdWItYW5hbHlzdC0xIiwiYXVkIjoibWNwLWdhdGV3YXkiLCJleHAiOjE3OTM0NTYwMDB9"
		signature = "S1gN4tUr3XqP7wLm2ZbV9cYhKjF0dRtE8uIoAsDfGhJkLzXcVbNmQwErTyUiOpAsDfGhJkLz"
		token     = header + "." + payload + "." + signature
	)

	h := newLeakHarness(t, token)
	h.dispatch(token)
	h.requireTwoLines()

	sink := h.sink()
	if strings.Contains(sink, token) {
		t.Fatalf("LEAK: the emitted JSONL contains the whole bearer token:\n%s", sink)
	}
	for name, segment := range map[string]string{
		"header": header, "payload": payload, "signature": signature,
	} {
		if strings.Contains(sink, segment) {
			t.Fatalf("LEAK: the emitted JSONL contains the token's %s segment:\n%s", name, sink)
		}
	}
}

// TestSIEMSinkCarriesNoGroupClaims: the caller's IdP groups drive
// authorization and are not evidence. They are membership data about a
// person, they change outside this system, and a stream of them in Graylog
// is a directory nobody asked for.
//
// This is also the honest place to record what v1 does NOT carry: there is
// no `roles` field either. See ADR-0017 -- audit.Record holds no roles, and
// a field the gateway cannot populate would be a schema key that is always
// empty.
func TestSIEMSinkCarriesNoGroupClaims(t *testing.T) {
	const secret = "vt-fake-l3ak-check-0000000000"

	h := newLeakHarness(t, secret)
	h.dispatch(secret)
	h.requireTwoLines()

	// "soc-n1" is the group claim newLeakHarness gives the analyst, and
	// "n1-triage" is the role it maps to. Neither is a line field.
	for _, forbidden := range []string{"soc-n1", "n1-triage", "Ana Lyst"} {
		if strings.Contains(h.sink(), forbidden) {
			t.Fatalf("LEAK: the emitted JSONL contains %q:\n%s", forbidden, h.sink())
		}
	}
}
