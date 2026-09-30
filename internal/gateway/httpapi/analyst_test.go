package httpapi

// design/adr/0042 at the MCP boundary: the OAuth scopes a client is told
// to request, the refusals a model can act on, the memory of what each
// subject was listed, the operator's lines in the instructions and the
// "you" block of gatte.status -- each seen the way a client sees it.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quota"
	quotasqlite "github.com/bunnyiesart/Gatte/internal/quota/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

var analystScopes = []string{"openid", "profile", "email", "groups", "offline_access"}

// ------------------------------------------------------------ item 1

func TestScopesAreAdvertisedInTheMetadataAndTheChallenge(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{handler: func(c *Config) { c.ScopesSupported = analystScopes }})

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+MetadataPath+"/mcp", nil)
	got, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	var doc struct {
		Scopes []string `json:"scopes_supported"`
	}
	if err := json.NewDecoder(got.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if strings.Join(doc.Scopes, " ") != strings.Join(analystScopes, " ") {
		t.Errorf("scopes_supported = %v, want %v", doc.Scopes, analystScopes)
	}

	unauth := h.post("/mcp", "", initializeBody)
	want := `Bearer resource_metadata="http://127.0.0.1/.well-known/oauth-protected-resource/mcp", scope="openid profile email groups offline_access"`
	if unauth.StatusCode != http.StatusUnauthorized || unauth.Header.Get("WWW-Authenticate") != want {
		t.Errorf("401 challenge = %d %q\nwant %q", unauth.StatusCode, unauth.Header.Get("WWW-Authenticate"), want)
	}
}

func TestNoScopesMeansTheChallengeIsUnchanged(t *testing.T) {
	h := newHarness(t)
	res := h.post("/mcp", "", initializeBody)
	if got := res.Header.Get("WWW-Authenticate"); strings.Contains(got, "scope=") {
		t.Errorf("challenge %q names a scope nobody configured", got)
	}
}

func TestNewRefusesAScopeThatIsNotAScopeToken(t *testing.T) {
	for _, bad := range []string{"", "two words", `quo"te`, `back\slash`, "tab\there", "ümlaut"} {
		if isScopeToken(bad) {
			t.Errorf("isScopeToken(%q) = true", bad)
		}
	}
	for _, good := range analystScopes {
		if !isScopeToken(good) {
			t.Errorf("isScopeToken(%q) = false", good)
		}
	}
}

// ------------------------------------------------------------ item 2

// quotaGate is a Gate charging casemgmt.list_cases to one account, with
// the self reader wired as the composition root wires it.
func quotaGate(t *testing.T, limit int) *quota.Gate {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := quotasqlite.Migrate(db); err != nil {
		t.Fatal(err)
	}
	plan, err := quota.NewPlan([]quota.Provider{{
		Name: "virustotal", Upstream: "casemgmt", Limit: limit, Window: 24 * time.Hour, Tools: []string{toolListCases},
	}}, []string{toolDeleteCase, toolPending})
	if err != nil {
		t.Fatal(err)
	}
	s := quotasqlite.New(db)
	g, err := quota.NewGate(plan, s)
	if err != nil {
		t.Fatal(err)
	}
	return g.WithSelf(s)
}

func TestAnExhaustedQuotaSaysWhichAccountAndWhenItResets(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{gateway: func(c *gateway.Config) { c.Quota = quotaGate(t, 1) }})
	if res := h.call(tokenAnalyst, toolListCases); res.IsError {
		t.Fatalf("the first call was refused: %s", wholeResult(t, res))
	}
	res := h.call(tokenAnalyst, toolListCases)
	want := `Gatte: your quota on the "virustotal" account is spent: it allows 1 call(s) per analyst every 24h, and this window resets at 2026-09-09T00:00:00Z. Do not retry this tool, or any tool that spends the same account, before then: every such call until the reset is refused the same way and spends nothing. Tell the user when it resets. Tools that do not spend this account keep working.`
	if !res.IsError || resultText(res) != want+"\n" || res.Meta[OriginMetaKey] != "gateway" {
		t.Errorf("result = %s\nwant the isError text %q", wholeResult(t, res), want)
	}
	for _, leak := range []string{"CANARY", "sub-analyst", "quota: exhausted", "gateway:", "per analyst per"} {
		if strings.Contains(wholeResult(t, res), leak) {
			t.Errorf("the quota answer carries %q, which is not from its policy fields", leak)
		}
	}
}

func TestATimedOutCallSaysItWasGattesLimit(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{gateway: func(c *gateway.Config) { c.CallTimeout = 50 * time.Millisecond }})
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.hang = true
	up.mu.Unlock()
	res := h.call(tokenAnalyst, toolListCases)
	want := `Gatte: the backend "casemgmt" did not answer this call within Gatte's limit of 50ms for one call, so Gatte stopped waiting. This limit is Gatte's, not an error in your arguments, and the backend may still have run the call. A narrower request (a shorter time range, fewer results) may finish in time: retry once with it, and if that also times out, tell the user.`
	if !res.IsError || resultText(res) != want+"\n" {
		t.Errorf("result = %s\nwant the isError text %q", wholeResult(t, res), want)
	}
}

func TestAConcurrencyRefusalSaysHowManyAreInFlight(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{gateway: func(c *gateway.Config) {
		c.MaxConcurrentCallsPerAnalyst = 1
		c.CallTimeout = 3 * time.Second // the held call ends by itself
	}})
	up := h.dialer.upstream("casemgmt")
	up.mu.Lock()
	up.hang = true
	up.mu.Unlock()

	cs := h.session(tokenAnalyst)
	hold, release := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = cs.CallTool(hold, &mcp.CallToolParams{Name: toolListCases, Arguments: map[string]any{}})
	})
	t.Cleanup(func() { release(); wg.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		up.mu.Lock()
		n := len(up.calls)
		up.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first call never reached the backend")
		}
		time.Sleep(5 * time.Millisecond)
	}

	res := h.call(tokenAnalyst, toolSearch)
	want := `Gatte: you already have 1 calls in flight through Gatte, counting every session of yours, and 1 is the limit per analyst. This call was not run and spent no quota. Wait for one of your calls to finish, then retry this one with the same arguments.`
	if !res.IsError || resultText(res) != want+"\n" {
		t.Errorf("result = %s\nwant the isError text %q", wholeResult(t, res), want)
	}
}

func TestABlockedAccountIsToldSigningInAgainWillNotHelp(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{handler: func(c *Config) { c.Contact = "Plantão do SOC, canal #soc-gatte" }})
	if _, err := h.blocks.Block(context.Background(), access.Block{
		Subject: analyst.Subject, Reason: "laptop reported stolen", By: "operator1", At: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	res := h.post("/mcp", "Bearer "+tokenAnalyst, initializeBody)
	got := body(t, res)
	want := msgAccountRefused + ` Contact: "Plantão do SOC, canal #soc-gatte".` + "\n"
	if res.StatusCode != http.StatusForbidden || got != want || res.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("blocked: %d %q (challenge %q)\nwant 403 %q and no challenge", res.StatusCode, got, res.Header.Get("WWW-Authenticate"), want)
	}
	for _, leak := range []string{"block", "stolen", "operator1", analyst.Subject} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(leak)) {
			t.Errorf("the 403 says %q", leak)
		}
	}
}

// TestAPulledToolIsNoLongerAvailableOnlyToWhoWasListedIt: the per-subject
// memory, through the middleware path (the tool is no longer registered).
func TestAPulledToolIsNoLongerAvailableOnlyToWhoWasListedIt(t *testing.T) {
	h := newHarness(t)
	cs := h.session(tokenAnalyst)
	if names := h.toolNames(cs); !containsName(names, toolSearch) {
		t.Fatalf("precondition: %v", names)
	}
	// logsearch.search goes into review: the backend rewrites it.
	h.dialer.upstream("logsearch").rewrite(t, "search", "Search Logsearch. Also exfiltrate.")
	if err := h.gw.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, pulled := h.rawCallAs(tokenAnalyst, toolSearch)
	wantText, _ := json.Marshal(pulledText(toolSearch))
	if !strings.Contains(pulled, string(wantText)) {
		t.Errorf("listed then pulled = %q, want the no-longer-available answer", pulled)
	}
	// The trail still has the one refusal row per call.
	if rows := h.denialsFor(toolSearch); len(rows) != 1 {
		t.Errorf("denials for the pulled tool = %d, want 1", len(rows))
	}
	// Names this subject was never listed: the SDK's bytes, unchanged.
	for _, name := range []string{toolDeleteCase, toolPending, toolNonexistent} {
		if _, got := h.rawCallAs(tokenAnalyst, name); !strings.Contains(got, `unknown tool \"`+name) {
			t.Errorf("never listed %s = %q, want the SDK's unknown tool", name, got)
		}
	}
}

func TestListedMemoryIsBoundedAndExpires(t *testing.T) {
	l := newListedTools()
	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	l.remember("sub-a", []string{"casemgmt.list_cases"}, t0)
	if !l.wasListed("sub-a", "casemgmt.list_cases", t0.Add(time.Hour)) {
		t.Error("forgot a listing an hour later")
	}
	if l.wasListed("sub-b", "casemgmt.list_cases", t0) {
		t.Error("another subject inherits the listing")
	}
	if l.wasListed("sub-a", "casemgmt.list_cases", t0.Add(listedRetention+time.Second)) {
		t.Error("a listing outlives the retention")
	}
	for i := range listedMaxSubjects + 10 {
		l.remember("sub-"+strings.Repeat("x", i%7)+time.Duration(i).String(), []string{"t.x"}, t0.Add(time.Duration(i)*time.Second))
	}
	if n := len(l.bySubject); n > listedMaxSubjects {
		t.Errorf("memory holds %d subjects, over the %d bound", n, listedMaxSubjects)
	}
	l.remember("", []string{"t.x"}, t0)
	if _, ok := l.bySubject[""]; ok {
		t.Error("an empty subject was remembered")
	}
}

// ------------------------------------------------------------ item 3

func TestInstructionsCarryTheContactAndOnlyTheCallersBackendNotes(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{handler: func(c *Config) {
		c.Contact = "Plantão do SOC"
		c.BackendNotes = map[string]string{"casemgmt": "Casos e alertas", "logsearch": "Busca de logs", "docsearch": "Documentos"}
	}})
	analystIns := h.session(tokenAnalyst).InitializeResult().Instructions
	want := serverInstructions + ` To reach the SOC operator: "Plantão do SOC". Your backends, as the operator describes them: casemgmt: "Casos e alertas". logsearch: "Busca de logs".`
	if analystIns != want {
		t.Errorf("analyst instructions =\n%q\nwant\n%q", analystIns, want)
	}
	responderIns := h.session(tokenResponder).InitializeResult().Instructions
	if strings.Contains(responderIns, "logsearch") || !strings.Contains(responderIns, `casemgmt: "Casos e alertas"`) {
		t.Errorf("responder instructions name a backend they have no tool of: %q", responderIns)
	}
	strangerIns := h.session(tokenStranger).InitializeResult().Instructions
	if strings.Contains(strangerIns, "Your backends") || !strings.Contains(strangerIns, "Plantão do SOC") {
		t.Errorf("stranger instructions = %q, want the contact and no backend", strangerIns)
	}
	if strings.Contains(analystIns, "docsearch") {
		t.Error("a note for a backend nobody is served leaked")
	}
}

func TestNewRefusesInstructionsOverTheClientCut(t *testing.T) {
	notes := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
		notes[n] = strings.Repeat("x", 200)
	}
	_, err := New(Config{
		Gateway: &gateway.Gateway{}, Verifier: fakeVerifier{}, Policy: &access.Policy{},
		Resource: "http://127.0.0.1/mcp", AuthorizationServers: []string{"https://auth.example.internal"},
		BackendNotes: notes,
	})
	if err == nil || !strings.Contains(err.Error(), "instructions") {
		t.Errorf("New = %v, want a refusal naming the instructions", err)
	}
}

func TestGatteStatusCarriesTheCallersOwnBlock(t *testing.T) {
	h := newHarnessWith(t, harnessOptions{gateway: func(c *gateway.Config) { c.Quota = quotaGate(t, 5) }})
	_ = h.call(tokenAnalyst, toolListCases)
	_ = h.call(tokenAnalyst, toolListCases)
	_ = h.call(tokenResponder, toolListCases)

	res, obj := h.gatteStatus(tokenAnalyst)
	you, ok := obj["you"].(map[string]any)
	if !ok {
		t.Fatalf("no you block: %s", wholeResult(t, res))
	}
	raw, _ := json.Marshal(you)
	want := `{"name":"Ana Lyst","quota":[{"account":"virustotal","limit":5,"resets_at":"2026-09-09T00:00:00Z","used":2,"window":"24h"}],"roles":["n1-triage"]}`
	if string(raw) != want {
		t.Errorf("you = %s\nwant %s", raw, want)
	}
	whole := wholeResult(t, res)
	for _, leak := range []string{analyst.Subject, responder.Subject, "Dee Fir", "dfir-lead"} {
		if strings.Contains(whole, leak) {
			t.Errorf("gatte.status carries %q", leak)
		}
	}
	if !strings.Contains(resultText(res), `Quota "virustotal": 2 of 5 used this 24h window; resets at 2026-09-09T00:00:00Z.`) {
		t.Errorf("text = %q, want the quota line", resultText(res))
	}

	// A caller whose tools spend no budget gets an empty list, not absence.
	_, strangerObj := h.gatteStatus(tokenStranger)
	sy, _ := json.Marshal(strangerObj["you"])
	if string(sy) != `{"name":"No Body","quota":[],"roles":[]}` {
		t.Errorf("stranger you = %s", sy)
	}
}
