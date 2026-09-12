// Command trafficgen drives synthetic MCP traffic through a RUNNING gateway so
// the Audit Trail accumulates realistic records without an analyst having to
// sit there clicking.
//
// It is the HTTP counterpart to lab/probe, and deliberately not an extension
// of it. probe spawns ONE upstream over stdio and asks one question -- did the
// credential arrive, and did it leak. This connects to the gateway's
// streamable-HTTP endpoint as an ordinary authenticated client, enumerates
// whatever that caller's role can see, and calls it. The two tools answer
// different questions and share no useful code beyond the SDK.
//
// # WHAT IT ACTUALLY DOES TO THE BACKENDS
//
// Nothing here is simulated below the gateway. A call dispatched to a real
// upstream runs a real query against that upstream -- a real Graylog search, a
// real IRIS read, a real third-party lookup against someone's API quota. The
// traffic is synthetic in the sense that no human meant it, not in the sense
// that it is inert. Point this at a gateway wired to lab/servers/* when what
// you want is a populated trail; point it at production only when you mean to.
// That is what -confirm is for.
//
// Generated argument values are drawn from reserved ranges on purpose:
// RFC 5737 documentation addresses (192.0.2.0/24) and example.com, never a
// real address or domain. A load generator that turns into a scanner because
// someone left it running overnight is a bad way to find out.
//
// Exit codes follow lab/probe: 0 the run completed, 1 the run completed and
// something in it failed in a way worth a non-zero exit, 2 the tool could not
// run at all (bad flags, no token, connect failure).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	exitOK       = 0
	exitFail     = 1
	exitUsageErr = 2
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

type config struct {
	endpoint  string
	tokenFile string
	caFile    string
	duration  time.Duration
	rate      float64
	seed      int64
	only      string
	skip      string
	unknown   int
	planOnly  bool
	confirm   bool
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, code, err := parseFlags(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: %v\n", err)
		return code
	}
	if cfg == nil {
		return exitOK // -h printed usage
	}

	// The token is read from a file or the environment and never from a
	// flag. A bearer token on a command line is in the shell history and in
	// every `ps` on the box, and this project exists to stop credentials
	// living in places like that.
	token, err := loadToken(cfg.tokenFile)
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: %v\n", err)
		return exitUsageErr
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpClient, err := buildHTTPClient(cfg.caFile, token)
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: %v\n", err)
		return exitUsageErr
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "trafficgen", Version: "v0"}, nil)
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   cfg.endpoint,
		HTTPClient: httpClient,
	}, nil)
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: connect %s: %v\n", cfg.endpoint, err)
		fmt.Fprintf(stderr, "  a 401 here means the token is absent, expired or has the wrong audience;\n")
		fmt.Fprintf(stderr, "  Authelia mints ~1h tokens and an empty-audience token is refused by design.\n")
		return exitUsageErr
	}
	// Discarded explicitly: this Close is teardown of a session whose work is
	// already done and already counted. A failure to tear down cleanly says
	// nothing about the traffic that was generated, so there is no outcome
	// here that should change what this run reports or exits with.
	defer func() { _ = sess.Close() }()

	listed, err := sess.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: list tools: %v\n", err)
		return exitUsageErr
	}

	callable, err := selectTools(listed.Tools, cfg.only, cfg.skip)
	if err != nil {
		fmt.Fprintf(stderr, "trafficgen: %v\n", err)
		return exitUsageErr
	}
	if len(callable) == 0 {
		fmt.Fprintf(stderr, "trafficgen: no tools to call.\n")
		fmt.Fprintf(stderr, "  The gateway served %d tool(s); the filters left none.\n", len(listed.Tools))
		fmt.Fprintf(stderr, "  An EMPTY list from the gateway is not a bug either: a role that grants\n")
		fmt.Fprintf(stderr, "  nothing, and a backend whose tools are all still quarantined, both look\n")
		fmt.Fprintf(stderr, "  exactly like this to a client.\n")
		return exitUsageErr
	}

	printPlan(stdout, cfg, listed.Tools, callable)
	if cfg.planOnly {
		return exitOK
	}
	if err := guardEndpoint(cfg.endpoint, cfg.confirm); err != nil {
		fmt.Fprintf(stderr, "trafficgen: %v\n", err)
		return exitUsageErr
	}

	// math/rand, seeded and printed, on purpose -- gosec's G404 fires here
	// and is wrong about this use. Nothing generated is a secret: these
	// values pick which tool to call and what to pass it. A reproducible
	// run is the actual requirement, and crypto/rand cannot give one.
	seed := cfg.seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	fmt.Fprintf(stdout, "\nseed %d (pass -seed %d to repeat this exact run)\n\n", seed, seed)

	tally := drive(ctx, sess, callable, cfg, rand.New(rand.NewSource(seed)), stdout)
	printSummary(stdout, tally)

	if tally.transportErrors > 0 {
		return exitFail
	}
	return exitOK
}

func parseFlags(args []string, stderr io.Writer) (*config, int, error) {
	cfg := &config{}
	fs := flag.NewFlagSet("trafficgen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.endpoint, "endpoint", "", "gateway streamable-HTTP endpoint, e.g. https://mcp.soc.internal/ (required)")
	fs.StringVar(&cfg.tokenFile, "token-file", "", "file holding the bearer token; defaults to $GATTE_TOKEN")
	fs.StringVar(&cfg.caFile, "ca", "", "PEM root the gateway's certificate chains to (the SOC CA, for an internal name)")
	fs.DurationVar(&cfg.duration, "duration", time.Minute, "how long to keep calling")
	fs.Float64Var(&cfg.rate, "rate", 1, "calls per second")
	fs.Int64Var(&cfg.seed, "seed", 0, "RNG seed; 0 picks one and prints it, so any run can be replayed")
	fs.StringVar(&cfg.only, "only", "", "regexp: call only tools whose namespaced name matches")
	fs.StringVar(&cfg.skip, "skip", "", "regexp: never call tools whose namespaced name matches")
	fs.IntVar(&cfg.unknown, "unknown-pct", 5, "percent of calls aimed at a tool that does not exist, to exercise the refusal path")
	fs.BoolVar(&cfg.planOnly, "plan", false, "print what would be called and exit without calling anything")
	fs.BoolVar(&cfg.confirm, "confirm", false, "required to fire at a non-loopback endpoint")

	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: trafficgen -endpoint URL [flags]\n\n")
		fmt.Fprintf(stderr, "Drives synthetic MCP calls through a running gateway to populate its\n")
		fmt.Fprintf(stderr, "Audit Trail. Calls dispatched to real upstreams run real queries.\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, exitOK, nil
		}
		return nil, exitUsageErr, err
	}
	if cfg.endpoint == "" {
		fs.Usage()
		return nil, exitUsageErr, errors.New("-endpoint is required")
	}
	if _, err := url.Parse(cfg.endpoint); err != nil {
		return nil, exitUsageErr, fmt.Errorf("-endpoint %q: %w", cfg.endpoint, err)
	}
	if cfg.rate <= 0 {
		return nil, exitUsageErr, fmt.Errorf("-rate must be positive, got %v", cfg.rate)
	}
	if cfg.duration <= 0 {
		return nil, exitUsageErr, fmt.Errorf("-duration must be positive, got %v", cfg.duration)
	}
	if cfg.unknown < 0 || cfg.unknown > 100 {
		return nil, exitUsageErr, fmt.Errorf("-unknown-pct must be 0..100, got %d", cfg.unknown)
	}
	return cfg, exitOK, nil
}

// loadToken prefers an explicit file, falls back to $GATTE_TOKEN, and treats
// an empty token as a usage error rather than sending an anonymous request:
// the gateway would refuse it, and "401" is a much worse error message than
// "you did not give me a token".
func loadToken(path string) (string, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read -token-file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("-token-file %s is empty", path)
		}
		return tok, nil
	}
	tok := strings.TrimSpace(os.Getenv("GATTE_TOKEN"))
	if tok == "" {
		return "", errors.New("no token: pass -token-file or set GATTE_TOKEN")
	}
	return tok, nil
}

func buildHTTPClient(caFile, token string) (*http.Client, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read -ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-ca %s: no certificate found in file", caFile)
		}
		base.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	// No -insecure flag, and that is not an oversight. Turning off
	// verification against the one endpoint that brokers every backend
	// credential is not a convenience worth shipping; pass -ca instead.
	return &http.Client{Transport: &bearer{base: base, token: token}, Timeout: 60 * time.Second}, nil
}

type bearer struct {
	base  http.RoundTripper
	token string
}

func (b *bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(req)
}

func selectTools(tools []*mcp.Tool, only, skip string) ([]*mcp.Tool, error) {
	var onlyRe, skipRe *regexp.Regexp
	var err error
	if only != "" {
		if onlyRe, err = regexp.Compile(only); err != nil {
			return nil, fmt.Errorf("-only: %w", err)
		}
	}
	if skip != "" {
		if skipRe, err = regexp.Compile(skip); err != nil {
			return nil, fmt.Errorf("-skip: %w", err)
		}
	}
	var out []*mcp.Tool
	for _, t := range tools {
		if onlyRe != nil && !onlyRe.MatchString(t.Name) {
			continue
		}
		if skipRe != nil && skipRe.MatchString(t.Name) {
			continue
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// guardEndpoint refuses to fire at anything but loopback unless the caller
// said -confirm. The plan is always printed first, so the cost of the guard
// is one flag after you have already read what it was going to do.
func guardEndpoint(endpoint string, confirm bool) error {
	if confirm {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("parse endpoint: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s is not loopback: calls would reach real upstreams and run real queries.\n"+
		"  Re-run with -confirm if that is what you mean, or -plan to see the calls without making them", host)
}

type outcome string

const (
	outcomeOK        outcome = "ok"
	outcomeToolError outcome = "tool-error"
	outcomeRefused   outcome = "refused"
)

type tally struct {
	byOutcome       map[outcome]int
	byTool          map[string]map[outcome]int
	transportErrors int
	started         time.Time
	elapsed         time.Duration
}

func newTally() *tally {
	return &tally{
		byOutcome: map[outcome]int{},
		byTool:    map[string]map[outcome]int{},
		started:   time.Now(),
	}
}

func (t *tally) record(tool string, o outcome) {
	t.byOutcome[o]++
	if t.byTool[tool] == nil {
		t.byTool[tool] = map[outcome]int{}
	}
	t.byTool[tool][o]++
}

// drive is the loop. It ticks at the requested rate and stops at the first of
// -duration elapsing or the context being cancelled, so a Ctrl-C still prints
// a summary rather than losing the run.
func drive(ctx context.Context, sess *mcp.ClientSession, tools []*mcp.Tool, cfg *config, rng *rand.Rand, stdout io.Writer) *tally {
	t := newTally()
	interval := time.Duration(float64(time.Second) / cfg.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.After(cfg.duration)

	for {
		select {
		case <-ctx.Done():
			t.elapsed = time.Since(t.started)
			fmt.Fprintf(stdout, "\ninterrupted after %s\n", t.elapsed.Round(time.Millisecond))
			return t
		case <-deadline:
			t.elapsed = time.Since(t.started)
			return t
		case <-ticker.C:
			name, args := nextCall(tools, cfg.unknown, rng)
			o := callOnce(ctx, sess, name, args, t)
			t.record(name, o)
		}
	}
}

// nextCall picks the next (tool, arguments) pair, occasionally inventing a
// tool name that cannot exist so the refusal path gets exercised too. A trail
// containing only successes is a poor corpus for testing the thing that reads
// it.
func nextCall(tools []*mcp.Tool, unknownPct int, rng *rand.Rand) (string, map[string]any) {
	if unknownPct > 0 && rng.Intn(100) < unknownPct {
		base := tools[rng.Intn(len(tools))].Name
		ns := base
		if i := strings.Index(base, "."); i >= 0 {
			ns = base[:i]
		}
		return fmt.Sprintf("%s.tool_that_does_not_exist_%04d", ns, rng.Intn(10000)), map[string]any{}
	}
	tool := tools[rng.Intn(len(tools))]
	return tool.Name, synthArgs(schemaOf(tool), rng)
}

func callOnce(ctx context.Context, sess *mcp.ClientSession, name string, args map[string]any, t *tally) outcome {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	res, err := sess.CallTool(callCtx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		// A JSON-RPC error is the gateway refusing: unknown tool, not
		// granted to this role, still quarantined. That is a recorded
		// audit outcome and a successful exercise of the refusal path,
		// not a failure of this tool -- so it is not counted as a
		// transport error and does not change the exit code.
		if isTransportFailure(err) {
			t.transportErrors++
		}
		return outcomeRefused
	}
	if res.IsError {
		return outcomeToolError
	}
	return outcomeOK
}

// isTransportFailure distinguishes "the gateway answered, and the answer was
// no" from "the gateway did not answer". Only the second is this tool's
// problem, and only the second should colour the exit code.
func isTransportFailure(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var jsonrpc interface{ Code() int64 }
	if errors.As(err, &jsonrpc) {
		return false
	}
	msg := err.Error()
	for _, s := range []string{"connection refused", "EOF", "no such host", "tls:", "x509:", "401", "403"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// schemaOf recovers a typed schema from Tool.InputSchema, which arrives off
// the wire as `any`. A tool whose schema will not decode still gets called --
// with no arguments, which is the honest thing to send when the declaration
// is unreadable, and which the gateway will reject or accept on its own terms.
func schemaOf(t *mcp.Tool) *jsonschema.Schema {
	if t.InputSchema == nil {
		return nil
	}
	raw, err := json.Marshal(t.InputSchema)
	if err != nil {
		return nil
	}
	var s jsonschema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return &s
}

func synthArgs(s *jsonschema.Schema, rng *rand.Rand) map[string]any {
	out := map[string]any{}
	if s == nil || len(s.Properties) == 0 {
		return out
	}
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names) // deterministic given a seed
	for _, n := range names {
		// Every required property, and optional ones about half the
		// time -- so repeated runs cover both the minimal call and the
		// fully-populated one.
		if !required[n] && rng.Intn(2) == 0 {
			continue
		}
		if v, ok := synthValue(s.Properties[n], n, rng, 0); ok {
			out[n] = v
		}
	}
	return out
}

const maxSynthDepth = 4

func synthValue(s *jsonschema.Schema, name string, rng *rand.Rand, depth int) (any, bool) {
	if s == nil || depth > maxSynthDepth {
		return nil, false
	}
	// A declared constant or default beats anything invented: the author
	// said what belongs here.
	if s.Const != nil {
		return *s.Const, true
	}
	if len(s.Default) > 0 {
		var v any
		if json.Unmarshal(s.Default, &v) == nil {
			return v, true
		}
	}
	if len(s.Enum) > 0 {
		return s.Enum[rng.Intn(len(s.Enum))], true
	}

	typ := s.Type
	if typ == "" && len(s.Types) > 0 {
		typ = s.Types[0]
	}
	switch typ {
	case "string":
		return synthString(s, name, rng), true
	case "integer":
		return int64(boundedNumber(s, rng)), true
	case "number":
		return boundedNumber(s, rng), true
	case "boolean":
		return rng.Intn(2) == 0, true
	case "array":
		item, ok := synthValue(s.Items, name, rng, depth+1)
		if !ok {
			return []any{}, true
		}
		return []any{item}, true
	case "object":
		nested := map[string]any{}
		for n, p := range s.Properties {
			if v, ok := synthValue(p, n, rng, depth+1); ok {
				nested[n] = v
			}
		}
		return nested, true
	default:
		// No type declared. A string is the safest guess and the most
		// common reality.
		return synthString(s, name, rng), true
	}
}

// synthString guesses from the property name, because a tool called with
// `ip: "sample-value"` exercises an argument parser and nothing else, while
// `ip: "192.0.2.7"` exercises the actual lookup path the audit record is
// supposed to be evidence of.
//
// Every value below is from a range reserved for documentation: RFC 5737 for
// IPv4, RFC 3849 for IPv6, example.com for names. This generator must never
// emit an address that belongs to someone.
func synthString(s *jsonschema.Schema, name string, rng *rand.Rand) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "ipv6"):
		return fmt.Sprintf("2001:db8::%x", rng.Intn(0xffff))
	case n == "ip" || strings.HasSuffix(n, "_ip") || strings.Contains(n, "address"):
		return fmt.Sprintf("192.0.2.%d", rng.Intn(254)+1)
	case strings.Contains(n, "domain") || strings.Contains(n, "host") || strings.Contains(n, "fqdn"):
		return fmt.Sprintf("host%d.example.com", rng.Intn(500))
	case strings.Contains(n, "url"):
		return fmt.Sprintf("https://host%d.example.com/path", rng.Intn(500))
	case strings.Contains(n, "hash") || strings.Contains(n, "sha") || strings.Contains(n, "md5"):
		return fmt.Sprintf("%064x", rng.Int63())
	case strings.Contains(n, "email"):
		return fmt.Sprintf("user%d@example.com", rng.Intn(500))
	case strings.Contains(n, "query") || strings.Contains(n, "search") || strings.Contains(n, "keyword"):
		return "*"
	case strings.Contains(n, "index"):
		return "*"
	case strings.Contains(n, "id"):
		return fmt.Sprintf("%d", rng.Intn(1000)+1)
	case strings.Contains(n, "range") || strings.Contains(n, "window") || strings.Contains(n, "relative"):
		return "3600"
	case strings.Contains(n, "user") || strings.Contains(n, "account"):
		return fmt.Sprintf("analyst%d", rng.Intn(20)+1)
	}
	// Respect a declared minimum length so the value is not rejected before
	// it reaches anything interesting.
	v := fmt.Sprintf("trafficgen-%04d", rng.Intn(10000))
	if s != nil && s.MinLength != nil && len(v) < *s.MinLength {
		v += strings.Repeat("x", *s.MinLength-len(v))
	}
	return v
}

func boundedNumber(s *jsonschema.Schema, rng *rand.Rand) float64 {
	lo, hi := 1.0, 100.0
	if s != nil {
		if s.Minimum != nil {
			lo = *s.Minimum
		}
		if s.Maximum != nil {
			hi = *s.Maximum
		}
	}
	if hi < lo {
		hi = lo
	}
	if hi == lo {
		return lo
	}
	return lo + rng.Float64()*(hi-lo)
}

func printPlan(w io.Writer, cfg *config, served, callable []*mcp.Tool) {
	fmt.Fprintf(w, "endpoint   %s\n", cfg.endpoint)
	fmt.Fprintf(w, "served     %d tool(s) visible to this token's role\n", len(served))
	fmt.Fprintf(w, "callable   %d after -only/-skip\n", len(callable))
	if !cfg.planOnly {
		est := int(cfg.rate * cfg.duration.Seconds())
		fmt.Fprintf(w, "plan       %s at %.3g call/s, about %d calls, %d%% aimed at a non-existent tool\n",
			cfg.duration, cfg.rate, est, cfg.unknown)
	}
	fmt.Fprintf(w, "\ntools to be called:\n")
	for _, t := range callable {
		fmt.Fprintf(w, "  %s\n", t.Name)
	}
}

func printSummary(w io.Writer, t *tally) {
	fmt.Fprintf(w, "\nran %s\n\n", t.elapsed.Round(time.Millisecond))

	total := 0
	for _, n := range t.byOutcome {
		total += n
	}
	fmt.Fprintf(w, "  %-12s %s\n", "outcome", "calls")
	for _, o := range []outcome{outcomeOK, outcomeToolError, outcomeRefused} {
		fmt.Fprintf(w, "  %-12s %d\n", o, t.byOutcome[o])
	}
	fmt.Fprintf(w, "  %-12s %d\n", "total", total)

	if t.transportErrors > 0 {
		fmt.Fprintf(w, "\n  %d call(s) failed at the transport, not at the gateway's decision.\n", t.transportErrors)
		fmt.Fprintf(w, "  Those are NOT audit records: a call the gateway never saw was never audited.\n")
	}

	fmt.Fprintf(w, "\nEach call above that the gateway decided on is one audit record. Verify the\n")
	fmt.Fprintf(w, "chain on the host with:  mcp-gateway audit -verify\n")
}
