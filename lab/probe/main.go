// Command probe is the lab's leak-detection harness (lab/README.md). It
// exists to answer the one question this whole project is built around:
// when a secret is injected into an upstream MCP server's process
// environment, does that secret ever cross back over the wire to the
// client?
//
// The probe spawns an MCP server over stdio with a freshly-generated,
// unpredictable secret in its environment (as MOCK_SECRET and
// MOCK_EXPECT -- simulating a credential injector that got it right),
// calls a named "<name>_credcheck" tool on it, and -- independent of
// whatever that tool reports -- scans every raw byte of the MCP
// protocol traffic that passed between probe and server for the literal
// secret value.
//
// This is deliberately two separate checks, and both must pass:
//
//  1. The structured result: did the server's credcheck tool report that
//     it received the secret we sent it? This proves credential
//     injection into the child process actually worked.
//
//  2. The leak check: did the secret appear anywhere in the raw wire
//     traffic -- request or response, any field, any log line the
//     transport captured? This proves the credential injection
//     mechanism (or the mock server misbehaving) never let the secret
//     itself leak back out, which is the actual security property the
//     gateway this lab tests exists to guarantee. A credcheck tool
//     could theoretically report success while some other bug echoes
//     the secret in an unrelated tool result or log message; the leak
//     check catches that regardless of what the credcheck result says.
//
// A secret that only ever needs to prove its own presence (via a
// fingerprint) and never needs to be reconstructed by anything watching
// the wire is the whole design of mockutil.CredCheckResult; this probe
// is the tool that verifies that design is actually being honored by a
// given server and, transitively, by whatever spawned it.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exit codes, matching this project's tooling convention: 0 means the
// probe ran and found no problem, 1 means the probe ran and found a
// problem (a failed credcheck, a leaked secret, or both), 2 means the
// probe itself could not complete -- bad usage, the command couldn't be
// spawned, the client couldn't connect, or the result couldn't be
// parsed. A 2 means "this test didn't run," not "this test found an
// issue."
const (
	exitOK       = 0
	exitFail     = 1
	exitUsageErr = 2
)

// probeTimeout bounds the whole spawn-connect-call-close exchange so a
// hung or misbehaving mock server can't make the probe hang forever.
const probeTimeout = 30 * time.Second

func main() {
	os.Exit(mainRun(os.Args[1:], os.Stdout, os.Stderr))
}

// mainRun parses probe's own command-line arguments and dispatches to
// run. It is separated from main only so main itself stays a one-liner.
func mainRun(args []string, stdout, stderr io.Writer) int {
	toolName, cmdArgs, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "usage: probe --tool <credcheck-tool-name> -- <command> [args...]\n")
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsageErr
	}
	return run(toolName, cmdArgs, stdout, stderr)
}

// parseArgs splits probe's own arguments from the child command and its
// arguments, which are separated by a literal "--".
//
// The standard flag package's Parse stops at the first non-flag
// argument, which makes it unsuitable here: "--tool" is a flag, but
// everything after "--" must be treated as opaque positional arguments
// for the child command even if some of them look like flags (e.g. a
// child command invoked with its own "--tool" or "-v"). Splitting on a
// literal "--" first, then handing only the probe-owned slice to flag,
// sidesteps that ambiguity entirely and was verified against a real
// invocation (probe --tool foo_credcheck -- some-binary --tool bar)
// before being chosen over relying on flag's own stop-at-first-non-flag
// behavior.
func parseArgs(args []string) (toolName string, cmdArgs []string, err error) {
	sepIdx := -1
	for i, a := range args {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 {
		return "", nil, fmt.Errorf("missing \"--\" separator before the command to spawn")
	}

	probeArgs := args[:sepIdx]
	cmdArgs = args[sepIdx+1:]
	if len(cmdArgs) == 0 {
		return "", nil, fmt.Errorf("no command given after \"--\"")
	}

	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	tool := fs.String("tool", "", "name of the <name>_credcheck tool to call")
	if err := fs.Parse(probeArgs); err != nil {
		return "", nil, err
	}
	if *tool == "" {
		return "", nil, fmt.Errorf("--tool is required")
	}
	if fs.NArg() > 0 {
		return "", nil, fmt.Errorf("unexpected extra argument(s) before \"--\": %v", fs.Args())
	}

	return *tool, cmdArgs, nil
}

// generateSecret returns a fresh, unpredictable test secret: 16 random
// bytes from crypto/rand, hex-encoded. math/rand is deliberately not
// used -- a leak check is only meaningful if the value it looks for
// could not plausibly appear in unrelated output by coincidence.
func generateSecret() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// run is the probe's real logic, factored out of main so it can be
// exercised directly by tests: it spawns cmdArgs[0] with a generated
// secret in its environment, calls toolName on it as an MCP tool over
// stdio, and reports on stdout whether the secret was both received
// correctly by the child and never observed on the wire. It writes
// PASS/FAIL detail to stdout and any error/leak detail to stderr, and
// returns one of exitOK, exitFail, or exitUsageErr.
func run(toolName string, cmdArgs []string, stdout, stderr io.Writer) int {
	if toolName == "" {
		fmt.Fprintln(stderr, "error: tool name is required")
		return exitUsageErr
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(stderr, "error: no command given to spawn")
		return exitUsageErr
	}

	secret, err := generateSecret()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitUsageErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = append(os.Environ(), "MOCK_SECRET="+secret, "MOCK_EXPECT="+secret)
	// The child's stderr is deliberately not wired to the probe's own
	// stderr writer: os/exec copies a non-nil, non-*os.File Stderr in a
	// background goroutine for as long as the child is alive, and that
	// goroutine would then be writing to the same io.Writer this
	// function also writes diagnostics to directly -- a data race. The
	// child's stderr is not part of the MCP wire protocol this probe
	// exists to check anyway, so it is simplest to just discard it
	// (cmd.Stderr == nil connects it to the null device).

	logBuf := &bytes.Buffer{}
	transport := &mcp.LoggingTransport{
		Transport: &mcp.CommandTransport{Command: cmd},
		Writer:    logBuf,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "probe"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: connect: %v\n", err)
		return checkLeakOnly(logBuf, secret, stderr, exitUsageErr)
	}

	callResult, callErr := session.CallTool(ctx, &mcp.CallToolParams{Name: toolName})

	// Close the session -- and so stop its background read loop, which
	// writes into logBuf as messages arrive -- before this function
	// reads logBuf itself. Reading logBuf.Bytes() while that loop might
	// still be running is a data race, not just bad style: the loop
	// keeps reading for as long as the connection is open, whether or
	// not this function is expecting another message.
	// Discarded explicitly: this Close is a synchronisation step, not a
	// flush. Its job is to stop the background reader before logBuf is
	// read, and it has done that whether or not the teardown itself
	// erred -- there is no outcome here that should change what this
	// function reports.
	_ = session.Close()

	// The leak check runs and is reported regardless of what happens
	// above: whether the call succeeded, whether its result parses,
	// whether the credcheck itself passed. It is the single most
	// important thing this tool proves.
	leaked := bytes.Contains(logBuf.Bytes(), []byte(secret))
	if leaked {
		fmt.Fprintln(stderr, "LEAK: the secret appeared in the MCP wire protocol")
	}

	if callErr != nil {
		fmt.Fprintf(stderr, "error: call tool %q: %v\n", toolName, callErr)
		return reportAndExit(stdout, stderr, false, "", leaked, exitUsageErr)
	}
	if len(callResult.Content) == 0 {
		fmt.Fprintf(stderr, "error: tool %q returned no content\n", toolName)
		return reportAndExit(stdout, stderr, false, "", leaked, exitUsageErr)
	}
	textContent, ok := callResult.Content[0].(*mcp.TextContent)
	if !ok {
		fmt.Fprintf(stderr, "error: tool %q returned non-text content (%T)\n", toolName, callResult.Content[0])
		return reportAndExit(stdout, stderr, false, "", leaked, exitUsageErr)
	}

	var result mockutil.CredCheckResult
	if err := json.Unmarshal([]byte(textContent.Text), &result); err != nil {
		fmt.Fprintf(stderr, "error: parse credcheck result: %v\n", err)
		return reportAndExit(stdout, stderr, false, "", leaked, exitUsageErr)
	}

	return reportAndExit(stdout, stderr, result.ReceivedExpectedSecret, result.Fingerprint, leaked, -1)
}

// checkLeakOnly runs the leak check against whatever was captured before
// an early failure (e.g. a failed connect) and returns forcedExit. It
// exists so that even a connect failure still gets the leak check it
// deserves -- some transports may write partial handshake bytes before
// failing.
func checkLeakOnly(logBuf *bytes.Buffer, secret string, stderr io.Writer, forcedExit int) int {
	if bytes.Contains(logBuf.Bytes(), []byte(secret)) {
		fmt.Fprintln(stderr, "LEAK: the secret appeared in the MCP wire protocol")
	}
	return forcedExit
}

// reportAndExit prints the PASS/FAIL summary to stdout and computes the
// exit code.
//
// leaked takes priority over everything else, deliberately: a leak must
// never be reported as exitUsageErr ("this test didn't run"), even when
// it was discovered alongside a call/parse failure (exactly what happens
// against a genuinely misbehaving server -- it may well return malformed
// output *because* it's leaking something it shouldn't). An automated
// caller that treats exitUsageErr as "flaky, ignore or retry" must never
// be able to wave away a real leak that way. This was a real bug caught
// before this file was ever trusted: an earlier version let forcedExit
// override leaked unconditionally, so calling a tool that leaked but
// returned non-CredCheckResult-shaped content (lab/probe/testdata/leakyfixture's
// leaky_tool does exactly this) reported exitUsageErr instead of a
// failure.
//
// Otherwise: if forcedExit is non-negative (a usage-style failure
// occurred and there was no leak), it is returned as-is; failing that,
// the exit code is derived from matched.
func reportAndExit(stdout, stderr io.Writer, matched bool, fingerprint string, leaked bool, forcedExit int) int {
	fmt.Fprintln(stdout, "=== probe result ===")
	if matched {
		fmt.Fprintf(stdout, "tool result: MATCHED (fingerprint %s)\n", fingerprint)
	} else {
		fmt.Fprintf(stdout, "tool result: NOT MATCHED (fingerprint %s)\n", fingerprint)
	}
	if leaked {
		fmt.Fprintln(stdout, "leak check:  LEAKED -- secret observed on the wire")
	} else {
		fmt.Fprintln(stdout, "leak check:  CLEAN")
	}

	if leaked {
		fmt.Fprintln(stdout, "result:      FAIL (secret leaked)")
		return exitFail
	}
	if forcedExit >= 0 {
		fmt.Fprintln(stdout, "result:      FAIL (test did not complete normally)")
		return forcedExit
	}
	if matched {
		fmt.Fprintln(stdout, "result:      PASS")
		return exitOK
	}
	fmt.Fprintln(stdout, "result:      FAIL")
	return exitFail
}
