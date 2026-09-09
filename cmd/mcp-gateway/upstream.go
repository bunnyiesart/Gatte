// Operator Console -- the "upstream" subcommand: the Upstream Registry's
// operator surface.

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// cmdUpstream implements "mcp-gateway upstream": list, register and
// deregister backend MCP servers.
func cmdUpstream(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		upstreamUsage(stderr)
		return exitCannotRun
	}

	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return upstreamList(rest, stdout, stderr)
	case "register":
		return upstreamRegister(rest, stdout, stderr)
	case "deregister":
		return upstreamDeregister(rest, stdout, stderr)
	case "-h", "--help", "help":
		upstreamUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"upstream\" subcommand %q\n\n", sub)
		upstreamUsage(stderr)
		return exitCannotRun
	}
}

func upstreamUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway upstream list [-config FILE] [-json]
  mcp-gateway upstream register [-config FILE] -name NAME -transport stdio|http
                                [-command CMD] [-arg ARG ...] [-url URL]
                                [-env VARNAME ...]
  mcp-gateway upstream deregister [-config FILE] NAME

Registering does not sign. Run "mcp-gateway sign NAME" afterwards, or the
gateway will not trust the entry.

-env takes environment variable NAMES only, never values: the Credential
Vault resolves a name to a value in memory at spawn time, and the registry
has no field capable of holding a secret.

Exit codes: 0 ok, 1 ran and found a problem, 2 could not run.
`)
}

// upstreamList prints every registered entry, with its signature state.
func upstreamList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("upstream list", stderr)
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	fs.Usage = func() { upstreamUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if !opNoArgs(fs, stderr) {
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runUpstreamList(e, *asJSON)
	})
}

// upstreamJSON is the -json shape of one registry entry. It carries env
// var names, like the table does, and nothing else that could ever be a
// secret -- there is no such field to carry.
type upstreamJSON struct {
	Name        string    `json:"name"`
	Transport   string    `json:"transport"`
	Command     string    `json:"command,omitempty"`
	Args        []string  `json:"args,omitempty"`
	URL         string    `json:"url,omitempty"`
	EnvVarNames []string  `json:"env_var_names"`
	Signature   string    `json:"signature"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func runUpstreamList(e *opEnv, asJSON bool) int {
	entries, err := e.upstreams().List(e.ctx())
	if err != nil {
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}

	// Signature state is resolved once, here, and reused by both output
	// formats so the table and the JSON can never disagree about whether
	// the gateway will trust an entry.
	states := make([]signatureState, len(entries))
	for i, entry := range entries {
		state, err := entrySignatureState(e.ctx(), e.signatures(), entry)
		if err != nil {
			fmt.Fprintf(e.stderr, "signatures: %v\n", err)
			return exitCannotRun
		}
		states[i] = state
	}

	if asJSON {
		out := make([]upstreamJSON, 0, len(entries))
		for i, entry := range entries {
			out = append(out, upstreamJSON{
				Name:        entry.Name,
				Transport:   string(entry.Transport),
				Command:     entry.Command,
				Args:        entry.Args,
				URL:         entry.URL,
				EnvVarNames: envVarNamesOrEmpty(entry),
				Signature:   string(states[i]),
				CreatedAt:   entry.CreatedAt,
				UpdatedAt:   entry.UpdatedAt,
			})
		}
		if err := opJSON(e.stdout, out); err != nil {
			fmt.Fprintf(e.stderr, "writing json: %v\n", err)
			return exitCannotRun
		}
		if len(entries) == 0 {
			return exitProblem
		}
		return exitOK
	}

	if len(entries) == 0 {
		fmt.Fprintf(e.stdout, "No upstream servers are registered.\n\nRegister one with:\n\n    mcp-gateway upstream register -name NAME -transport stdio -command CMD\n")
		return exitProblem
	}

	tw := opTable(e.stdout)
	fmt.Fprintln(tw, "NAME\tTRANSPORT\tCOMMAND / URL\tENV VAR NAMES\tSIGNED")
	for i, entry := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			entry.Name,
			entry.Transport,
			opCommandLine(entry),
			opDash(strings.Join(entry.EnvVarNames, ", ")),
			states[i],
		)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}

	var unsigned, invalid []string
	for i, entry := range entries {
		switch states[i] {
		case sigUnsigned:
			unsigned = append(unsigned, entry.Name)
		case sigInvalid:
			invalid = append(invalid, entry.Name)
		}
	}

	fmt.Fprintf(e.stdout, "\n%d %s. ENV VAR NAMES lists names only; the values live in the\nCredential Vault and are never stored here or printed.\n",
		len(entries), opPlural(len(entries), "entry", "entries"))

	if len(unsigned) > 0 {
		verb := "warns about"
		if e.cfg.Signer.SignaturesRequired() {
			verb = "refuses to serve"
		}
		fmt.Fprintf(e.stdout, "\n%d unsigned %s: %s\nThe gateway %s an unsigned entry (signer.require_signed = %t). Sign with:\n\n    mcp-gateway sign NAME\n",
			len(unsigned), opPlural(len(unsigned), "entry", "entries"),
			strings.Join(unsigned, ", "), verb, e.cfg.Signer.SignaturesRequired())
	}
	if len(invalid) > 0 {
		// An absent signature is the normal state of a new entry; a
		// signature that does not verify is positive evidence that the
		// entry changed after it was signed (ADR-0006 item 4). The two
		// must not read alike in a table an operator skims.
		fmt.Fprintf(e.stdout, "\nWARNING: %d %s a stored signature that does NOT match its current\ndefinition: %s\nThat is evidence of tampering, not a stale signature -- the gateway refuses\nto serve such an entry. Find out what changed before re-signing it.\n",
			len(invalid), opPlural(len(invalid), "entry has", "entries have"),
			strings.Join(invalid, ", "))
	}
	return exitOK
}

// envVarNamesOrEmpty keeps the JSON field an array rather than null, so a
// consumer never has to distinguish "no names" from "field missing".
func envVarNamesOrEmpty(s registry.UpstreamServer) []string {
	if s.EnvVarNames == nil {
		return []string{}
	}
	return s.EnvVarNames
}

// upstreamRegister adds an entry to the registry.
func upstreamRegister(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("upstream register", stderr)
	name := fs.String("name", "", "name of the entry, e.g. \"casemgmt\" (required)")
	transport := fs.String("transport", string(registry.TransportStdio), "\"stdio\" (spawn a process) or \"http\" (call a URL)")
	command := fs.String("command", "", "command to spawn, for -transport stdio")
	url := fs.String("url", "", "endpoint URL, for -transport http")
	var argv opStringList
	fs.Var(&argv, "arg", "argument for the spawned command; repeat, in order")
	var envs opStringList
	fs.Var(&envs, "env", "NAME of an environment variable the upstream needs; repeat. Names only, never values")
	fs.Usage = func() { upstreamUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if !opNoArgs(fs, stderr) {
		return exitCannotRun
	}

	// Checked before registry.Validate so the message can be specific,
	// and -- the reason this exists at all -- so the offending argument is
	// never echoed. If an operator pasted TOKEN=hunter2 here, repeating it
	// in an error message would put the secret in their scrollback, their
	// shell history's neighbourhood, and any terminal recording. Only the
	// part left of "=" is printed.
	for _, raw := range envs {
		if before, _, found := strings.Cut(raw, "="); found {
			fmt.Fprintf(stderr, "-env %q looks like NAME=value (the value is not echoed here).\n\n-env takes the NAME of an environment variable only. The registry never\nstores a secret value: the Credential Vault resolves the name to a value in\nmemory at spawn time (design/adr/0003-security-controls.md).\n", before)
			return exitCannotRun
		}
	}

	entry := registry.UpstreamServer{
		Name:        *name,
		Transport:   registry.Transport(*transport),
		Command:     *command,
		Args:        argv,
		URL:         *url,
		EnvVarNames: envs,
	}
	// Validated here rather than left to the adapter: a malformed entry is
	// bad usage, and reporting it before the database is even opened means
	// the operator sees the rule they broke and nothing else.
	if err := entry.Validate(); err != nil {
		fmt.Fprintf(stderr, "%v\n\n", err)
		upstreamUsage(stderr)
		return exitCannotRun
	}

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runUpstreamRegister(e, entry)
	})
}

func runUpstreamRegister(e *opEnv, entry registry.UpstreamServer) int {
	err := e.upstreams().Register(e.ctx(), entry)
	switch {
	case errors.Is(err, registry.ErrAlreadyExists):
		fmt.Fprintf(e.stderr, "an upstream named %q is already registered.\n\nDeregister it first, or choose another name:\n\n    mcp-gateway upstream deregister %s\n", entry.Name, entry.Name)
		return exitProblem
	case errors.Is(err, registry.ErrInvalid):
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}

	fmt.Fprintf(e.stdout, "Registered %q.\n\n", entry.Name)
	tw := opTable(e.stdout)
	fmt.Fprintf(tw, "  transport\t%s\n", entry.Transport)
	fmt.Fprintf(tw, "  command / url\t%s\n", opCommandLine(entry))
	fmt.Fprintf(tw, "  env var names\t%s\n", opDash(strings.Join(entry.EnvVarNames, ", ")))
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(e.stderr, "writing table: %v\n", err)
		return exitCannotRun
	}

	// Registering deliberately does not sign: signing needs the private
	// key, and an operator should know exactly when that key is used. But
	// an entry the gateway will refuse (or warn about) is a confusing
	// thing to have created silently, so say it here rather than let it be
	// discovered at the next restart.
	verb := "warn about"
	consequence := "signer.require_signed is false today, so the entry will still be served"
	if e.cfg.Signer.SignaturesRequired() {
		verb = "refuse to serve"
		consequence = "signer.require_signed is true, so the entry will NOT be served until it is signed"
	}
	fmt.Fprintf(e.stdout, "\nThis entry is NOT SIGNED. Registering never signs -- signing is a separate,\ndeliberate use of the signing key. The gateway will %s an unsigned entry:\n%s.\n\nSign it now:\n\n    mcp-gateway sign %s\n",
		verb, consequence, entry.Name)
	return exitOK
}

// upstreamDeregister removes an entry from the registry.
func upstreamDeregister(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("upstream deregister", stderr)
	fs.Usage = func() { upstreamUsage(stderr) }
	if code, ok := opParse(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "deregister takes exactly one argument: the name of the entry to remove\n\n")
		upstreamUsage(stderr)
		return exitCannotRun
	}
	name := fs.Arg(0)

	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runUpstreamDeregister(e, name)
	})
}

func runUpstreamDeregister(e *opEnv, name string) int {
	err := e.upstreams().Deregister(e.ctx(), name)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		fmt.Fprintf(e.stderr, "no upstream named %q is registered.\n\nList what is:\n\n    mcp-gateway upstream list\n", name)
		return exitProblem
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}
	fmt.Fprintf(e.stdout, "Deregistered %q.\n", name)

	// The signature is keyed by entry name and would outlive the entry.
	// Left behind, it would authenticate a *future* entry registered under
	// the same name with the same command -- exactly the transplant that
	// including Name in the canonical form (ADR-0006 item 3) exists to
	// prevent, handed over for free by a name being reused. Removing it is
	// part of deregistering, not a separate chore to remember.
	switch err := e.signatures().Delete(e.ctx(), name); {
	case errors.Is(err, signer.ErrNotFound):
		fmt.Fprintf(e.stdout, "It had no stored signature.\n")
	case err != nil:
		fmt.Fprintf(e.stderr, "\nWARNING: the entry was removed but its stored signature was not: %v\nA signature left behind would authenticate a future entry registered under\nthe same name. Remove it before reusing %q.\n", err, name)
		return exitProblem
	default:
		fmt.Fprintf(e.stdout, "Its stored signature was removed too, so the name cannot be reused by an\nentry nobody signed.\n")
	}
	return exitOK
}
