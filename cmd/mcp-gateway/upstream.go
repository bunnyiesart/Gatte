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
  mcp-gateway upstream register [-config FILE] -name NAME -transport stdio
                                -command CMD [-arg ARG ...]
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
	if code, ok := opParse(fs, args, stdout, stderr, upstreamUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, upstreamUsage) {
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
		state, err := entrySignatureState(e, entry)
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
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
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
		// signature the gateway will not accept is positive evidence that
		// something is wrong (ADR-0006 item 4). The two must not read alike
		// in a table an operator skims.
		//
		// Since ADR-0010 there are two ways to land here, and they call for
		// completely different actions, so the message names both rather
		// than asserting the one it cannot distinguish from the outside.
		// Blaming "the entry changed" when the real cause is a key missing
		// from trusted_keys sends the operator hunting for a tampering that
		// did not happen -- and, worse, teaches them that this warning is
		// usually noise.
		fmt.Fprintf(e.stdout, "\nWARNING: the gateway will NOT serve %d %s a stored signature it does\nnot accept: %s\nEither the entry changed after it was signed, or it was signed by a key that\nis not in signer.trusted_keys. Neither has a benign reading on its own:\nfind out which it is -- and what changed, or whose key that is -- before\nre-signing.\n",
			len(invalid), opPlural(len(invalid), "entry with", "entries with"),
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
	transport := fs.String("transport", string(registry.TransportStdio), "\"stdio\" (spawn a process). \"http\" is recognised but has no dialer in this build and is refused")
	command := fs.String("command", "", "command to spawn, for -transport stdio")
	url := fs.String("url", "", "endpoint URL, for -transport http. Kept for when an http dialer exists; registering http is refused until then")
	var argv opStringList
	fs.Var(&argv, "arg", "argument for the spawned command; repeat, in order")
	var envs opStringList
	fs.Var(&envs, "env", "NAME of an environment variable the upstream needs; repeat. Names only, never values")
	if code, ok := opParse(fs, args, stdout, stderr, upstreamUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, upstreamUsage) {
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
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}

	// Registering deliberately does not sign: signing needs the private
	// key, and an operator should know exactly when that key is used. But
	// an entry the gateway will refuse (or warn about) is a confusing
	// thing to have created silently, so say it here rather than let it be
	// discovered at the next restart.
	//
	// What this used to do was print "NOT SIGNED" categorically, without
	// ever opening the signature store -- an assertion about a table it
	// never read. Signatures are keyed by *name*, not by entry, so a name
	// that has been used before can still carry one: deregister removes it,
	// but a hand-edited database, a restore from backup, or a crash between
	// deregister's two deletes does not. In that state the console said
	// "NOT SIGNED ... will NOT be served" and `upstream list`, one command
	// later, said SIGNED: yes. Both cannot be true, and the one that was
	// wrong is the one an operator reads at the moment they decide whether
	// there is anything left to do (GAB-25).
	//
	// entrySignatureState is the same function `upstream list` uses, and
	// therefore the same answer the gateway will reach at boot.
	state, err := entrySignatureState(e, entry)
	if err != nil {
		// The entry is registered; only the reading of the signature store
		// failed. Saying nothing about signing would be the same silence
		// this block exists to break, and guessing would be worse than the
		// bug being fixed here.
		fmt.Fprintf(e.stderr, "\nWARNING: %q was registered, but whether it is signed could not be determined: %v\nDo not assume either way -- find out before relying on this entry:\n\n    mcp-gateway upstream list\n", entry.Name, err)
		return exitProblem
	}

	switch state {
	case sigValid:
		// The loud case, and the reason this is exitProblem rather than a
		// footnote. A signature that verifies an entry created seconds ago
		// was not made by anybody reviewing *this* entry -- it was made
		// for a previous occupant of the name, and it matches because the
		// new entry runs the same command with the same arguments and the
		// same env var names. That is exactly the transplant including
		// Name in the canonical form (ADR-0006 item 3) exists to prevent,
		// handed over for free by the name being reused.
		//
		// It is not automatically an attack -- re-registering an entry you
		// just removed by mistake lands here too -- but it means the
		// gateway will serve this entry, immediately, on the strength of a
		// review nobody performed today.
		fmt.Fprintf(e.stdout, `
WARNING: this entry is ALREADY SIGNED, and nobody signed it just now.

A signature is stored under the name %q and it VERIFIES the entry that was
just created -- so the gateway will serve it from the next restart, with no
further action. Registering did not do that: the signature was already
there, left by a previous entry of the same name, and it matches because
this entry runs the same command with the same arguments and env var names.

That means what the gateway will trust here was vetted by whoever signed
that earlier entry, and nobody reviewed the one you just registered. If
that is not what you intended, remove it -- deregistering also removes the
stored signature:

    mcp-gateway upstream deregister %s

If it is what you intended, sign it yourself so the signature belongs to
this entry and to you:

    mcp-gateway sign %s

Either way, check what is actually stored:

    mcp-gateway upstream list
`, entry.Name, entry.Name, entry.Name)
		return exitProblem

	case sigInvalid:
		// A stored signature that does not verify is refused no matter
		// what require_signed says (ADR-0006 item 4), so the require_signed
		// sentence below would be misleading here: this entry is not
		// servable either way.
		fmt.Fprintf(e.stdout, "\nWARNING: a signature is already stored under the name %q and it is INVALID for\nthe entry just registered -- it does not verify it, or it was made by a key\nthat is not in signer.trusted_keys.\n\nThe gateway refuses an entry with a signature it does not accept regardless of\nsigner.require_signed, so this entry will NOT be served. Left over from an\nearlier entry of this name, most likely. Signing replaces it:\n\n    mcp-gateway sign %s\n",
			entry.Name, entry.Name)
		return exitProblem
	}

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
	if code, ok := opParse(fs, args, stdout, stderr, upstreamUsage); !ok {
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

// runUpstreamDeregister removes everything this gateway holds under one
// upstream name: the registry row, the stored signature, and the quarantine
// state. All three are keyed by name, which is why all three are this
// command's job.
//
// A missing registry row does not stop the other two, and that is GAB-25(b).
// This used to return on registry.ErrNotFound before reaching either
// cleanup -- so in exactly the state the warnings below describe (row gone,
// signature and approvals still there, both keyed by a name anyone may
// register next), the remedy those warnings prescribe did nothing and said
// "no such upstream". Getting that answer while stale approvals sit in the
// database is the worst of both: nothing was cleaned, and the operator was
// told there was nothing to clean.
func runUpstreamDeregister(e *opEnv, name string) int {
	registryHadIt := true
	switch err := e.upstreams().Deregister(e.ctx(), name); {
	case errors.Is(err, registry.ErrNotFound):
		registryHadIt = false
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}

	if registryHadIt {
		fmt.Fprintf(e.stdout, "Deregistered %q.\n", name)
	} else {
		// Said first, and on stderr, because it is what the operator asked
		// about and is probably a typo. The command keeps going anyway:
		// whether a row exists says nothing about whether the state keyed
		// by the same name does.
		fmt.Fprintf(e.stderr, "no upstream named %q is registered.\n\nList what is:\n\n    mcp-gateway upstream list\n", name)
		fmt.Fprintf(e.stdout, "\nChecking anyway for state left behind under that name -- a signature and\nany approvals are keyed by name, not by the entry, so they can outlive it.\n")
	}

	// The signature is keyed by entry name and would outlive the entry.
	// Left behind, it would authenticate a *future* entry registered under
	// the same name with the same command -- exactly the transplant that
	// including Name in the canonical form (ADR-0006 item 3) exists to
	// prevent, handed over for free by a name being reused. Removing it is
	// part of deregistering, not a separate chore to remember.
	//
	// cleaned counts what was actually removed here, so that the closing
	// message for a name with no registry row can say which of the two it
	// is: an operator's typo, or a database that was carrying state for an
	// entry that no longer exists.
	cleaned := 0
	switch err := e.signatures().Delete(e.ctx(), name); {
	case errors.Is(err, signer.ErrNotFound):
		fmt.Fprintf(e.stdout, "There was no stored signature under this name.\n")
	case err != nil:
		fmt.Fprintf(e.stderr, "\nWARNING: the stored signature under %q was NOT removed: %v\nA signature left behind would authenticate a future entry registered under\nthe same name. Remove it before reusing %q.\n", name, err, name)
		return exitProblem
	default:
		cleaned++
		fmt.Fprintf(e.stdout, "Its stored signature was removed too, so the name cannot be reused by an\nentry nobody signed.\n")
	}

	// Same argument as the signature, one component over (ADR-0013 item 2).
	// Quarantine state is keyed by upstream *name*, so an approval left
	// behind here does not merely go stale -- it vouches for whatever is
	// registered under that name next. This was reproduced on the live
	// deployment: an upstream removed and re-registered with a different
	// command, different credentials and a new signature had all three of
	// its tools still approved and servable the moment it came up, because
	// the quarantine never saw a new upstream at all.
	//
	// The fingerprint cannot cover this. A replacement advertising
	// byte-identical definitions -- which is exactly what swapping a
	// backend's binary would arrange, the tool list being the part an
	// attacker controls -- hashes to the approved baseline, because it *is*
	// the approved baseline. Only removing the state closes it.
	//
	// Not fatal on failure, and reported the same way the signature is: the
	// entry is already gone, and leaving the operator believing otherwise
	// would be worse than an exit code.
	switch n, err := e.tools().Forget(e.ctx(), name); {
	case err != nil:
		fmt.Fprintf(e.stderr, "\nWARNING: the quarantine state under %q was NOT removed: %v\nApprovals left behind are keyed by name, so anything registered under %q\nnext would be served under the approvals a human gave to the entry this\nstate belonged to. Clear them before reusing the name.\n", name, err, name)
		return exitProblem
	case n == 0:
		fmt.Fprintf(e.stdout, "There were no observed tools under this name, so there was no quarantine\nstate to remove.\n")
	default:
		cleaned += n
		fmt.Fprintf(e.stdout, "%d quarantine %s removed with it, so a future upstream registered under\nthis name starts from pending and has to be approved on its own -- an\nidentical-looking replacement does not inherit the review this one had.\n",
			n, opPlural(n, "entry was", "entries were"))
	}

	if registryHadIt {
		return exitOK
	}
	// exitProblem either way: a name with no registry row is either a typo
	// or a database that was still vouching for an entry nobody can see.
	// Both are things the operator asked about and did not get.
	if cleaned > 0 {
		fmt.Fprintf(e.stdout, "\nNothing was registered under %q, but state keyed by that name was, and it\nhas now been removed. Until this ran, the next entry registered under %q\nwould have inherited it.\n", name, name)
	} else {
		// Worth one line rather than silence: "no such upstream" on its own
		// leaves open whether anything is still stored under the name, and
		// that question is the whole reason this command keeps going.
		fmt.Fprintf(e.stdout, "\nSo nothing was left over either: the name %q is clean and safe to reuse.\n", name)
	}
	return exitProblem
}
