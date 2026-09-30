// Operator Console -- "reload" and "upstream redial" (design/adr/0044):
// ask the running serve, through a row in the database and a SIGHUP, to
// apply the reloadable part of the configuration or to drop and re-dial
// one backend, and print what it answered.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// defaultCLIServeWait is how long the CLI waits for serve: longer than
// the API, because a redial waits for one whole round (a dial and a
// listing), and nothing here has a request deadline.
const defaultCLIServeWait = 2 * time.Minute

func reloadUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway reload [-config FILE] [-wait 2m] [-json]
  mcp-gateway upstream redial [-config FILE] [-wait 2m] [-json] NAME

reload asks the running serve to re-read ITS configuration file and apply
[[role]], [group_to_role] and [quota] from the next call on, without a
restart. The whole file is loaded and validated first; if anything in it is
wrong, or the new [quota] disagrees with the registry, nothing changes and
the refusal is printed and recorded. It prints who gains and who loses which
tool, and every key that differs from the file serve started with and is NOT
applied until a restart: listen, [oidc], [signer] (trusted_keys included),
[vault], [audit], [telemetry], [response], [oci], [upstreams] and the rest.
Clients that already listed their tools keep that list until they reconnect
(Claude Code: /mcp); a call to a tool a role lost is refused at once.
SIGHUP to serve (systemctl reload) does the same, recorded as the signal's.

upstream redial drops serve's connection to one backend and dials it again,
with the vault as it is now: a rotated credential or a restarted container
takes effect for that backend alone. Its calls are answered as reconnecting
until the new process has been listed.

Both run as the gateway's service account (they signal serve and write its
database) and are recorded in the audit trail as operator actions, by serve:
(config reload) and (upstream redial).

-wait is how long to wait for serve's answer; serve takes the request later
if it is busy, and "pending" is printed with the request's id.

Exit codes: 0 applied, 1 refused or still pending, 2 could not run (serve is
not running on this database, or the file does not load here).
`)
}

// cmdReload implements "mcp-gateway reload".
func cmdReload(args []string, stdout, stderr io.Writer) int {
	return serveControlCommand("reload", args, stdout, stderr)
}

// upstreamRedial implements "mcp-gateway upstream redial NAME".
func upstreamRedial(args []string, stdout, stderr io.Writer) int {
	return serveControlCommand("upstream redial", args, stdout, stderr)
}

func serveControlCommand(name string, args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet(name, stderr)
	wait := fs.Duration("wait", defaultCLIServeWait, "how long to wait for serve's answer")
	asJSON := fs.Bool("json", false, "print the answer as JSON")
	positional, code, ok := parseInterspersedWith(fs, args, stdout, stderr, reloadUsage)
	if !ok {
		return code
	}
	redial := name == "upstream redial"
	switch {
	case redial && len(positional) != 1:
		fmt.Fprintf(stderr, "%s takes exactly one argument: the backend's name\n\n", name)
		reloadUsage(stderr)
		return exitCannotRun
	case !redial && len(positional) != 0:
		fmt.Fprintf(stderr, "unexpected argument %q\n\n", positional[0])
		reloadUsage(stderr)
		return exitCannotRun
	case *wait <= 0:
		fmt.Fprint(stderr, "-wait must be positive\n")
		return exitCannotRun
	}
	actor, err := cliActor()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		cfg := e.cfg
		svc, err := newAdminService(e.db, func() (*config.Config, error) { return cfg, nil }, e.stderr, e.configPath, newLogger(io.Discard),
			func(d *admin.Deps) { d.ServeWait = *wait })
		if err != nil {
			fmt.Fprintf(e.stderr, "%v\n", err)
			return exitCannotRun
		}
		ctx, cancel := context.WithTimeout(e.ctx(), *wait+10*time.Second)
		defer cancel()
		var res adminapi.ServeRequest
		if redial {
			res, err = svc.Redial(ctx, actor, adminapi.RedialRequest{Upstream: positional[0]})
		} else {
			res, err = svc.Reload(ctx, actor)
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "%s: %s\n", name, cliErrText(err))
			var ae *adminapi.Error
			if errors.As(err, &ae) && ae.Code == adminapi.CodeNotFound {
				return exitProblem
			}
			return exitCannotRun
		}
		if *asJSON {
			if err := opJSON(e.stdout, res); err != nil {
				fmt.Fprintf(e.stderr, "writing json: %v\n", err)
				return exitCannotRun
			}
		} else {
			printServeRequest(e.stdout, res)
		}
		switch {
		case res.State != adminapi.ServeStateDone:
			return exitProblem
		case res.Outcome != adminapi.ServeOutcomeApplied:
			return exitProblem
		}
		return exitOK
	})
}

// parseInterspersedWith is parseInterspersed with this command's usage.
func parseInterspersedWith(fs *flag.FlagSet, args []string, stdout, stderr io.Writer, usage func(io.Writer)) ([]string, int, bool) {
	var positional []string
	for {
		if code, ok := opParse(fs, args, stdout, stderr, usage); !ok {
			return nil, code, false
		}
		if fs.NArg() == 0 {
			return positional, exitOK, true
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// printServeRequest renders serve's answer for a person.
func printServeRequest(w io.Writer, r adminapi.ServeRequest) {
	what := "reload"
	if r.Kind == adminapi.ServeKindRedial {
		what = "redial of " + r.Upstream
	}
	switch {
	case r.State != adminapi.ServeStateDone:
		fmt.Fprintf(w, "Request %d (%s) is PENDING: serve was rung and has not answered yet.\n", r.ID, what)
	case r.Outcome == adminapi.ServeOutcomeApplied:
		fmt.Fprintf(w, "Request %d (%s): applied.\n", r.ID, what)
	default:
		fmt.Fprintf(w, "Request %d (%s): REFUSED (%s).\n", r.ID, what, r.Refusal)
	}
	if c := r.Reload; c != nil {
		for _, ch := range c.Roles {
			label := ""
			switch {
			case ch.Added:
				label = " (new role)"
			case ch.Removed:
				label = " (role removed)"
			}
			fmt.Fprintf(w, "  role %s%s\n", oneLine(ch.Role), label)
			for _, t := range ch.Gained {
				fmt.Fprintf(w, "    + %s\n", oneLine(t))
			}
			for _, t := range ch.Lost {
				fmt.Fprintf(w, "    - %s\n", oneLine(t))
			}
			if !ch.Added && !ch.Removed {
				for _, g := range ch.GrantsAdded {
					fmt.Fprintf(w, "    grant + %s\n", oneLine(g))
				}
				for _, g := range ch.GrantsRemoved {
					fmt.Fprintf(w, "    grant - %s\n", oneLine(g))
				}
			}
		}
		for _, g := range c.Groups {
			fmt.Fprintf(w, "  group %s: %s -> %s\n", oneLine(g.Group), opDash(oneLine(g.From)), opDash(oneLine(g.To)))
		}
		for _, q := range c.Quota {
			fmt.Fprintf(w, "  quota %s %s", oneLine(q.Account), q.Change)
			if q.To != "" {
				fmt.Fprintf(w, ": %s", oneLine(q.To))
			}
			fmt.Fprintln(w)
		}
		if c.FreeToolsChanged {
			fmt.Fprintln(w, "  quota.free_tools changed")
		}
		if len(c.NotReloaded) > 0 {
			fmt.Fprintf(w, "  NOT applied until a restart: %s\n", strings.Join(c.NotReloaded, ", "))
		}
	}
	if o := r.Redial; o != nil {
		fmt.Fprintf(w, "  was connected: %t; live now: %t", o.WasConnected, o.Live)
		if o.Cause != "" {
			fmt.Fprintf(w, " (%s)", o.Cause)
		}
		fmt.Fprintln(w)
	}
	for _, m := range r.Messages {
		fmt.Fprintln(w, oneLine(m))
	}
	for _, wn := range r.Warnings {
		if wn.Code == adminapi.WarnAuditWriteFailed {
			fmt.Fprintf(w, "WARNING: %s\n", oneLine(wn.Message))
		}
	}
	if r.Recorded && r.Audit != nil {
		fmt.Fprintf(w, "Recorded in the audit trail as %s by %s.\n", r.Audit.Tool, r.Audit.Identity)
	}
}
