// Operator Console -- planned maintenance (design/adr/0041 item 6):
// "upstream maintenance on|off NAME" for one backend and "maintenance
// on|off|list" for the whole gateway. Both go through the management
// service the API uses, so the message and until are held to the same
// rules and every change is the same (maintenance on|off) operator row.

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func maintenanceUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway upstream maintenance on  [-config FILE] NAME -message TEXT [-until RFC3339|DURATION|none]
  mcp-gateway upstream maintenance off [-config FILE] NAME
  mcp-gateway upstream maintenance list [-config FILE] [-json]
  mcp-gateway maintenance on   [-config FILE] -message TEXT [-until RFC3339|DURATION|none]
  mcp-gateway maintenance off  [-config FILE]
  mcp-gateway maintenance list [-config FILE] [-json]

A backend in maintenance keeps its tools listed; from the running gateway's
next call on, a call to one of them is answered with your message and is not
sent to the backend. The whole gateway in maintenance is a notice, not a
block: calls are still served, and text results and gatte.status carry it.
No restart is needed either way.

-message is what analysts and their models read: 1 to 200 characters on one
line, no control or hidden characters. -until announces the end, as an
RFC 3339 time (2026-09-29T15:00:00Z) or a duration from now (2h, 90m), at
most 90 days ahead. It is a forecast, not a deadline: the maintenance lasts
until "off". Running "on" again changes the message, and the end when
-until is given, and keeps when the maintenance started: without -until the
end already announced is kept (dropped, with a note, if it has passed), and
-until none takes it back.

Each on and off is recorded in the audit trail as an operator action.

Exit codes: 0 ok (including "already in maintenance with this message"), 1
ran and found a problem ("off" of something not in maintenance, or a change
the trail could not record), 2 could not run.
`)
}

// cmdMaintenance implements "mcp-gateway maintenance": the whole gateway.
func cmdMaintenance(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		maintenanceUsage(stderr)
		return exitCannotRun
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "on", "off":
		return maintenanceChange(adminapi.ScopeGateway, sub, rest, stdout, stderr)
	case "list":
		return maintenanceList(rest, stdout, stderr)
	case "-h", "--help", "help":
		maintenanceUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"maintenance\" subcommand %q\n\n", sub)
		maintenanceUsage(stderr)
		return exitCannotRun
	}
}

// upstreamMaintenance implements "mcp-gateway upstream maintenance".
func upstreamMaintenance(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		maintenanceUsage(stderr)
		return exitCannotRun
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "on", "off":
		return maintenanceChange(adminapi.ScopeUpstream, sub, rest, stdout, stderr)
	case "list":
		return maintenanceList(rest, stdout, stderr)
	case "-h", "--help", "help":
		maintenanceUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown \"upstream maintenance\" subcommand %q\n\n", sub)
		maintenanceUsage(stderr)
		return exitCannotRun
	}
}

// parseInterspersed parses flags before and after the arguments, so that
// "on NAME -message TEXT", the order an operator types, works as well as
// "on -message TEXT NAME". It returns the arguments.
func parseInterspersed(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) ([]string, int, bool) {
	var positional []string
	for {
		if code, ok := opParse(fs, args, stdout, stderr, maintenanceUsage); !ok {
			return nil, code, false
		}
		if fs.NArg() == 0 {
			return positional, exitOK, true
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// untilNone is the -until that takes an announced end back.
const untilNone = "none"

// parseUntil reads -until: an RFC 3339 time, or a duration from now. The
// range (future, at most 90 days) is health.ValidateUntil's. "" and
// "none" are no end; the caller tells them apart.
func parseUntil(raw string, now time.Time) (time.Time, error) {
	if raw == "" || raw == untilNone {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC(), nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return time.Time{}, fmt.Errorf("-until %q is neither an RFC 3339 time (2026-09-29T15:00:00Z) nor a positive duration (2h, 90m)", raw)
	}
	return now.Add(d).UTC(), nil
}

func maintenanceChange(scope, sub string, args []string, stdout, stderr io.Writer) int {
	name := "maintenance " + sub
	if scope == adminapi.ScopeUpstream {
		name = "upstream " + name
	}
	fs, configPath := opFlagSet(name, stderr)
	var message, until *string
	if sub == "on" {
		message = fs.String("message", "", "what analysts and their models read (required)")
		until = fs.String("until", "", "announced end: RFC 3339 time or a duration from now")
	}
	positional, code, ok := parseInterspersed(fs, args, stdout, stderr)
	if !ok {
		return code
	}
	var upstream string
	switch {
	case scope == adminapi.ScopeUpstream && len(positional) != 1:
		fmt.Fprintf(stderr, "%s takes exactly one argument: the backend's name\n\n", name)
		maintenanceUsage(stderr)
		return exitCannotRun
	case scope == adminapi.ScopeUpstream:
		upstream = positional[0]
	case len(positional) != 0:
		fmt.Fprintf(stderr, "unexpected argument %q: %s is for the whole gateway; for one backend use \"upstream maintenance\"\n\n", positional[0], name)
		maintenanceUsage(stderr)
		return exitCannotRun
	}

	// Validated before anything is opened, as the service will, so a typo
	// costs nothing and is never recorded.
	req := adminapi.MaintenanceRequest{Scope: scope, Upstream: upstream}
	if sub == "on" {
		msg, err := health.ValidateMessage(*message)
		if err != nil {
			fmt.Fprintf(stderr, "-message: %v\n", err)
			return exitCannotRun
		}
		now := time.Now()
		end, err := parseUntil(*until, now)
		if err == nil {
			err = health.ValidateUntil(end, now)
		}
		if err != nil {
			fmt.Fprintf(stderr, "%v\n", err)
			return exitCannotRun
		}
		req.Message = msg
		if !end.IsZero() {
			req.Until = &end
		}
	}
	// Without -until, an "on" that updates a maintenance keeps its end.
	keepUntil := sub == "on" && *until == ""
	actor, err := cliActor()
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		e.actor = actor
		svc, err := e.service()
		if err != nil {
			fmt.Fprintf(e.stderr, "%v\n", err)
			return exitCannotRun
		}
		var res adminapi.MaintenanceResult
		if keepUntil {
			list, err := svc.ListMaintenance(e.ctx())
			if err != nil {
				fmt.Fprintf(e.stderr, "maintenance: %s\n", cliErrText(err))
				return exitCannotRun
			}
			var cur *adminapi.Maintenance
			if scope == adminapi.ScopeGateway {
				cur = list.Gateway
			}
			for i := range list.Upstreams {
				if scope == adminapi.ScopeUpstream && list.Upstreams[i].Upstream == upstream {
					cur = &list.Upstreams[i].Maintenance
				}
			}
			switch {
			case cur == nil || cur.Until == nil:
			case cur.UntilPassed:
				fmt.Fprintf(e.stdout, "The end announced for %s has passed and is dropped; announce a new one with -until.\n", opTime(*cur.Until))
			default:
				req.Until = cur.Until
			}
		}
		if sub == "on" {
			res, err = svc.StartMaintenance(e.ctx(), actor, req)
		} else {
			res, err = svc.EndMaintenance(e.ctx(), actor, adminapi.MaintenanceTarget{Scope: scope, Upstream: upstream})
		}
		if err != nil {
			fmt.Fprintf(e.stderr, "maintenance: %s\n", cliErrText(err))
			return exitCannotRun
		}
		for _, m := range res.Messages {
			fmt.Fprintln(e.stdout, m)
		}
		switch {
		case res.Changed && !res.Recorded:
			fmt.Fprintf(e.stderr, "THE CHANGE IS IN FORCE, but the audit trail could not record it: %s\n", warningText(res.ActionResult, adminapi.WarnAuditWriteFailed))
			return exitProblem
		case !res.Changed && sub == "off":
			return exitProblem
		}
		if sub == "on" && res.Changed {
			off := "maintenance off"
			if scope == adminapi.ScopeUpstream {
				off = "upstream maintenance off " + opShellQuote(upstream)
			}
			fmt.Fprintf(e.stdout, "End it with: %s\n", e.cmd(off))
		}
		return exitOK
	})
}

func maintenanceList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("maintenance list", stderr)
	asJSON := fs.Bool("json", false, "print JSON instead of an aligned table")
	if code, ok := opParse(fs, args, stdout, stderr, maintenanceUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, maintenanceUsage) {
		return exitCannotRun
	}
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		svc, err := e.service()
		if err != nil {
			fmt.Fprintf(e.stderr, "%v\n", err)
			return exitCannotRun
		}
		list, err := svc.ListMaintenance(e.ctx())
		if err != nil {
			fmt.Fprintf(e.stderr, "maintenance: %s\n", cliErrText(err))
			return exitCannotRun
		}
		if *asJSON {
			if err := opJSON(e.stdout, list); err != nil {
				fmt.Fprintf(e.stderr, "writing json: %v\n", err)
				return exitCannotRun
			}
			return exitOK
		}
		if list.Gateway == nil && len(list.Upstreams) == 0 {
			fmt.Fprintln(e.stdout, "Nothing is in maintenance.")
			return exitOK
		}
		tw := opTable(e.stdout)
		fmt.Fprintln(tw, "TARGET\tSINCE\tUNTIL\tSET BY\tMESSAGE")
		row := func(target string, m adminapi.Maintenance) {
			end := "-"
			if m.Until != nil {
				end = opTime(*m.Until)
				if m.UntilPassed {
					end += " (passed)"
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", target, opTime(m.StartedAt), end, m.SetBy, oneLine(m.Message))
		}
		if list.Gateway != nil {
			row(health.GatewayTarget, *list.Gateway)
		}
		for _, u := range list.Upstreams {
			row(u.Upstream, u.Maintenance)
		}
		if !opFlushTable(tw, e.stderr) {
			return exitProblem
		}
		return exitOK
	})
}

// oneLine keeps a table row one row: a message is stored validated, and
// this is only the terminal's belt.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
