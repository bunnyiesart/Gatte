//go:build !nofront

// Operator Console -- "tui": the Gatte terminal front, run as the operator,
// as a client of the management API (design/adr/0040 §6), like `ui`.
//
// This file only starts it. The screens are internal/front/gattetui, which
// reaches the gateway through pkg/adminapi and nothing else. So `tui` opens
// no database and reads no config.toml: it connects to the operator socket,
// and with -manage-users to the accounts socket, and the backend says who
// the operator is from the kernel's credentials of this process.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bunnyiesart/Gatte/internal/front/gattetui"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func cmdTUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway tui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	o := uiOptions{}
	fs.StringVar(&o.Socket, "socket", adminapi.DefaultOperatorSocket, "the management API's operator socket")
	fs.StringVar(&o.AccountsSocket, "accounts-socket", adminapi.DefaultAccountsSocket, "the management API's accounts socket, for -manage-users")
	fs.BoolVar(&o.Manage, "manage-users", false, "also open the accounts socket, to edit accounts, secrets, signatures and the roles file")
	if code, ok := opParse(fs, args, stdout, stderr, tuiUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, tuiUsage) {
		return exitCannotRun
	}
	ctx, stop := signalContext()
	defer stop()
	return runTUI(ctx, o, os.Stdin, stdout, stderr)
}

// runTUI draws the console on the terminal until the operator quits or ctx
// ends.
func runTUI(ctx context.Context, o uiOptions, stdin io.Reader, stdout, stderr io.Writer) int {
	op := adminapi.New(o.Socket, adminapi.WithFront(gattetui.FrontName))
	if _, err := op.WhoAmI(ctx); err != nil {
		fmt.Fprintf(stderr, "tui: cannot use the management API at %s: %v\n\n"+
			"Start it (systemctl start mcp-gateway-admin.socket, or mcp-gateway admin -socket %s as the\n"+
			"service account) and run tui as a member of the socket's group (gatte-operators).\n", o.Socket, err, o.Socket)
		return exitCannotRun
	}
	var acc *adminapi.Client
	if o.Manage {
		acc = adminapi.NewAccounts(o.AccountsSocket, adminapi.WithFront(gattetui.FrontName))
		if _, err := acc.WhoAmI(ctx); err != nil {
			if errors.Is(err, adminapi.ErrImpostor) {
				fmt.Fprintf(stderr, "tui: %s is not root's accounts socket (its server is not root): %v\n"+
					"Refusing to send accounts or secrets to it (design/adr/0040 §4).\n", o.AccountsSocket, err)
				return exitCannotRun
			}
			fmt.Fprintf(stderr, "tui: -manage-users cannot use the accounts socket at %s: %v\n\n"+
				"It is served by root (mcp-gateway admin -accounts). Open it with sudo mcp-gateway tui -manage-users,\n"+
				"or without sudo as a member of [admin] account_group when the socket is delegated (design/adr/0040 §1).\n", o.AccountsSocket, err)
			return exitCannotRun
		}
	}
	if err := gattetui.Run(ctx, gattetui.Options{Operator: op, Accounts: acc}, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "tui: %v\n", err)
		return exitCannotRun
	}
	return exitOK
}

func tuiUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway tui [-socket PATH] [-manage-users [-accounts-socket PATH]]

Draws the operator console in this terminal, with the web console's two
tabs: "MCP Servers / APIs" (each backend's health, its tools to review,
approve, revoke and clear, its secret names, its maintenance, redial, sign
and deregister) and "Users" (accounts, roles and the blocklist).

It is a client of the management API (mcp-gateway admin), like ui: every
screen is a call to it, and every action is the API's action of the same
name, with the same checks and the same audit rows, tagged [tui]. It reads
no configuration file and opens no database.

Run it as yourself, as a member of the operator socket's group; the audit
trail names you from the kernel's credentials. With -manage-users it also
opens the accounts socket, served by root: run it with sudo, or as a member
of [admin] account_group when that socket is delegated. It refuses an
accounts socket not served by root.

Keys: 1 and 2 (or tab) switch tabs, the arrows move, enter opens, esc goes
back, r re-reads, q quits. Each screen lists its own action keys at the
bottom; a destructive one asks first.

Default sockets:
  operator  `+adminapi.DefaultOperatorSocket+`
  accounts  `+adminapi.DefaultAccountsSocket+`
`)
}
