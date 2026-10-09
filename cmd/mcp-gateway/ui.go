//go:build !nofront

// Operator Console -- "ui": the Gatte web front (design/adr/0036), run as
// the operator, as a client of the management API (design/adr/0040 §6).
//
// This file only starts it. The pages are internal/front/gatteweb, which
// reaches the gateway through pkg/adminapi and nothing else, and serves
// through pkg/frontkit and nothing else. So `ui` opens no database and
// reads no config.toml: it connects to the operator socket, and with
// -manage-users to the accounts socket, and the backend says who the
// operator is from the kernel's credentials of this process.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/bunnyiesart/Gatte/internal/front/gatteweb"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// uiDefaultListen is not serve's 8080, so both can run side by side.
const uiDefaultListen = "127.0.0.1:8090"

// uiMaxBody bounds a POST to the console. frontkit's default, 64 KiB, fits
// every form of a few short fields; the Add an API form of design/adr/0050
// uploads or pastes an OpenAPI document of up to
// adminapi.MaxUpstreamDocumentBytes (4 MiB) as multipart, and the Roles
// form sends a roles file of up to 1 MiB url-encoded (up to three bytes per
// byte). 6 MiB holds either with room for the other fields; the management
// API holds each document to its own bound after that.
const uiMaxBody = 6 << 20

// uiOptions is what `ui` is started with.
type uiOptions struct {
	Listen         string
	Socket         string
	AccountsSocket string
	// Manage opens the accounts socket too, for the account pages.
	Manage bool
}

func cmdUI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway ui", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	o := uiOptions{}
	fs.StringVar(&o.Listen, "listen", uiDefaultListen, "loopback address to serve the console on")
	fs.StringVar(&o.Socket, "socket", adminapi.DefaultOperatorSocket, "the management API's operator socket")
	fs.StringVar(&o.AccountsSocket, "accounts-socket", adminapi.DefaultAccountsSocket, "the management API's accounts socket, for -manage-users")
	fs.BoolVar(&o.Manage, "manage-users", false, "also open the accounts socket, to edit the identity provider's accounts")
	config := fs.String("config", "", "not used: the console reads no configuration file")
	if code, ok := opParse(fs, args, stdout, stderr, uiUsage); !ok {
		return code
	}
	if !opNoArgs(fs, stderr, uiUsage) {
		return exitCannotRun
	}
	if *config != "" {
		fmt.Fprintf(stderr, "ui reads no configuration file: it is a client of the management API (mcp-gateway admin),\n"+
			"which reads it. Point it at the operator socket instead: -socket %s\n", adminapi.DefaultOperatorSocket)
		return exitCannotRun
	}
	ctx, stop := signalContext()
	defer stop()
	return runUI(ctx, o, stdout, stderr)
}

// runUI serves the console until ctx ends.
func runUI(ctx context.Context, o uiOptions, stdout, stderr io.Writer) int {
	kit, err := frontkit.New(frontkit.Config{Listen: o.Listen, MaxBody: uiMaxBody})
	if err != nil {
		fmt.Fprintf(stderr, "ui: %v (design/adr/0036)\n", err)
		return exitCannotRun
	}
	defer func() { _ = kit.Close() }()

	op := adminapi.New(o.Socket, adminapi.WithFront(gatteweb.FrontName))
	me, err := op.WhoAmI(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "ui: cannot use the management API at %s: %v\n\n"+
			"Start it (systemctl start mcp-gateway-admin.socket, or mcp-gateway admin -socket %s as the\n"+
			"service account) and run ui as a member of the socket's group (gatte-operators).\n", o.Socket, err, o.Socket)
		return exitCannotRun
	}
	var acc *adminapi.Client
	if o.Manage {
		acc = adminapi.NewAccounts(o.AccountsSocket, adminapi.WithFront(gatteweb.FrontName))
		if _, err := acc.WhoAmI(ctx); err != nil {
			if errors.Is(err, adminapi.ErrImpostor) {
				fmt.Fprintf(stderr, "ui: %s is not root's accounts socket (its server is not root): %v\n"+
					"Refusing to send accounts to it (design/adr/0040 §4).\n", o.AccountsSocket, err)
				return exitCannotRun
			}
			fmt.Fprintf(stderr, "ui: -manage-users cannot use the accounts socket at %s: %v\n\n"+
				"It is served by root (mcp-gateway admin -accounts). Open it with sudo mcp-gateway ui -manage-users,\n"+
				"or without sudo as a member of [admin] account_group when the socket is delegated (design/adr/0040 §1).\n", o.AccountsSocket, err)
			return exitCannotRun
		}
	}
	front, err := gatteweb.New(gatteweb.Options{Operator: op, Accounts: acc, Kit: kit})
	if err != nil {
		fmt.Fprintf(stderr, "ui: %v\n", err)
		return exitCannotRun
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = kit.Shutdown(shut)
	}()
	manage := ""
	if acc != nil {
		manage = ", with the identity provider's accounts"
	}
	fmt.Fprintf(stdout, "Gatte web console on %s%s, acting as operator %q.\n\nOpen this link (it logs this browser in; keep it private):\n\n    %s\n\nFrom another machine: ssh -L %s:%s HOST, then open the same link there.\nCtrl-C stops the console. The gateway and its management API keep running.\n",
		o.Socket, manage, me.Operator.Name, kit.LoginURL(), uiPort(kit.Addr()), kit.Addr())
	if err := front.Serve(); err != nil {
		fmt.Fprintf(stderr, "ui: %v\n", err)
		return exitCannotRun
	}
	return exitOK
}

func uiPort(a net.Addr) string {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return "8090"
	}
	return p
}

func uiUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  mcp-gateway ui [-socket PATH] [-listen 127.0.0.1:8090] [-manage-users [-accounts-socket PATH]]

Serves the operator console as a web page on loopback: the tool approval
queue with each definition's review and diff, the blocklist, the audit
trail and its verification, the people and roles, the registered backends
and quota spend.

It is a client of the management API (mcp-gateway admin): every page is a
call to it over the operator socket, and every button is the API's action
of the same name, with the same checks and the same audit rows. It reads
no configuration file and opens no database.

With [admin] console_manages = true (design/adr/0050) it also adds REST
APIs from their OpenAPI document, removes and redials backends, clears
sensitive tools and reloads the configuration; with -manage-users as well,
it signs backends and edits the vault's secrets and the roles file. With
the key off, registering and signing a backend stay in the terminal.

Run it as yourself, as a member of the operator socket's group; the audit
trail names you from the kernel's credentials, not from anything you type.
With -manage-users it also opens the accounts socket, served by root: run
it with sudo, or as a member of [admin] account_group when that socket is
delegated. It refuses an accounts socket not served by root.

It prints a /login link carrying a random token; open it once and the
browser keeps a cookie for this run. -listen must be loopback. To use it
from your own machine, forward the port: ssh -L 8090:127.0.0.1:8090 HOST.

Default sockets:
  operator  `+adminapi.DefaultOperatorSocket+`
  accounts  `+adminapi.DefaultAccountsSocket+`
`)
}
