// Package gattetui is the Gatte terminal front: the operator console as a
// full-screen terminal program (`mcp-gateway tui`), a client of the
// management API (design/adr/0040 §6) like the web console.
//
// It holds no rule. Every list, review and action is a call of pkg/adminapi
// to `mcp-gateway admin`, over the operator socket and, with -manage-users,
// the accounts socket; what a screen shows after an action is what the
// backend answered. The front only draws and confirms: a confirmation asks
// for exactly what the API itself checks (the fingerprint shown, the name
// typed again), and forwards it.
//
// It mirrors the web console's two tabs (design/adr/0051): "MCP Servers /
// APIs" and "Users". Each tab, each server-detail panel and each Users
// section registers itself from its own file's init() (registry.go), so a
// new surface never edits a shared menu.
//
// Every string the API returns is untrusted: it is drawn through
// frontkit.VisibleText (vis), which writes control characters, escape
// sequences and hidden code points as \u{XXXX}, so a backend cannot move
// the cursor, recolour the screen or hide text from the reviewer.
package gattetui

import (
	"context"
	"errors"
	"io"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// FrontName is the [tui] tag the backend writes in this front's operator
// rows (adminapi.WithFront).
const FrontName = "tui"

// Options is what the terminal front is built from.
type Options struct {
	// Operator is a client of the operator socket. Required.
	Operator *adminapi.Client
	// Accounts is a client of the accounts socket, nil without
	// -manage-users: accounts, secrets, signing and the roles file are then
	// read-only or absent, as in the web console.
	Accounts *adminapi.Client
}

// New returns the program's root model.
func New(o Options) (tea.Model, error) {
	if o.Operator == nil {
		return nil, errors.New("gattetui: an operator client is required")
	}
	return newApp(env{op: o.Operator, acc: o.Accounts}), nil
}

// Run draws the console on the terminal until the operator quits or ctx
// ends.
func Run(ctx context.Context, o Options, in io.Reader, out io.Writer) error {
	m, err := New(o)
	if err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithContext(ctx), tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	if _, err := p.Run(); err != nil && !(errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil) {
		return err
	}
	return nil
}
