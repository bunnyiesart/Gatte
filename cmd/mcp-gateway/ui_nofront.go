//go:build nofront

// Operator Console -- "ui" in a binary built without a front
// (design/adr/0040 §6): the gateway, the management API and the CLI are
// all here; the web console is not.

package main

import (
	"fmt"
	"io"
)

func cmdUI(_ []string, _, stderr io.Writer) int {
	fmt.Fprint(stderr, "This mcp-gateway was built without a front (-tags nofront): there is no web console in it.\n"+
		"The management API is `mcp-gateway admin`; any front that speaks it can be used instead.\n")
	return exitCannotRun
}
