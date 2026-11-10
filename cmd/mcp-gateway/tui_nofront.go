//go:build nofront

// Operator Console -- "tui" in a binary built without a front
// (design/adr/0040 §6): the terminal console is not in it either.

package main

import (
	"fmt"
	"io"
)

func cmdTUI(_ []string, _, stderr io.Writer) int {
	fmt.Fprint(stderr, "This mcp-gateway was built without a front (-tags nofront): there is no terminal console in it.\n"+
		"The management API is `mcp-gateway admin`; any front that speaks it can be used instead.\n")
	return exitCannotRun
}
