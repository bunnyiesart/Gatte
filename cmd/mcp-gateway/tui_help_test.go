//go:build !nofront

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/front/gattetui"
)

// TestTUIHelpListsEveryCommand: the terminal console's help screen lists
// each command usage() lists, so a new command cannot be missing from it.
func TestTUIHelpListsEveryCommand(t *testing.T) {
	var b bytes.Buffer
	usage(&b)
	_, list, ok := strings.Cut(b.String(), "Commands:\n")
	if !ok {
		t.Fatal("usage() has no Commands: section")
	}
	list, _, _ = strings.Cut(list, "\n\n")
	known := map[string]bool{}
	for _, c := range gattetui.Commands {
		known[c.Name] = true
	}
	for _, line := range strings.Split(list, "\n") {
		name := strings.Fields(line)[0]
		if !known[name] {
			t.Errorf("usage() lists %q but the TUI help screen (gattetui.Commands) does not", name)
		}
		delete(known, name)
	}
	for name := range known {
		t.Errorf("the TUI help screen lists %q, which usage() does not", name)
	}
}

// TestTUIHelpListsEveryDispatchedCommand: the same, against the commands
// runWithStdin actually dispatches, so a command added there but not to
// usage() is caught too.
func TestTUIHelpListsEveryDispatchedCommand(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, c := range gattetui.Commands {
		known[c.Name] = true
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runWithStdin" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				name, _ := strconv.Unquote(lit.Value)
				if strings.HasPrefix(name, "-") || name == "help" {
					continue
				}
				found++
				if !known[name] {
					t.Errorf("main.go dispatches %q but the TUI help screen (gattetui.Commands) does not list it", name)
				}
			}
			return true
		})
		return false
	})
	if found == 0 {
		t.Fatal("found no dispatched command in runWithStdin")
	}
}
