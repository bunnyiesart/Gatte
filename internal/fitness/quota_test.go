// Fitness function: the request path may not read a quota counter.
//
// # The property being protected
//
// The per-analyst quota has two ports, deliberately (design/adr/0030, and
// the declarations in internal/quota): quota.Store reserves and cannot
// read; quota.Reader reads and cannot reserve. The Gateway holds a Store.
// The Operator Console holds a Reader.
//
// The counter is a record of which third-party accounts an analyst has
// been querying, which is a summary of what they are investigating. "How
// much has X spent" is therefore a question the request path must not be
// able to answer -- a Gateway that could read counters would put one
// analyst's investigative activity one code change away from another
// analyst's tool call, and a component that can read is a component whose
// answer will eventually be returned to somebody.
//
// # Why the port split is not enough on its own
//
// Nothing in Go stops a package from importing quota and declaring its own
// variable of type quota.Reader, or from type-asserting a Store to one.
// The adapter satisfies both interfaces -- one value, two capabilities --
// so the separation lives entirely in which interface each caller names.
// That is a property of the wiring, and wiring is exactly what a review
// reads past.
//
// So the rule is positional, like the adapter rules in fitness_test.go: no
// package under internal/gateway may name the read port at all. The
// composition root may, because it is where the console's half is wired.

package fitness

import (
	"go/ast"
	"strings"
	"testing"
)

// quotaPkg is the quota component's domain package.
const quotaPkg = internalPrefix + "quota"

// quotaReadNames are the identifiers that mean "this code can see what an
// analyst has spent": the read port itself and the value it returns.
//
// Both, not just the interface. A package that never names quota.Reader
// but holds a []quota.Usage has the same knowledge by a different route,
// and the point of the rule is the knowledge.
var quotaReadNames = map[string]string{
	"Reader": "the counter-read port",
	"Usage":  "a counter's contents",
}

// TestTheRequestPathCannotReadAQuotaCounter is ADR-0030's separation made
// structural.
func TestTheRequestPathCannotReadAQuotaCounter(t *testing.T) {
	files := moduleSource(t)

	requestPath := internalPrefix + "gateway"
	var checked, importers int

	for _, f := range files {
		if f.Pkg != requestPath && !strings.HasPrefix(f.Pkg, requestPath+"/") {
			continue
		}
		checked++

		aliases := importAliases(f)
		quotaAlias := ""
		for alias, path := range aliases {
			if path == quotaPkg {
				quotaAlias = alias
			}
		}
		if quotaAlias == "" {
			continue
		}
		importers++

		ast.Inspect(f.File, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != quotaAlias {
				return true
			}
			if what, forbidden := quotaReadNames[sel.Sel.Name]; forbidden {
				t.Errorf(
					"%s: %s names quota.%s (%s).\n\n"+
						"The request path holds quota.Store, which can reserve and cannot read. A counter says which "+
						"third-party accounts an analyst has been querying, which is a summary of what they are "+
						"investigating, and nothing reachable from a tool call may be able to answer that. Reading "+
						"consumption is the Operator Console's job (`mcp-gateway quota usage`), and the console holds "+
						"the other port.\n\n"+
						"If the request path genuinely needs this, that is an ADR amendment and a new argument, not a "+
						"test edit.",
					f.Fset.Position(sel.Pos()), f.Pkg, sel.Sel.Name, what)
			}
			return true
		})
	}

	// Two canaries, because this rule passes trivially in two different
	// ways: by finding no packages to check, and by finding no package
	// that imports quota at all (in which case a future import would be
	// unguarded and nobody would know the rule had gone quiet).
	if checked == 0 {
		t.Fatal("no package under internal/gateway was inspected -- this rule is checking nothing")
	}
	if importers == 0 {
		t.Fatal("no package under internal/gateway imports internal/quota, so the gate is not wired where this rule " +
			"believes it is; either Dispatch stopped consulting the quota or this rule has lost track of it")
	}
}

// TestQuotaReadDetectorFailsOnARegression is the negative test. The rule
// above would be a comment if nobody had watched it fail, and the shape it
// has to catch is unremarkable-looking code: a field, or a helper that
// "just reports usage for the operator".
func TestQuotaReadDetectorFailsOnARegression(t *testing.T) {
	const src = `package gateway

import "github.com/bunnyiesart/Gatte/internal/quota"

type Gateway struct {
	quota   *quota.Gate
	counters quota.Reader
}

func (g *Gateway) spentBy(ctx context.Context) ([]quota.Usage, error) {
	return g.counters.Usage(ctx)
}
`
	f := parseSyntheticAs(t, internalPrefix+"gateway", src)
	aliases := importAliases(f)

	var found []string
	ast.Inspect(f.File, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if aliases[pkg.Name] != quotaPkg {
			return true
		}
		if _, forbidden := quotaReadNames[sel.Sel.Name]; forbidden {
			found = append(found, sel.Sel.Name)
		}
		return true
	})

	if len(found) != 2 {
		t.Fatalf("the detector found %v in code that reads counters from the request path, want both Reader and Usage", found)
	}

	// The control: the shape the request path actually has today must stay
	// clean, or a detector that reported everything would pass this test.
	const allowed = `package gateway

import "github.com/bunnyiesart/Gatte/internal/quota"

type Gateway struct{ quota *quota.Gate }

func (g *Gateway) admit(ctx context.Context, who, tool string) error {
	if err := g.quota.Admit(ctx, who, tool, g.now()); err != nil {
		if errors.Is(err, quota.ErrExhausted) {
			return err
		}
		return err
	}
	return nil
}
`
	clean := parseSyntheticAs(t, internalPrefix+"gateway", allowed)
	cleanAliases := importAliases(clean)
	ast.Inspect(clean.File, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); ok && cleanAliases[pkg.Name] == quotaPkg {
			if _, forbidden := quotaReadNames[sel.Sel.Name]; forbidden {
				t.Errorf("the detector flagged quota.%s in code that only reserves; the rule would forbid the gate itself", sel.Sel.Name)
			}
		}
		return true
	})
}
