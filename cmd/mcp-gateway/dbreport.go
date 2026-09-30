// What backup, restore and check say about one database file
// (design/adr/0045): the same four questions, asked the same way.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/store"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// dbReport is one database file, examined.
type dbReport struct {
	// Schema is the recorded schema version.
	Schema int
	// Drift names every trigger, view, index or table of the file that is
	// extra, missing or different from what this binary's migrations
	// produce (store.SchemaDrift). A file with drift carries rules of its
	// own, which no check below would see.
	Drift []string
	// Chain is the audit trail's hash chain as VerifyChain found it.
	Chain audit.ChainCheck
	// Upstreams is how many entries the registry holds, and the three
	// lists are their names by signature state, as `upstream list` and
	// serve's trust anchor decide it.
	Upstreams int
	Valid     []string
	Unsigned  []string
	Invalid   []string
	// entries is the registry as read, for check's vault and oci checks.
	entries []registry.UpstreamServer
}

// inspectIntegrity runs the one check that must come before anything
// else reads the file: a damaged file is not asked anything more.
func inspectIntegrity(ctx context.Context, db *sql.DB) ([]string, error) {
	problems, err := store.IntegrityCheck(ctx, db)
	if err != nil {
		return nil, err
	}
	return problems, nil
}

// inspectContent fills the rest of the report from a file that passed
// the integrity check: schema, chain and signatures, the last against
// cfg's trusted keys, the anchor of ADR-0010 that is NOT in the file.
func inspectContent(ctx context.Context, cfg *config.Config, db *sql.DB, r *dbReport) error {
	v, err := store.SchemaOf(ctx, db)
	if err != nil {
		return err
	}
	r.Schema = v

	if r.Drift, err = schemaDrift(ctx, db); err != nil {
		return err
	}

	e := &opEnv{cfg: cfg, db: db}
	chain, err := e.auditChain().VerifyChain(ctx)
	if err != nil {
		return fmt.Errorf("audit trail: %w", err)
	}
	r.Chain = chain

	entries, err := e.upstreams().List(ctx)
	if err != nil {
		return fmt.Errorf("upstream registry: %w", err)
	}
	r.Upstreams = len(entries)
	r.entries = entries
	for _, entry := range entries {
		state, err := entrySignatureState(e, entry)
		if err != nil {
			return fmt.Errorf("signature of %q: %w", entry.Name, err)
		}
		// Escaped: a backup being restored is a file from elsewhere, and a
		// name in it reaches the terminal.
		name := visible.Escape(entry.Name)
		switch state {
		case sigValid:
			r.Valid = append(r.Valid, name)
		case sigUnsigned:
			r.Unsigned = append(r.Unsigned, name)
		default:
			r.Invalid = append(r.Invalid, name)
		}
	}
	return nil
}

// schemaDrift compares db, at this binary's schema, with a database this
// binary's migrations create in memory: the reference is the code, not a
// file anyone could have edited.
func schemaDrift(ctx context.Context, db *sql.DB) ([]string, error) {
	ref, err := openStorePath(":memory:")
	if err != nil {
		return nil, fmt.Errorf("the reference schema: %w", err)
	}
	defer ref.Close()
	want, err := store.SchemaShape(ctx, ref)
	if err != nil {
		return nil, err
	}
	got, err := store.SchemaShape(ctx, db)
	if err != nil {
		return nil, err
	}
	return store.SchemaDrift(got, want), nil
}

// driftLine is the drift in one line, escaped: the names come from the file.
func (r dbReport) driftLine() string {
	parts := make([]string, 0, len(r.Drift))
	for _, d := range r.Drift {
		parts = append(parts, visible.Escape(d))
	}
	return "its schema is not the one this binary's migrations produce: " + strings.Join(parts, ", ")
}

// chainLine is the audit chain in one line, for the three commands' output.
func (r dbReport) chainLine() string {
	if r.Chain.FirstBreak != nil {
		return fmt.Sprintf("BROKEN at record %d of %d (run mcp-gateway audit -verify on it for the detail)",
			r.Chain.FirstBreak.Position, r.Chain.Count)
	}
	return fmt.Sprintf("%d record(s), chain intact, head %s", r.Chain.Count, headOrNone(r.Chain.Head))
}

// signatureLine is the registry's signatures in one line.
func (r dbReport) signatureLine() string {
	parts := []string{fmt.Sprintf("%d signed by a trusted key", len(r.Valid))}
	if len(r.Unsigned) > 0 {
		parts = append(parts, fmt.Sprintf("%d unsigned (%s)", len(r.Unsigned), strings.Join(r.Unsigned, ", ")))
	}
	if len(r.Invalid) > 0 {
		parts = append(parts, fmt.Sprintf("%d with an INVALID signature (%s)", len(r.Invalid), strings.Join(r.Invalid, ", ")))
	}
	return fmt.Sprintf("%d %s: %s", r.Upstreams, opPlural(r.Upstreams, "entry", "entries"), strings.Join(parts, ", "))
}
