// Command mcp-gateway is the entrypoint for the gateway binary.
//
// As of Phase 1 (WORKFLOW.md), this only proves the foundation wires
// together: it opens the shared SQLite store and migrates the Upstream
// Registry and Audit Trail schemas. There is no MCP-serving behavior yet
// -- that is Gateway Endpoint, Phase 5. Do not add flags or subcommands
// here ahead of the phase that needs them.
package main

import (
	"flag"
	"log"

	auditsqlite "github.com/bunnyiesart/Gatte/internal/audit/sqlite"
	registrysqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

func main() {
	dbPath := flag.String("db", "mcp-gateway.db", "path to the SQLite database file")
	flag.Parse()

	db, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer db.Close()

	if err := registrysqlite.Migrate(db); err != nil {
		log.Fatalf("migrate upstream registry: %v", err)
	}
	if err := auditsqlite.Migrate(db); err != nil {
		log.Fatalf("migrate audit trail: %v", err)
	}

	log.Printf("mcp-gateway: store ready at %s (upstream registry + audit trail migrated)", *dbPath)
}
