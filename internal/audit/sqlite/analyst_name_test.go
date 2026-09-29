package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// preNameSchema is audit_records as it stood before design/adr/0037:
// chained, with its meta table, and no analyst_name. Spelled out by hand
// for the reason legacySchema is.
const preNameSchema = `
CREATE TABLE audit_records (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	analyst_identity TEXT NOT NULL,
	tool             TEXT NOT NULL,
	target_upstream  TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	outcome          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	source_address   TEXT NOT NULL DEFAULT '',
	prev_hash        TEXT NOT NULL DEFAULT '',
	hash             TEXT NOT NULL DEFAULT ''
);
CREATE TABLE audit_chain_meta (
	id                      INTEGER PRIMARY KEY CHECK (id = 1),
	retroactive_boundary_id INTEGER NOT NULL
);
INSERT INTO audit_chain_meta (id, retroactive_boundary_id) VALUES (1, 0);
`

// preNameRow is a row written by the pre-0037 gateway, with the hash that
// code computed for it (the same vector internal/audit pins). Literal, so
// this test does not depend on today's ChainHash agreeing with itself.
const preNameRow = `
INSERT INTO audit_records (analyst_identity, tool, target_upstream, timestamp, outcome, reason, source_address, prev_hash, hash)
VALUES ('95f757fe-0c7b-4272-9d5e-3f1a2b4c6d8e', 'casemgmt.list_cases', 'casemgmt',
        '2026-09-11T12:00:00.123456789Z', 'denied', 'forbidden', '192.0.2.10',
        '', '35a7b578421c34e0a65b3c1b409ca87afcefb1c55b21bba5cdc527e8c1513511')`

func namedRecord(at time.Time) audit.Record {
	return audit.Record{
		AnalystIdentity: "95f757fe-0c7b-4272-9d5e-3f1a2b4c6d8e",
		AnalystName:     "Ana Lyst",
		Tool:            "logsearch.search",
		TargetUpstream:  "logsearch",
		Timestamp:       at,
		Outcome:         audit.OutcomeAllowed,
		SourceAddress:   "192.0.2.10",
	}
}

// TestMigrate_APreNameTrailStillVerifiesAndTakesNamedRows: the migration
// adds the column, the old row keeps its hash, and a mixed trail -- old
// unnamed rows, then new unnamed and named ones -- verifies end to end.
func TestMigrate_APreNameTrailStillVerifiesAndTakesNamedRows(t *testing.T) {
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(preNameSchema); err != nil {
		t.Fatalf("creating the pre-0037 table: %v", err)
	}
	if _, err := db.Exec(preNameRow); err != nil {
		t.Fatalf("seeding the pre-0037 row: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate against a pre-0037 database: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	r := New(db)
	ctx := context.Background()
	check, err := r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() || check.Count != 1 {
		t.Fatalf("the pre-0037 row does not verify after migration: %+v", check)
	}

	at := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	unnamed := namedRecord(at)
	unnamed.AnalystName = ""
	for _, rec := range []audit.Record{namedRecord(at), unnamed, namedRecord(at.Add(time.Second))} {
		if err := r.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	check, err = r.VerifyChain(ctx)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() || check.Count != 4 {
		t.Fatalf("a mixed trail does not verify: %+v", check)
	}

	got, err := r.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got[0].AnalystName != "" {
		t.Errorf("the pre-0037 row reads back with name %q, want empty", got[0].AnalystName)
	}
	if got[1].AnalystName != "Ana Lyst" || got[2].AnalystName != "" || got[3].AnalystName != "Ana Lyst" {
		t.Errorf("names did not round-trip: %q %q %q", got[1].AnalystName, got[2].AnalystName, got[3].AnalystName)
	}
}

// TestVerifyChain_AnEditedNameIsReported: the name is in the chain, so
// renaming, adding or erasing it on disk is a break like any other edit.
func TestVerifyChain_AnEditedNameIsReported(t *testing.T) {
	for _, tc := range []struct{ name, set string }{
		{"renamed", "Mallory"},
		{"erased", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			r := New(db)
			ctx := context.Background()
			at := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
			for i := range 3 {
				if err := r.Record(ctx, namedRecord(at.Add(time.Duration(i)*time.Second))); err != nil {
					t.Fatalf("Record: %v", err)
				}
			}
			if _, err := db.Exec(`UPDATE audit_records SET analyst_name = ? WHERE id = 2`, tc.set); err != nil {
				t.Fatalf("tamper: %v", err)
			}
			check, err := r.VerifyChain(ctx)
			if err != nil {
				t.Fatalf("VerifyChain: %v", err)
			}
			if check.Intact() || check.FirstBreak.Position != 2 {
				t.Fatalf("an edited analyst_name was not reported at record 2: %+v", check)
			}
			if check.FirstBreak.Record.AnalystName != tc.set {
				t.Errorf("break reports name %q, want the value on disk %q", check.FirstBreak.Record.AnalystName, tc.set)
			}
		})
	}

	// And a row with no name that gains one is an edit too.
	db := newTestDB(t)
	r := New(db)
	unnamed := namedRecord(time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC))
	unnamed.AnalystName = ""
	if err := r.Record(context.Background(), unnamed); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if _, err := db.Exec(`UPDATE audit_records SET analyst_name = 'Ana Lyst' WHERE id = 1`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	check, err := r.VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if check.Intact() {
		t.Fatal("a name added to an unnamed row verifies")
	}
}

// TestMigrate_BackfillCarriesTheName: backfillChain is the third reader of
// the table; a row it hashes must be hashed with every field, name
// included, or VerifyChain would disagree with it.
func TestMigrate_BackfillCarriesTheName(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.Exec(`DELETE FROM audit_chain_meta`); err != nil {
		t.Fatalf("reset meta: %v", err)
	}
	if _, err := db.Exec(`
INSERT INTO audit_records (analyst_identity, analyst_name, tool, target_upstream, timestamp, outcome, reason, source_address)
VALUES ('95f757fe', 'Ana Lyst', 'casemgmt.list_cases', 'casemgmt', '2026-09-29T09:00:00Z', 'allowed', '', '')`); err != nil {
		t.Fatalf("seed unhashed named row: %v", err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	check, err := New(db).VerifyChain(context.Background())
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !check.Intact() {
		t.Fatalf("a backfilled named row does not verify: %+v", check.FirstBreak)
	}
}
