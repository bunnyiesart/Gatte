package store

import (
	"context"
	"sync"
	"testing"
)

// TestInMemoryPoolSeesOneDatabase pins the reason Open pins the pool for
// ":memory:".
//
// SQLite gives every connection to ":memory:" its own private database.
// Before this was pinned, a second pooled connection saw no tables at all
// -- so every adapter test in this repository was quietly depending on
// database/sql never deciding to open one. This test fails without the
// pin (verified by removing it: "SQL logic error: no such table").
func TestInMemoryPoolSeesOneDatabase(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	// Hold one connection open so the pool is forced to consider a second.
	held, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("first conn: %v", err)
	}
	defer held.Close()

	done := make(chan error, 1)
	go func() {
		_, err := db.Exec(`INSERT INTO t VALUES (1)`)
		done <- err
	}()

	// The insert can only proceed once the held connection is released,
	// which is exactly the serialization the pin buys.
	held.Close()
	if err := <-done; err != nil {
		t.Fatalf("second user of the pool could not see the table: %v", err)
	}
}

// TestInMemoryConcurrentUseIsSafe is the case that would have broken
// first in practice: several goroutines writing at once. Without the pin
// this is nondeterministic -- some goroutines land on fresh, empty
// databases.
func TestInMemoryConcurrentUseIsSafe(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := db.Exec(`INSERT INTO t VALUES (?)`, i); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent insert: %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != writers {
		t.Errorf("row count = %d, want %d -- writes landed in different databases", n, writers)
	}
}

// TestSeparateInMemoryStoresAreIsolated guards the other half of the
// decision: pinning the pool must not be swapped for
// "file::memory:?cache=shared", which would make two independent Open
// calls share one database and let tests contaminate each other.
func TestSeparateInMemoryStoresAreIsolated(t *testing.T) {
	a, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open a: %v", err)
	}
	defer a.Close()
	b, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open b: %v", err)
	}
	defer b.Close()

	if _, err := a.Exec(`CREATE TABLE only_in_a (x INTEGER)`); err != nil {
		t.Fatalf("create in a: %v", err)
	}
	if _, err := b.Exec(`SELECT 1 FROM only_in_a`); err == nil {
		t.Fatal("b can see a's table -- the two in-memory stores are sharing a database")
	}
}
