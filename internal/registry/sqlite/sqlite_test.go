package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/registry"
	regsqlite "github.com/bunnyiesart/Gatte/internal/registry/sqlite"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// newTestRepo returns a Repository backed by a fresh in-memory database,
// along with the raw *sql.DB so tests can inspect stored column values
// directly where the Repository's exported API can't express the check.
func newTestRepo(t *testing.T) (*sql.DB, *regsqlite.Repository) {
	t.Helper()

	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := regsqlite.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	return db, regsqlite.New(db)
}

func TestRepository_RegisterGet_RoundTrip(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	in := registry.UpstreamServer{
		Name:        "casemgmt",
		Transport:   registry.TransportStdio,
		Command:     "/usr/local/bin/casemgmt-mcp",
		Args:        []string{"--config", "/etc/casemgmt/config.yaml"},
		URL:         "",
		EnvVarNames: []string{"CASEMGMT_API_KEY", "CASEMGMT_BASE_URL"},
	}

	if err := repo.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := repo.Get(ctx, "casemgmt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Name != in.Name {
		t.Errorf("Name = %q, want %q", got.Name, in.Name)
	}
	if got.Transport != in.Transport {
		t.Errorf("Transport = %q, want %q", got.Transport, in.Transport)
	}
	if got.Command != in.Command {
		t.Errorf("Command = %q, want %q", got.Command, in.Command)
	}
	if len(got.Args) != len(in.Args) {
		t.Fatalf("Args = %v, want %v", got.Args, in.Args)
	}
	for i := range in.Args {
		if got.Args[i] != in.Args[i] {
			t.Errorf("Args[%d] = %q, want %q", i, got.Args[i], in.Args[i])
		}
	}
	if got.URL != in.URL {
		t.Errorf("URL = %q, want %q", got.URL, in.URL)
	}
	if len(got.EnvVarNames) != len(in.EnvVarNames) {
		t.Fatalf("EnvVarNames = %v, want %v", got.EnvVarNames, in.EnvVarNames)
	}
	for i := range in.EnvVarNames {
		if got.EnvVarNames[i] != in.EnvVarNames[i] {
			t.Errorf("EnvVarNames[%d] = %q, want %q", i, got.EnvVarNames[i], in.EnvVarNames[i])
		}
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, want it set by Register")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt is zero, want it set by Register")
	}
	if !got.CreatedAt.Equal(got.UpdatedAt) {
		t.Errorf("CreatedAt (%v) != UpdatedAt (%v) on first Register, want them equal", got.CreatedAt, got.UpdatedAt)
	}
}

func TestRepository_RegisterGet_EmptySlicesRoundTripAsEmptyNotNil(t *testing.T) {
	db, repo := newTestRepo(t)
	ctx := context.Background()

	in := registry.UpstreamServer{
		Name:      "no-secrets-needed",
		Transport: registry.TransportHTTP,
		URL:       "https://example.internal",
		// Args and EnvVarNames deliberately left nil -- a server can
		// require zero secrets and take zero extra args.
	}

	if err := repo.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := repo.Get(ctx, "no-secrets-needed")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if got.Args == nil {
		t.Error("Args round-tripped as nil, want an empty non-nil slice")
	}
	if len(got.Args) != 0 {
		t.Errorf("Args = %v, want empty", got.Args)
	}
	if got.EnvVarNames == nil {
		t.Error("EnvVarNames round-tripped as nil, want an empty non-nil slice")
	}
	if len(got.EnvVarNames) != 0 {
		t.Errorf("EnvVarNames = %v, want empty", got.EnvVarNames)
	}

	// Confirm the value actually stored is the JSON empty array "[]", not
	// the literal "null" -- Register normalizes nil slices before
	// encoding specifically so this distinction doesn't leak into what's
	// persisted.
	var rawArgs, rawEnvVarNames string
	row := db.QueryRowContext(ctx, `SELECT args, env_var_names FROM upstream_servers WHERE name = ?`, "no-secrets-needed")
	if err := row.Scan(&rawArgs, &rawEnvVarNames); err != nil {
		t.Fatalf("querying raw stored columns: %v", err)
	}
	if rawArgs != "[]" {
		t.Errorf("stored args column = %q, want %q", rawArgs, "[]")
	}
	if rawEnvVarNames != "[]" {
		t.Errorf("stored env_var_names column = %q, want %q", rawEnvVarNames, "[]")
	}
}

func TestRepository_Register_DuplicateNameReturnsErrAlreadyExists(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	original := registry.UpstreamServer{
		Name:      "logsearch",
		Transport: registry.TransportHTTP,
		URL:       "https://logsearch.internal:9000",
	}
	if err := repo.Register(ctx, original); err != nil {
		t.Fatalf("Register (original): %v", err)
	}

	duplicate := registry.UpstreamServer{
		Name:      "logsearch",
		Transport: registry.TransportStdio,
		Command:   "/some/other/binary",
	}
	err := repo.Register(ctx, duplicate)
	if !errors.Is(err, registry.ErrAlreadyExists) {
		t.Fatalf("Register (duplicate) error = %v, want ErrAlreadyExists", err)
	}

	// The original entry must be untouched by the failed duplicate
	// registration.
	got, err := repo.Get(ctx, "logsearch")
	if err != nil {
		t.Fatalf("Get after failed duplicate Register: %v", err)
	}
	if got.Transport != registry.TransportHTTP {
		t.Errorf("Transport = %q, want unchanged %q", got.Transport, registry.TransportHTTP)
	}
	if got.URL != original.URL {
		t.Errorf("URL = %q, want unchanged %q", got.URL, original.URL)
	}
	if got.Command != "" {
		t.Errorf("Command = %q, want unchanged empty string", got.Command)
	}
}

func TestRepository_Get_NonexistentReturnsErrNotFound(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	_, err := repo.Get(ctx, "does-not-exist")
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("Get error = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_EmptyReturnsEmptyNonNilSlice(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Fatal("List returned nil, want an empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
}

func TestRepository_List_ReturnsAllRegistered(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	servers := []registry.UpstreamServer{
		{Name: "casemgmt", Transport: registry.TransportStdio, Command: "/bin/casemgmt"},
		{Name: "threatintel", Transport: registry.TransportStdio, Command: "/bin/threatintel"},
	}
	for _, s := range servers {
		if err := repo.Register(ctx, s); err != nil {
			t.Fatalf("Register(%q): %v", s.Name, err)
		}
	}

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List returned %d entries, want 2: %v", len(got), got)
	}

	names := map[string]bool{}
	for _, s := range got {
		names[s.Name] = true
	}
	for _, s := range servers {
		if !names[s.Name] {
			t.Errorf("List missing entry %q", s.Name)
		}
	}
}

func TestRepository_Deregister(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	in := registry.UpstreamServer{
		Name:      "docsearch",
		Transport: registry.TransportHTTP,
		URL:       "https://docsearch.internal:9200",
	}
	if err := repo.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := repo.Deregister(ctx, "docsearch"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}

	if _, err := repo.Get(ctx, "docsearch"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("Get after Deregister error = %v, want ErrNotFound", err)
	}

	// Deregistering the same name again must return ErrNotFound, not
	// silently succeed.
	if err := repo.Deregister(ctx, "docsearch"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("second Deregister error = %v, want ErrNotFound", err)
	}
}

func TestRepository_Deregister_NonexistentReturnsErrNotFound(t *testing.T) {
	_, repo := newTestRepo(t)
	ctx := context.Background()

	if err := repo.Deregister(ctx, "never-registered"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("Deregister error = %v, want ErrNotFound", err)
	}
}
