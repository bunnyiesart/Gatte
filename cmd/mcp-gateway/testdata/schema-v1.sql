-- index idx_audit_records_timestamp
CREATE INDEX idx_audit_records_timestamp
	ON audit_records (timestamp);

-- table audit_chain_meta
CREATE TABLE audit_chain_meta (
	id                      INTEGER PRIMARY KEY CHECK (id = 1),
	retroactive_boundary_id INTEGER NOT NULL
);

-- table audit_records
CREATE TABLE audit_records (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	analyst_identity TEXT NOT NULL,
	tool             TEXT NOT NULL,
	target_upstream  TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	outcome          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL DEFAULT '',
	source_address   TEXT NOT NULL DEFAULT '',
	analyst_name     TEXT NOT NULL DEFAULT ''
, prev_hash TEXT NOT NULL DEFAULT '', hash TEXT NOT NULL DEFAULT '');

-- table backend_health
CREATE TABLE backend_health (
	backend      TEXT PRIMARY KEY,
	live         INTEGER NOT NULL,
	since        TEXT NOT NULL,
	last_attempt TEXT NOT NULL DEFAULT '',
	next_attempt TEXT NOT NULL DEFAULT '',
	cause        TEXT NOT NULL DEFAULT '',
	updated_at   TEXT NOT NULL
);

-- table backend_listing
CREATE TABLE backend_listing (
	backend   TEXT NOT NULL,
	tool      TEXT NOT NULL,
	hash      TEXT NOT NULL,
	listed_at TEXT NOT NULL,
	PRIMARY KEY (backend, tool)
);

-- table blocked_subjects
CREATE TABLE blocked_subjects (
	subject    TEXT PRIMARY KEY,
	reason     TEXT NOT NULL DEFAULT '',
	blocked_by TEXT NOT NULL,
	blocked_at TEXT NOT NULL
, blocked_until TEXT NOT NULL DEFAULT '');

-- table entry_signatures
CREATE TABLE entry_signatures (
	name       TEXT PRIMARY KEY,
	public_key BLOB NOT NULL,
	signature  BLOB NOT NULL
);

-- table maintenance
CREATE TABLE maintenance (
	target     TEXT PRIMARY KEY,
	message    TEXT NOT NULL,
	until      TEXT NOT NULL DEFAULT '',
	started_at TEXT NOT NULL,
	set_by     TEXT NOT NULL,
	set_at     TEXT NOT NULL
);

-- table quarantined_tools
CREATE TABLE quarantined_tools (
	server_name   TEXT NOT NULL,
	tool_name     TEXT NOT NULL,
	status        TEXT NOT NULL,
	approved_hash TEXT NOT NULL,
	observed_hash TEXT NOT NULL,
	first_seen_at TEXT NOT NULL,
	updated_at    TEXT NOT NULL,
	PRIMARY KEY (server_name, tool_name)
);

-- table quota_counters
CREATE TABLE quota_counters (
	analyst      TEXT NOT NULL,
	provider     TEXT NOT NULL,
	window_start TEXT NOT NULL,
	used         INTEGER NOT NULL,
	PRIMARY KEY (analyst, provider, window_start)
);

-- table serve_process
CREATE TABLE serve_process (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	pid         INTEGER NOT NULL,
	boot        TEXT NOT NULL,
	start_token TEXT NOT NULL DEFAULT ''
);

-- table serve_request
CREATE TABLE serve_request (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	kind         TEXT NOT NULL,
	target       TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL,
	tag          TEXT NOT NULL DEFAULT '',
	requested_at TEXT NOT NULL,
	state        TEXT NOT NULL,
	done_at      TEXT NOT NULL DEFAULT '',
	outcome      TEXT NOT NULL DEFAULT '',
	result       TEXT NOT NULL DEFAULT '',
	boot         TEXT NOT NULL DEFAULT ''
);

-- table serve_status
CREATE TABLE serve_status (
	id                     INTEGER PRIMARY KEY CHECK (id = 1),
	boot                   TEXT NOT NULL,
	last_round_at          TEXT NOT NULL,
	round_interval_seconds INTEGER NOT NULL
);

-- table tool_definitions
CREATE TABLE tool_definitions (
	hash          TEXT NOT NULL PRIMARY KEY,
	name          TEXT NOT NULL,
	description   TEXT NOT NULL,
	input_schema  BLOB NOT NULL,
	output_schema BLOB NOT NULL,
	first_seen_at TEXT NOT NULL
);

-- table upstream_servers
CREATE TABLE upstream_servers (
	name          TEXT PRIMARY KEY,
	transport     TEXT NOT NULL,
	command       TEXT NOT NULL,
	args          TEXT NOT NULL,
	url           TEXT NOT NULL,
	env_var_names TEXT NOT NULL,
	created_at    TEXT NOT NULL,
	updated_at    TEXT NOT NULL
, image TEXT NOT NULL DEFAULT '');

-- trigger tool_definitions_no_delete_referenced
CREATE TRIGGER tool_definitions_no_delete_referenced
BEFORE DELETE ON tool_definitions
WHEN EXISTS (SELECT 1 FROM quarantined_tools
             WHERE approved_hash = OLD.hash OR observed_hash = OLD.hash)
BEGIN SELECT RAISE(ABORT, 'tool_definitions: a definition the quarantine references cannot be deleted'); END;

-- trigger tool_definitions_no_update
CREATE TRIGGER tool_definitions_no_update
BEFORE UPDATE ON tool_definitions
BEGIN SELECT RAISE(ABORT, 'tool_definitions rows are never rewritten'); END;

