package audit

import (
	"errors"
	"testing"
	"time"
)

func validRecord() Record {
	return Record{
		AnalystIdentity: "alice",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
	}
}

func TestValidate_Valid(t *testing.T) {
	if err := validRecord().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidate_EmptyAnalystIdentity(t *testing.T) {
	r := validRecord()
	r.AnalystIdentity = ""

	err := r.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}
}

func TestValidate_EmptyTool(t *testing.T) {
	r := validRecord()
	r.Tool = ""

	err := r.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}
}

func TestValidate_EmptyTargetUpstream(t *testing.T) {
	r := validRecord()
	r.TargetUpstream = ""

	err := r.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}
}

func TestValidate_ZeroTimestamp(t *testing.T) {
	r := validRecord()
	r.Timestamp = time.Time{}

	err := r.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}
}

// TestValidate_AllStringFieldsEmpty confirms Validate reports every
// violated rule at once, not just the first one it happens to check --
// AnalystIdentity, Tool, and TargetUpstream are all empty here, so the
// joined error must unwrap to (at least) three distinct underlying
// errors in addition to ErrInvalid.
func TestValidate_AllStringFieldsEmpty(t *testing.T) {
	r := Record{
		AnalystIdentity: "",
		Tool:            "",
		TargetUpstream:  "",
		Timestamp:       time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
	}

	err := r.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() = %v, want ErrInvalid", err)
	}

	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("Validate() error does not support multi-unwrap: %v", err)
	}
	unwrapped := joined.Unwrap()

	// ErrInvalid plus one error per violated rule (three, here).
	const wantCount = 4
	if len(unwrapped) != wantCount {
		t.Fatalf("Validate() joined %d errors, want %d: %v", len(unwrapped), wantCount, err)
	}
}
