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
		Outcome:         OutcomeAllowed,
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
		Outcome:         OutcomeAllowed,
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

// TestValidate_RequiresAnOutcome pins that Outcome has no usable zero
// value. A record defaulting to some outcome would quietly mark every
// call the same, which is precisely the failure the field was added to
// fix -- an audit trail that cannot tell a refused call from a completed
// one.
func TestValidate_RequiresAnOutcome(t *testing.T) {
	base := Record{
		AnalystIdentity: "analyst@example.test",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC),
	}

	t.Run("unset is rejected", func(t *testing.T) {
		if err := base.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Validate with no Outcome = %v, want ErrInvalid", err)
		}
	})

	t.Run("garbage is rejected", func(t *testing.T) {
		r := base
		r.Outcome = "probably-fine"
		if err := r.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Validate with a bogus Outcome = %v, want ErrInvalid", err)
		}
	})

	for _, o := range []Outcome{OutcomeAllowed, OutcomeDenied, OutcomeFailed} {
		t.Run(string(o)+" is accepted", func(t *testing.T) {
			r := base
			r.Outcome = o
			if err := r.Validate(); err != nil {
				t.Fatalf("Validate with Outcome %q = %v, want nil", o, err)
			}
		})
	}
}
