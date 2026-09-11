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

// chainRec is a well-formed record for the chain tests. Fields the test
// varies are set by the caller.
func chainRec() Record {
	return Record{
		AnalystIdentity: "ana",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		Outcome:         OutcomeAllowed,
	}
}

// TestCanonical_FieldBoundariesCannotShift is the reason the encoding is
// length-prefixed rather than concatenated. Without the lengths, moving a
// byte from one field to the next produces identical bytes, so a record
// could be rewritten into a DIFFERENT record that chains just as well --
// which is precisely the property the chain exists to provide.
func TestCanonical_FieldBoundariesCannotShift(t *testing.T) {
	for _, tc := range []struct{ name, a1, a2, b1, b2 string }{
		{"tool/reason", "ab", "c", "a", "bc"},
		{"identity/tool", "xy", "z", "x", "yz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := chainRec(), chainRec()
			switch tc.name {
			case "tool/reason":
				left.Tool, left.Reason = tc.a1, tc.a2
				right.Tool, right.Reason = tc.b1, tc.b2
			case "identity/tool":
				left.AnalystIdentity, left.Tool = tc.a1, tc.a2
				right.AnalystIdentity, right.Tool = tc.b1, tc.b2
			}

			if string(Canonical(left)) == string(Canonical(right)) {
				t.Fatal("two different records produced identical canonical bytes -- " +
					"a record can be rewritten into another without breaking the chain")
			}
			if ChainHash(GenesisHash, left) == ChainHash(GenesisHash, right) {
				t.Error("two different records hash identically")
			}
		})
	}
}

// TestCanonical_EveryFieldIsCovered: a field left out of the canonical
// bytes can be edited freely without the chain noticing, which is the
// quiet way this control becomes decorative.
func TestCanonical_EveryFieldIsCovered(t *testing.T) {
	for _, tc := range []struct {
		field  string
		mutate func(*Record)
	}{
		{"AnalystIdentity", func(r *Record) { r.AnalystIdentity = "mallory" }},
		{"Tool", func(r *Record) { r.Tool = "casemgmt.get_case" }},
		{"TargetUpstream", func(r *Record) { r.TargetUpstream = "logsearch" }},
		{"Timestamp", func(r *Record) { r.Timestamp = r.Timestamp.Add(time.Hour) }},
		{"Outcome", func(r *Record) { r.Outcome = OutcomeDenied }},
		{"Reason", func(r *Record) { r.Reason = "forbidden" }},
		{"SourceAddress", func(r *Record) { r.SourceAddress = "10.0.0.9" }},
	} {
		t.Run(tc.field, func(t *testing.T) {
			base := chainRec()
			altered := chainRec()
			tc.mutate(&altered)

			if ChainHash(GenesisHash, base) == ChainHash(GenesisHash, altered) {
				t.Errorf("editing %s does not change the hash -- that field is outside the chain "+
					"and can be rewritten undetected", tc.field)
			}
		})
	}
}

// TestChainHash_DependsOnThePredecessor: without this, every record hashes
// independently and reordering or removing one is invisible.
func TestChainHash_DependsOnThePredecessor(t *testing.T) {
	rec := chainRec()
	first := ChainHash(GenesisHash, rec)
	second := ChainHash(first, rec)

	if first == second {
		t.Fatal("the same record hashes identically under different predecessors -- " +
			"the links carry no ordering and a record could be moved or removed undetected")
	}
	if ChainHash(first, rec) != second {
		t.Error("ChainHash is not deterministic")
	}
}

// TestChainCheck_IntactIsAboutTheMiddleOnly documents, in the type's own
// tests, that Intact does not mean complete -- the distinction ADR-0015
// item 6 turns on.
func TestChainCheck_IntactIsAboutTheMiddleOnly(t *testing.T) {
	if !(ChainCheck{Count: 3}).Intact() {
		t.Error("a check with no break should report intact")
	}
	broken := ChainCheck{Count: 3, FirstBreak: &ChainBreak{Position: 2}}
	if broken.Intact() {
		t.Error("a check carrying a break should not report intact")
	}
}
