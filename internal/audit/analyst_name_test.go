package audit

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// pinnedRecord is a record in the format every trail on disk holds today:
// no analyst name. Its hashes below were computed by the code BEFORE
// AnalystName existed (design/adr/0037), and they are written out rather
// than recomputed so that a change to Canonical that re-hashes old rows --
// which would make every existing trail stop verifying -- fails here.
func pinnedRecord() Record {
	return Record{
		AnalystIdentity: "95f757fe-0c7b-4272-9d5e-3f1a2b4c6d8e",
		Tool:            "casemgmt.list_cases",
		TargetUpstream:  "casemgmt",
		Timestamp:       time.Date(2026, 9, 11, 12, 0, 0, 123456789, time.UTC),
		Outcome:         OutcomeDenied,
		Reason:          "forbidden",
		SourceAddress:   "192.0.2.10",
	}
}

const (
	pinnedGenesisHash = "35a7b578421c34e0a65b3c1b409ca87afcefb1c55b21bba5cdc527e8c1513511"
	pinnedSecondHash  = "85cbe199fe816d0c78fa6c941b45393759872ee1c540fa7af44d5588973e3afd"
)

// TestChainHash_AnUnnamedRecordHashesExactlyAsBefore is the compatibility
// half of ADR-0037: a record with no name must encode byte for byte as it
// did under chain v1, or no trail written before this change verifies.
func TestChainHash_AnUnnamedRecordHashesExactlyAsBefore(t *testing.T) {
	r := pinnedRecord()
	first := ChainHash(GenesisHash, r)
	if first != pinnedGenesisHash {
		t.Fatalf("ChainHash(genesis, unnamed) = %s, want the pre-ADR-0037 value %s -- "+
			"existing trails would stop verifying", first, pinnedGenesisHash)
	}
	if got := ChainHash(first, r); got != pinnedSecondHash {
		t.Fatalf("ChainHash(first, unnamed) = %s, want %s", got, pinnedSecondHash)
	}
	if !bytes.HasPrefix(Canonical(r)[8:], []byte("mcp-gateway/audit/chain/v1")) {
		t.Error("an unnamed record is not tagged chain/v1")
	}
}

// TestChainHash_ANamedRecordIsCoveredAndTaggedV2: the name is in the
// chain (editing it must break verification) and a named record is
// domain-separated from every v1 encoding.
func TestChainHash_ANamedRecordIsCoveredAndTaggedV2(t *testing.T) {
	unnamed := pinnedRecord()
	named := pinnedRecord()
	named.AnalystName = "Ana Lyst"

	if ChainHash(GenesisHash, named) == ChainHash(GenesisHash, unnamed) {
		t.Fatal("a named record hashes like the same record unnamed -- the name is outside the chain")
	}
	renamed := named
	renamed.AnalystName = "Mallory"
	if ChainHash(GenesisHash, named) == ChainHash(GenesisHash, renamed) {
		t.Fatal("editing AnalystName does not change the hash")
	}
	if !bytes.HasPrefix(Canonical(named)[8:], []byte("mcp-gateway/audit/chain/v2")) {
		t.Error("a named record is not tagged chain/v2")
	}
	// The name cannot be smuggled across the SourceAddress boundary.
	shifted := pinnedRecord()
	shifted.SourceAddress = unnamed.SourceAddress + "Ana"
	shifted.AnalystName = " Lyst"
	if bytes.Equal(Canonical(shifted), Canonical(named)) {
		t.Error("SourceAddress and AnalystName share a boundary")
	}
}

func TestValidate_AnalystName(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", true},
		{"ascii", "Ana Lyst", true},
		{"accented", "João Conceição", true},
		{"at the bound", strings.Repeat("a", MaxAnalystNameBytes), true},
		{"over the bound", strings.Repeat("a", MaxAnalystNameBytes+1), false},
		{"newline", "Ana\nallowed casemgmt", false},
		{"escape", "Ana\x1b[2J", false},
		{"bidi override", "Ana\u202eLyst", false},
		{"invalid utf-8", "Ana\xff", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validRecord()
			r.AnalystName = tc.in
			err := r.Validate()
			if tc.ok && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() = %v, want ErrInvalid", err)
			}
		})
	}
}

// TestDisplayName is the one rule for what goes into AnalystName: only a
// label that says something the subject does not, made safe to store.
func TestDisplayName(t *testing.T) {
	for _, tc := range []struct {
		name, subject, display, want string
	}{
		{"distinct", "95f757fe", "Ana Lyst", "Ana Lyst"},
		{"trimmed", "95f757fe", "  Ana Lyst ", "Ana Lyst"},
		{"empty", "95f757fe", "", ""},
		{"blank", "95f757fe", "   ", ""},
		{"fallback to subject", "95f757fe", "95f757fe", ""},
		{"hidden characters escaped", "95f757fe", "Ana\u202eLyst", `Ana\u{202E}Lyst`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := DisplayName(tc.subject, tc.display); got != tc.want {
				t.Fatalf("DisplayName(%q, %q) = %q, want %q", tc.subject, tc.display, got, tc.want)
			}
		})
	}

	long := DisplayName("s", strings.Repeat("é", MaxAnalystNameBytes))
	r := validRecord()
	r.AnalystName = long
	if err := r.Validate(); err != nil {
		t.Fatalf("an overlong name is not cut to something Validate accepts: %v (%d bytes)", err, len(long))
	}
	if long == "" {
		t.Fatal("an overlong name was dropped rather than cut")
	}
}
