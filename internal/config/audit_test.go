package config

import (
	"strings"
	"testing"
)

// -----------------------------------------------------------------------
// [audit.siem] -- the JSONL sink (design/adr/0017-audit-jsonl-siem-sink.md).
//
// Every test here is about the block being present WHOLE or not at all.
// The half-written forms are the ones worth refusing: one of them dies at
// boot inside a package the operator never configured, and the other reads
// as though the trail were shipping and ships nothing.
// -----------------------------------------------------------------------

// TestSIEMBlockLoads is the shape config.example.toml documents.
func TestSIEMBlockLoads(t *testing.T) {
	c := mustLoad(t, completeConfig+`
[audit.siem]
path  = "/var/log/mcp-gateway/audit.jsonl"
chain = "gatte-jail-01"
`)
	if !c.Audit.SIEM.Enabled() {
		t.Error("a file with both keys does not enable the sink")
	}
	if c.Audit.SIEM.Path != "/var/log/mcp-gateway/audit.jsonl" || c.Audit.SIEM.Chain != "gatte-jail-01" {
		t.Errorf("audit.siem = %+v, not what the file says", c.Audit.SIEM)
	}
}

// TestNoSIEMBlockIsTheDefault: the section is optional, and a file without
// it must load exactly as it did before ADR-0017 existed.
func TestNoSIEMBlockIsTheDefault(t *testing.T) {
	c := mustLoad(t, completeConfig)
	if c.Audit.SIEM.Enabled() {
		t.Errorf("a file with no [audit.siem] enables the sink: %+v", c.Audit.SIEM)
	}
}

// TestSIEMPathWithoutChainIsRefused is GAB-30 for the sixth time. jsonl.New
// requires a chain name, so without this rule the file loads, every
// operator subcommand works, and `serve` dies at the next restart with an
// error from a package the operator never wrote a line of.
func TestSIEMPathWithoutChainIsRefused(t *testing.T) {
	err := loadErr(t, completeConfig+`
[audit.siem]
path = "/var/log/mcp-gateway/audit.jsonl"
`)
	msg := err.Error()
	if !strings.Contains(msg, "audit.siem.chain") {
		t.Errorf("the refusal does not name the missing key: %v", err)
	}
	if !strings.Contains(msg, "expect-head") {
		t.Errorf("the refusal does not say what the chain name is for: %v", err)
	}
}

// TestSIEMChainWithoutPathIsRefused is the other half, and it is not
// symmetry for its own sake: that block reads as "this gateway ships its
// trail to the SIEM under this name" and ships nothing. A file that
// describes a control the code does not apply is this project's own defect
// class.
func TestSIEMChainWithoutPathIsRefused(t *testing.T) {
	err := loadErr(t, completeConfig+`
[audit.siem]
chain = "gatte-jail-01"
`)
	if !strings.Contains(err.Error(), "audit.siem.path") {
		t.Errorf("the refusal does not name the missing key: %v", err)
	}
}

// TestSIEMWhitespaceIsRefused: both values are matched verbatim
// downstream -- the path by the shipper's glob, the chain by a Graylog
// query -- so a padded value is a value nobody will ever find.
func TestSIEMWhitespaceIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, block, want string }{
		{
			name:  "path",
			block: "[audit.siem]\npath  = \"/var/log/audit.jsonl \"\nchain = \"gatte-jail-01\"\n",
			want:  "audit.siem.path",
		},
		{
			name:  "chain",
			block: "[audit.siem]\npath  = \"/var/log/audit.jsonl\"\nchain = \" gatte-jail-01\"\n",
			want:  "audit.siem.chain",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := loadErr(t, completeConfig+"\n"+tc.block)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal does not name %s: %v", tc.want, err)
			}
		})
	}
}

// TestSIEMUnknownKeyIsRefused confirms the new section is covered by
// rejectUnknownKeys like every other: a misspelled key in a section that
// controls where the audit trail goes must not be silently dropped.
func TestSIEMUnknownKeyIsRefused(t *testing.T) {
	err := loadErr(t, completeConfig+`
[audit.siem]
path  = "/var/log/mcp-gateway/audit.jsonl"
chain = "gatte-jail-01"
chian = "typo"
`)
	if !strings.Contains(err.Error(), "audit.siem.chian") {
		t.Errorf("a misspelled key in [audit.siem] was not named: %v", err)
	}
}
