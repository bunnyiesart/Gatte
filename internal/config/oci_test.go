package config

import (
	"strings"
	"testing"
)

// [oci] and [upstreams] -- design/adr/0034.

func TestOCISectionIsOptionalAndMeansTheDefaults(t *testing.T) {
	c := mustLoad(t, minimalConfig)
	if c.OCI.User != "" || c.OCI.Memory != "" || c.OCI.PidsLimit != nil || c.OCI.CPUs != nil {
		t.Errorf("an absent [oci] section decoded as %+v, want every field unset (the adapter's defaults)", c.OCI)
	}
	if c.Upstreams.AllowCredentialedStdio {
		t.Error("allow_credentialed_stdio defaults to true; the opt-in must be written")
	}
}

func TestOCISectionIsRead(t *testing.T) {
	c := mustLoad(t, minimalConfig+`
[oci]
user       = "10001:10001"
pids_limit = 128
memory     = "1g"
cpus       = 0.5

[upstreams]
allow_credentialed_stdio = true
`)
	if c.OCI.User != "10001:10001" || c.OCI.Memory != "1g" || c.OCI.PidsLimit == nil || *c.OCI.PidsLimit != 128 ||
		c.OCI.CPUs == nil || *c.OCI.CPUs != 0.5 {
		t.Errorf("[oci] decoded as %+v", c.OCI)
	}
	if !c.Upstreams.AllowCredentialedStdio {
		t.Error("allow_credentialed_stdio = true was not read")
	}
}

// TestOCISectionRefusesWhatWouldBeNoLimitOrRoot: refused at load, so every
// operator subcommand reports it and serve does not discover it later.
func TestOCISectionRefusesWhatWouldBeNoLimitOrRoot(t *testing.T) {
	for _, tc := range []struct{ line, key string }{
		{`user = "0:0"`, "oci.user"},
		{`user = "root"`, "oci.user"},
		{`user = "mcp"`, "oci.user"},
		{`user = "10001"`, "oci.user"},
		{`pids_limit = 0`, "oci.pids_limit"},
		{`pids_limit = -1`, "oci.pids_limit"},
		{`memory = "0"`, "oci.memory"},
		{`memory = "unlimited"`, "oci.memory"},
		{`memory = "5m"`, "oci.memory"},
		{`cpus = 0.0`, "oci.cpus"},
		{`cpus = -1.0`, "oci.cpus"},
	} {
		err := loadErr(t, minimalConfig+"\n[oci]\n"+tc.line+"\n")
		if !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: the refusal does not name %s: %v", tc.line, tc.key, err)
		}
	}
}
