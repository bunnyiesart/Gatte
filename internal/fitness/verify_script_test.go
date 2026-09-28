package fitness

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyScriptAuditChecksLeaveOutGatewayRows: since design/adr/0032 the
// gateway writes rows about itself on the same tool names a call uses
// (caller "(gateway)", outcome denied, reason "tool first seen: ..."). A
// check in deploy/vm/gateway-serve-verify.sh that asks "was the analyst's
// call audited?" by tool and outcome alone is then satisfied by the
// gateway's own first-seen row and can no longer fail. Every jq line there
// that selects on .outcome must go through $CALLS, the filter that drops
// those rows, or name the caller itself.
//
// And every `tool approve` there names the fingerprint it reviewed: without
// it the command approves nothing and exits 1.
func TestVerifyScriptAuditChecksLeaveOutGatewayRows(t *testing.T) {
	path := filepath.Join(repoRoot(t), "deploy", "vm", "gateway-serve-verify.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), `CALLS='[.[]|select(.analyst_identity!="(gateway)")]'`) {
		t.Errorf("%s does not define the $CALLS filter that drops the gateway's own rows", path)
	}
	for i, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(line, "jq") && strings.Contains(line, ".outcome==") &&
			!strings.Contains(line, `"$CALLS"`) && !strings.Contains(line, "analyst_identity") {
			t.Errorf("%s:%d selects audit rows by outcome without leaving out the (gateway) rows:\n\t%s", path, i+1, trimmed)
		}
		if strings.Contains(line, "tool approve") && !strings.Contains(line, "-fingerprint") {
			t.Errorf("%s:%d runs tool approve without -fingerprint:\n\t%s", path, i+1, trimmed)
		}
	}
}
