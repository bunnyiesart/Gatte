// The boot row: the first row every serving process writes to the trail
// (design/adr/0045 item 3).

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/store"
)

// The boot row's Tool, and the prefix of its Reason. Declared interface
// strings: a SIEM rule matches on them ("which version booted when").
const (
	bootTool         = "(boot)"
	bootReasonPrefix = "boot:"
	gatewayRowActor  = "(gateway)"
)

// bootReason is "boot: mcp-gateway VERSION, schema N". Only this binary's
// own constants: nothing read from the file, the host or a request.
func bootReason() string {
	return fmt.Sprintf("%s mcp-gateway %s, schema %d", bootReasonPrefix, buildIdentity(), store.SchemaVersion)
}

// bootRecord is the row. Attributed to (gateway) like the gateway's other
// rows about itself, so deploy/vm/gateway-serve-verify.sh's $CALLS filter
// and the console's list of analysts leave it out; `allowed` because
// nothing was refused.
func bootRecord(at time.Time) audit.Record {
	return audit.Record{
		AnalystIdentity: gatewayRowActor,
		Tool:            bootTool,
		TargetUpstream:  gatewayRowActor,
		Timestamp:       at,
		Outcome:         audit.OutcomeAllowed,
		Reason:          bootReason(),
	}
}

// recordBoot writes the boot row, retrying while another writer holds the
// file's write lock (an operator command, the management API): nothing
// was written when that is the error, so the retry cannot duplicate it.
func recordBoot(ctx context.Context, rec audit.Recorder, at time.Time) error {
	return retryBusy(ctx, func() error { return rec.Record(ctx, bootRecord(at)) })
}
