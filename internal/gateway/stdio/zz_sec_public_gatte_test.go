package stdio

// Malformed JSON-RPC from the UPSTREAM side (public Gatte): a child that
// answers the initialize handshake with garbage, with a wrong-id response,
// with a server->client request, or by echoing its injected credential to
// stdout, must fail Dial within the deadline, leave no goroutines behind,
// and not quote the credential in the returned error.

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestSecHostileUpstreamHandshakeFailsCleanly(t *testing.T) {
	scripts := map[string]string{
		"garbage line":             `printf 'not json at all\n'; cat >/dev/null`,
		"echoes its secret":        `printf '%s\n' "leak:$MOCK_SECRET"; cat >/dev/null`,
		"secret inside json":       `printf '{"jsonrpc":"2.0","id":"%s","result":1}\n' "$MOCK_SECRET"; cat >/dev/null`,
		"wrong id result":          `read l; printf '{"jsonrpc":"2.0","id":999,"result":{}}\n'; cat >/dev/null`,
		"error response with leak": `while read l; do id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); [ -n "$id" ] && printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"bad key %s"}}\n' "$id" "$MOCK_SECRET"; done`,
		"exits immediately":        `exit 3`,
		"closes stdout":            `exec 1>&-; sleep 30`,
		"huge line no newline":     `head -c 2000000 /dev/zero | tr '\0' 'A'; cat >/dev/null`,
		"server request flood":     `i=0; while [ $i -lt 200 ]; do printf '{"jsonrpc":"2.0","id":%d,"method":"sampling/createMessage","params":{}}\n' $i; i=$((i+1)); done; cat >/dev/null`,
	}
	// These three never answer the initialize id, so Dial returns only when
	// the context expires: the wait is the deadline itself, and a short one
	// proves the same thing (Dial fails, no leak, goroutines settle).
	hitsDeadline := map[string]bool{"secret inside json": true, "wrong id result": true, "server request flood": true}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			before := runtime.NumGoroutine()
			secret := newSecret(t)
			timeout := 5 * time.Second
			if hitsDeadline[name] {
				timeout = time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			start := time.Now()
			up, err := New(WithShutdownGrace(200*time.Millisecond)).Dial(ctx, gateway.UpstreamSpec{
				Name: "hostile", Transport: "stdio", Command: "/bin/sh", Args: []string{"-c", script},
			}, map[string]string{"MOCK_SECRET": secret})
			elapsed := time.Since(start)
			if err == nil {
				// A handshake that "succeeded" against garbage must at least
				// not produce a usable tool list.
				defs, lerr := up.ListTools(ctx)
				_ = up.Close()
				if lerr == nil && len(defs) > 0 {
					t.Errorf("hostile upstream yielded tools: %v", defs)
				}
				if lerr != nil && strings.Contains(lerr.Error(), secret) {
					t.Errorf("LEAK: ListTools error quotes the injected credential: %v", lerr)
				}
			} else if strings.Contains(err.Error(), secret) {
				t.Errorf("LEAK: Dial error quotes the injected credential: %v", err)
			}
			if elapsed > timeout+time.Second {
				t.Errorf("Dial took %v, past its %v deadline", elapsed, timeout)
			}
			assertGoroutinesSettle(t, before)
		})
	}
}

// TestSecDialErrorCauseIsNotReachable: scrubbing the text is not enough if
// errors.As can still pull the upstream's wire error -- and its message --
// back out of the chain.
func TestSecDialErrorCauseIsNotReachable(t *testing.T) {
	secret := newSecret(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	script := `while read l; do id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]*\).*/\1/p'); [ -n "$id" ] && printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"bad key %s"}}\n' "$id" "$MOCK_SECRET"; done`
	_, err := New(WithShutdownGrace(200*time.Millisecond)).Dial(ctx, gateway.UpstreamSpec{
		Name: "hostile", Transport: "stdio", Command: "/bin/sh", Args: []string{"-c", script},
	}, map[string]string{"MOCK_SECRET": secret})
	if err == nil {
		t.Fatal("Dial succeeded against an upstream that refuses initialize")
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("expected the echoed value to be redacted, got %v", err)
	}
	var wire *jsonrpc.Error
	if errors.As(err, &wire) {
		t.Errorf("the upstream's wire error is still reachable through the chain: %q", wire.Message)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if strings.Contains(e.Error(), secret) {
			t.Errorf("a link in the error chain quotes the injected credential: %v", e)
		}
	}
}
