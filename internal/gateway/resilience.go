package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
)

// Call-path resilience (design/adr/0035-resiliencia-do-caminho-de-chamada.md).

var (
	// ErrInternal means a call ended in a panic inside this process. The
	// panic was contained to that call and audited as a failure; the
	// caller is told nothing more, because a panic value is whatever the
	// code that panicked had in hand.
	ErrInternal = errors.New("gateway: internal error")

	// ErrConcurrencyLimited means the caller already has
	// max_concurrent_calls_per_analyst calls in flight. The call was
	// refused at once, with no queue, before the quota was debited and
	// before the allowed row was written.
	ErrConcurrencyLimited = errors.New("gateway: too many calls in flight for this analyst")
)

// Reasons ADR-0035 adds to the trail. Declared interface strings, like the
// others in endpoint.go.
const (
	// reasonInternalError is a call that panicked inside the gateway. The
	// same words as the client's constant message, so an analyst's report
	// and the operator's grep land on the same string.
	reasonInternalError = "internal error"
	// reasonConcurrencyLimited is a call refused because the analyst
	// already held every slot the cap allows.
	reasonConcurrencyLimited = "concurrency limited"
)

// DefaultMaxConcurrentCallsPerAnalyst is the cap an unconfigured gateway
// applies (response.max_concurrent_calls_per_analyst).
//
// Four: an analyst's agent that fans out a few lookups at once is ordinary
// work and fits; a loop or a stolen token opening dozens is not, and each
// of its calls may hold a shared backend process for up to call_timeout.
// It is a guess about one fleet of seven analysts, raised in the file when
// it is wrong.
const DefaultMaxConcurrentCallsPerAnalyst = 4

// callSlots counts calls in flight per subject. There is no queue: a call
// that finds every slot taken is refused, because a queue would hold the
// request goroutine anyway and only move where the pile-up happens.
type callSlots struct {
	max   int
	mu    sync.Mutex
	inUse map[string]int
}

func newCallSlots(max int) *callSlots {
	return &callSlots{max: max, inUse: map[string]int{}}
}

// acquire takes one slot for subject, reporting false when there is none.
// The returned func gives it back and must be called exactly once.
func (s *callSlots) acquire(subject string) (release func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inUse[subject] >= s.max {
		return nil, false
	}
	s.inUse[subject]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			// Deleted at zero so the map holds only subjects with a call in
			// flight, not every subject this process ever saw.
			if s.inUse[subject]--; s.inUse[subject] <= 0 {
				delete(s.inUse, subject)
			}
		})
	}, true
}

// containPanic is deferred first in Dispatch. A panic anywhere in the call
// -- an adapter, the scrub, a store -- ends that one call instead of the
// process: it is audited, and the caller gets ErrInternal.
//
// The row follows the trail's own rule (ADR-0012): before the allowed row
// was written nothing was dispatched, so it is a denial; after it, the
// failed row annotates the allowed one, as for any call that did not come
// back. Both carry reasonInternalError.
//
// The panic value is never logged or returned. It is whatever the code
// that panicked had in hand -- an upstream's error text, a credential --
// and this is the process that holds every backend's key. The log gets the
// value's type and the stack, which carries no string contents.
func (g *Gateway) containPanic(ctx context.Context, c Caller, tool string, dispatched *bool, res *Result, err *error) {
	r := recover()
	if r == nil {
		return
	}
	g.recordPanic(ctx, c, tool, targetOf(tool), *dispatched, r)
	*res = Result{}
	*err = ErrInternal
}

// RecordPanic is containPanic for a serving adapter: a panic it recovered
// in its own code, outside Dispatch, is written to the trail here so that
// every record keeps a single writer (see RecordRefusedProbe).
//
// dispatched says whether Dispatch already returned for this call, i.e.
// whether an allowed row exists that this one annotates. tool may be
// empty for a request that had not named one; it is then recorded as
// aimed at the gateway itself.
func (g *Gateway) RecordPanic(ctx context.Context, c Caller, tool string, dispatched bool, value any) {
	upstream := gatewayItself
	if strings.TrimSpace(tool) == "" {
		tool = requestTool
	} else {
		upstream = targetOf(tool)
	}
	g.recordPanic(ctx, c, tool, upstream, dispatched, value)
}

// requestTool is the Tool of a panic recovered while serving a request
// that had not reached a tool: authentication, listing, the protocol layer.
const requestTool = "(request)"

func (g *Gateway) recordPanic(ctx context.Context, c Caller, tool, upstream string, dispatched bool, value any) {
	g.log.ErrorContext(ctx, "gateway: recovered a panic; the call was refused and the process keeps serving",
		slog.String("subject", c.Identity.Subject),
		slog.String("tool", tool),
		slog.String("panic_type", fmt.Sprintf("%T", value)),
		slog.String("stack", string(debug.Stack())),
	)
	if strings.TrimSpace(c.Identity.Subject) == "" {
		c.Identity.Subject = unauthenticatedIdentity
	}
	if !dispatched {
		g.auditRefusal(ctx, c, tool, upstream, reasonInternalError)
		return
	}
	g.auditFailure(ctx, c, tool, upstream, ErrInternal)
}
