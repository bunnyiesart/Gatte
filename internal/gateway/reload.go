package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/internal/quota"
)

// ErrNotServable means an operator named a backend this gateway neither
// has a connection to nor considers servable: not registered, not signed,
// or refused by its own entry.
var ErrNotServable = errors.New("gateway: backend is not servable")

// Policy returns the role policy in force now. It is swapped whole by
// ApplyPolicy, so a caller that holds the pointer holds one coherent
// policy.
func (g *Gateway) Policy() *access.Policy { return g.policy.Load() }

// QuotaPlan returns the quota plan in force now.
func (g *Gateway) QuotaPlan() *quota.Plan { return g.quota.Load().Plan() }

// ApplyPolicy replaces the role policy and the quota gate of a running
// gateway (design/adr/0044). It is the whole of what a reload changes in
// this package.
//
// It refuses, and changes nothing, when the new quota plan and the
// registry disagree (ErrQuotaMisconfigured): a reload must not put the
// gateway in a state the same file would have refused at boot. It also
// refuses while the registry cannot be read, because that agreement
// cannot then be checked.
//
// The swap is one step under the table's lock, and in that same step the
// routes the new plan leaves undeclared are withheld, as Refresh would
// withhold them: between a reload and the next round, no tool of a newly
// budgeted backend is served uncounted. A call already past Authorize
// finishes under the policy it was admitted by; the next one reads the
// new pointer.
func (g *Gateway) ApplyPolicy(ctx context.Context, p *access.Policy, q *quota.Gate) error {
	if p == nil || q == nil {
		return errors.New("gateway: ApplyPolicy needs a policy and a quota gate")
	}
	g.refreshMu.Lock()
	defer g.refreshMu.Unlock()
	if g.isClosed() {
		return ErrClosed
	}
	entries, err := g.registry.List(ctx)
	if err != nil {
		return fmt.Errorf("%w: the quota plan cannot be checked against it: %w", ErrRegistryUnavailable, err)
	}
	if err := CheckQuotaCoverage(q.Plan(), entries); err != nil {
		return err
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	g.policy.Store(p)
	g.quota.Store(q)
	undeclared := UndeclaredQuotaTools(q.Plan(), slices.Collect(maps.Keys(g.routes)))
	for _, tool := range undeclared {
		delete(g.routes, tool)
	}
	g.mu.Unlock()

	if len(undeclared) > 0 {
		g.log.ErrorContext(ctx, "gateway: after the reload, tools of a budgeted upstream are not declared and are not being routed",
			slog.Int("tools", len(undeclared)), slog.String("detail", strings.Join(undeclared, ", ")))
	}
	return nil
}

// RoutedTools returns, sorted, the namespaced name of every tool in the
// routing table: approved or not, live backend or stable listing. It is
// the set a reload's reachability diff is computed over.
func (g *Gateway) RoutedTools() []string {
	return slices.Sorted(maps.Keys(g.snapshot()))
}

// Redial marks the live connection of name for closing and dialling again
// on the next Reconcile (design/adr/0044): for a credential rotated in the
// vault or a container restarted by hand, without restarting the gateway.
//
// From this moment the backend is not live: its calls are answered with
// its state (reconnecting), as for a process found dead, and a (backend
// health) row says why. The re-dial itself is Reconcile's, by the rule
// that re-dials a dead process, so there is one path that closes and
// brings a backend up, and the new process is served only once a Refresh
// has listed it (design/adr/0041 item 4).
//
// connected is false for a servable backend with no live connection: the
// next Reconcile dials it anyway, and nothing is marked. It refuses
// (ErrQuotaMisconfigured) while dials are held back, because the backend
// would be closed and not brought up again, and refuses a name that is
// neither connected nor servable (ErrNotServable).
func (g *Gateway) Redial(ctx context.Context, name string) (connected bool, err error) {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return false, ErrClosed
	}
	up, live := g.conns[name]
	if !live && !g.servable[name] {
		g.mu.Unlock()
		return false, fmt.Errorf("%w: %q", ErrNotServable, name)
	}
	if g.heldBack {
		g.mu.Unlock()
		return false, fmt.Errorf("%w: dials are held back while the quota policy and the registry disagree, so %q would be closed and not brought up again", ErrQuotaMisconfigured, name)
	}
	if !live || g.gone[name] == up {
		g.mu.Unlock()
		return false, nil
	}
	g.gone[name] = up
	var ev *healthEvent
	if _, known := g.health[name]; known {
		ev = g.observeLive(name, false, health.CauseRedial, false, g.now())
	}
	g.mu.Unlock()
	g.writeHealthEvents(ctx, []*healthEvent{ev})
	return true, nil
}

// BackendState is what this process knows of one backend's life: whether
// it is live, why not, and whether it is known at all.
func (g *Gateway) BackendState(name string) (live bool, cause health.Cause, known bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	b, ok := g.health[name]
	if !ok {
		return false, "", false
	}
	return b.live, b.cause, true
}
