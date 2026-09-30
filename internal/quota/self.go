package quota

// The one counter read the request path may make (design/adr/0042 item 3).
//
// Store and Reader stay what they are: the Gateway reserves and cannot read,
// the Operator Console reads and cannot reserve. What gatte.status needs is
// narrower than either: how much of each budget the CALLER has spent in
// the current window, so a model can pace itself and tell the user before
// the allowance runs out rather than after. That fact is the caller's own
// activity, told to the caller, and it is nothing they could not count
// themselves from the calls they made. What must stay out of reach is
// every OTHER analyst's counter, and the port below is shaped so that it
// cannot express that question:
//
//   - it is asked about one analyst and a set of charges, and answers one
//     number per charge -- no analyst names, no rows, no windows other than
//     the ones the charges name;
//   - it is reached only through Gate.Standing, whose analyst argument the
//     Gateway fills with the verified subject of the request and nothing
//     else (a fitness function in internal/fitness pins the call site);
//   - it is optional: a Gate without it reports every budget's use as
//     unknown, and nothing is refused because of it.

import (
	"context"
	"errors"
	"slices"
	"time"
)

// SelfReader reads, for ONE analyst, the current count of each charge's
// counter. It returns exactly one number per charge, in order; a counter
// with no row is zero. It is never asked about more than one analyst per
// call, and its answer carries no name at all.
type SelfReader interface {
	SpentBy(ctx context.Context, analyst string, charges []Charge) ([]int, error)
}

// Standing is one budget as its own analyst sees it in gatte.status: the
// declared policy (account, limit, window), the current window's end, and
// the analyst's own count in it, or -1 when it could not be read.
type Standing struct {
	Provider string
	Limit    int
	Window   time.Duration
	Used     int
	ResetsAt time.Time
}

// WithSelf returns a copy of g that answers Standing from r. The Gate on
// the request path is otherwise unchanged: Admit still only reserves.
func (g *Gate) WithSelf(r SelfReader) *Gate {
	cp := *g
	cp.self = r
	return &cp
}

// Standing reports analyst's budgets that any of tools spends, sorted by
// account, with the analyst's own use of each in the window containing
// now. tools is the set the caller was actually served: a budget none of
// their tools spends is not named, so gatte.status never names an account
// the caller's own tool list does not already lead to.
//
// A read failure is not a refusal: the budgets come back with Used = -1,
// and the error is returned alongside for the log. Nothing is debited.
func (g *Gate) Standing(ctx context.Context, analyst string, tools []string, now time.Time) ([]Standing, error) {
	if len(g.plan.providers) == 0 || len(tools) == 0 {
		return nil, nil
	}
	var (
		out     []Standing
		charges []Charge
	)
	for _, p := range g.plan.providers {
		if !slices.ContainsFunc(p.Tools, func(t string) bool { return slices.Contains(tools, t) }) {
			continue
		}
		start := p.WindowStart(now)
		c := Charge{Provider: p.Name, Limit: p.Limit, WindowStart: start, WindowEnd: start.Add(p.Window)}
		charges = append(charges, c)
		out = append(out, Standing{Provider: p.Name, Limit: p.Limit, Window: p.Window, Used: -1, ResetsAt: c.WindowEnd})
	}
	if len(out) == 0 || g.self == nil {
		return out, nil
	}
	if analyst == "" {
		return out, errors.New("quota: standing asked for an empty analyst")
	}
	used, err := g.self.SpentBy(ctx, analyst, charges)
	if err != nil {
		return out, err
	}
	if len(used) != len(out) {
		return out, errors.New("quota: self reader answered a different number of counters than it was asked")
	}
	for i := range out {
		out[i].Used = used[i]
	}
	return out, nil
}
