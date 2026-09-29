package admin

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/bunnyiesart/Gatte/internal/health"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Backend health for the fronts (design/adr/0041 item 7). The management
// backend is another process than serve and cannot see its memory, so it
// reads what serve last wrote -- one row per backend and one about serve
// itself -- and merges the maintenance rows in. The public state is
// derived as the gateway derives it for a caller (gateway.publicState):
// maintenance, else up when live, else down when dials are held back,
// else reconnecting. What serve wrote says nothing current once serve has
// stopped reporting, so every backend is then unknown.

// serveState is serve's state at now: running when a round completed
// within twice the round interval plus the grace (the reconciliation
// timeout: a round may take that long), not reporting otherwise.
func serveState(st health.ServeStatus, found bool, now time.Time, grace time.Duration) adminapi.ServeStatus {
	if !found {
		return adminapi.ServeStatus{State: adminapi.ServeNeverReported}
	}
	boot, last := st.Boot.UTC(), st.LastRoundAt.UTC()
	out := adminapi.ServeStatus{State: adminapi.ServeRunning, Boot: &boot, LastRoundAt: &last,
		RoundIntervalSeconds: int(st.RoundInterval / time.Second)}
	if now.Sub(st.LastRoundAt) > 2*st.RoundInterval+grace {
		out.State = adminapi.ServeNotReporting
	}
	return out
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// backendHealth merges what serve wrote about name (rec, nil when it wrote
// nothing) with its maintenance (m, nil when none).
func backendHealth(name string, rec *health.BackendRecord, m *health.Maintenance, serveRunning bool, now time.Time) adminapi.BackendHealth {
	out := adminapi.BackendHealth{Name: name, State: adminapi.BackendUnknown}
	if m != nil {
		out.Maintenance = toAPIMaintenance(*m, now)
	}
	if rec != nil && serveRunning {
		out.Live, out.Since, out.LastAttempt = rec.Live, timePtr(rec.Since), timePtr(rec.LastAttempt)
		if !rec.Live {
			out.Cause, out.NextAttempt = string(rec.Cause), timePtr(rec.NextAttempt)
		}
		switch {
		case rec.Live:
			out.State = adminapi.BackendUp
		case rec.Cause == health.CauseHeldBack:
			out.State = adminapi.BackendDown
		default:
			out.State = adminapi.BackendReconnecting
		}
	}
	if m != nil {
		out.State = adminapi.BackendMaintenance
	}
	return out
}

// health reads the health of every backend in names. An error names the
// part that could not be read.
func (s *Service) health(ctx context.Context, names []string) (*adminapi.Health, string, error) {
	now := s.d.Now()
	st, found, err := s.d.Health.Serve(ctx)
	if err != nil {
		return nil, "health", err
	}
	recs, err := s.d.Health.Backends(ctx)
	if err != nil {
		return nil, "health", err
	}
	var rows []health.Maintenance
	if s.d.Maintenance != nil {
		if rows, err = s.d.Maintenance.Maintenance(ctx); err != nil {
			return nil, "maintenance", err
		}
	}
	out := &adminapi.Health{Serve: serveState(st, found, now, s.d.ServeGrace), Backends: []adminapi.BackendHealth{}}
	running := out.Serve.State == adminapi.ServeRunning
	byName := map[string]*health.BackendRecord{}
	for i := range recs {
		byName[recs[i].Backend] = &recs[i]
	}
	maint := map[string]*health.Maintenance{}
	for i := range rows {
		if rows[i].Target == health.GatewayTarget {
			out.GatewayMaintenance = toAPIMaintenance(rows[i], now)
			continue
		}
		maint[rows[i].Target] = &rows[i]
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	for _, name := range slices.Compact(sorted) {
		out.Backends = append(out.Backends, backendHealth(name, byName[name], maint[name], running, now))
	}
	return out, "", nil
}

// healthAttention is what the health adds to the overview's attention
// list: serve not reporting (first), the backends not up, the backends in
// maintenance, and the gateway's maintenance (last).
func healthAttention(h *adminapi.Health) (first, backends, last []adminapi.Attention) {
	if h.Serve.State == adminapi.ServeNotReporting {
		detail := "The gateway process has not completed a round since " + h.Serve.LastRoundAt.Format(time.RFC3339) +
			". It may be stopped: check its service. What the console shows about backends is not current."
		first = append(first, adminapi.Attention{Kind: adminapi.AttentionServeNotReporting, Title: "The gateway process is not reporting", Detail: detail})
	}
	var inMaint []adminapi.Attention
	for _, b := range h.Backends {
		switch b.State {
		case adminapi.BackendReconnecting:
			backends = append(backends, adminapi.Attention{Kind: adminapi.AttentionBackendUnavailable, Title: b.Name, Upstream: b.Name,
				Detail: fmt.Sprintf("Not connected since %s; the gateway is reconnecting it. Analysts are told it is unavailable.", showSince(b.Since))})
		case adminapi.BackendDown:
			backends = append(backends, adminapi.Attention{Kind: adminapi.AttentionBackendUnavailable, Title: b.Name, Upstream: b.Name,
				Detail: fmt.Sprintf("Not connected since %s and not being reconnected: the quota and the registry disagree. Analysts are told an operator has to act.", showSince(b.Since))})
		case adminapi.BackendMaintenance:
			inMaint = append(inMaint, adminapi.Attention{Kind: adminapi.AttentionBackendMaintenance, Title: b.Name, Upstream: b.Name,
				Detail: "In planned maintenance: its calls are answered with the message and not sent to it, until the maintenance is ended."})
		}
	}
	backends = append(backends, inMaint...)
	if h.GatewayMaintenance != nil {
		last = append(last, adminapi.Attention{Kind: adminapi.AttentionGatewayMaintenance, Title: "The gateway is in planned maintenance",
			Detail: "Calls are still served; analysts see the notice until the maintenance is ended."})
	}
	return first, backends, last
}

func showSince(t *time.Time) string {
	if t == nil {
		return "an unknown time"
	}
	return t.Format(time.RFC3339)
}
