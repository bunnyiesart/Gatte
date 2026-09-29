package gatteweb

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// ---- backends: the registry (read-only: registering and signing stay in
// the terminal, because signing needs root's key), each backend's health,
// and planned maintenance (design/adr/0041), which is an operator action
// like a block.

type backendsData struct {
	Upstreams []adminapi.Upstream
	// Health and Maintenance are the backend's features: a front calls
	// what the backend lists, and an older backend lists neither.
	Health      bool
	Maintenance bool
	// Gateway is the whole gateway's maintenance, when there is one.
	Gateway *adminapi.Maintenance
	// InMaintenance is the backends in maintenance, by name, for an
	// older backend that serves maintenance and not health.
	InMaintenance map[string]adminapi.Maintenance
}

// features asks the backend what it serves. A backend that does not
// answer serves nothing optional.
func (f *Front) features(ctx context.Context) (health, maintenance bool) {
	me, err := f.op.WhoAmI(ctx)
	if err != nil {
		return false, false
	}
	return slices.Contains(me.Features, adminapi.FeatureBackendHealth), slices.Contains(me.Features, adminapi.FeatureMaintenance)
}

func (f *Front) upstreamsPage(w http.ResponseWriter, r *http.Request) {
	list, err := f.op.ListUpstreams(r.Context())
	d := backendsData{Upstreams: list.Upstreams, InMaintenance: map[string]adminapi.Maintenance{}}
	d.Health, d.Maintenance = f.features(r.Context())
	errs := []string{}
	if err != nil {
		errs = append(errs, errText(err))
	}
	if d.Maintenance {
		m, err := f.op.ListMaintenance(r.Context())
		if err != nil {
			errs = append(errs, "maintenance: "+errText(err))
		}
		d.Gateway = m.Gateway
		for _, u := range m.Upstreams {
			d.InMaintenance[u.Upstream] = u.Maintenance
		}
	}
	f.render(w, "upstreams", "Backends", page{Data: d, Error: strings.Join(errs, "\n")})
}

// untilOf reads the form's until: empty for none, a duration from now
// (2h, 90m), an RFC 3339 time, or the browser's datetime-local value,
// which carries no zone and is read as UTC, as the form says. The range
// is the backend's to check.
func untilOf(raw string, now time.Time) (*time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		t := now.Add(d).UTC()
		return &t, true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, raw); err == nil {
			t = t.UTC()
			return &t, true
		}
	}
	return nil, false
}

func maintenanceTitle(scope, upstream string) string {
	if scope == adminapi.ScopeGateway {
		return "the gateway"
	}
	return frontkit.VisibleText(upstream)
}

// formUntil is an announced end as the update form carries it back: RFC
// 3339 in UTC, or empty when there is none or it has passed (the backend
// refuses an end in the past, and the operator is told it passed).
func formUntil(until *time.Time, passed bool) string {
	if until == nil || passed {
		return ""
	}
	return until.UTC().Format(time.RFC3339)
}

// maintenanceServed answers 404 and reports false when the backend does
// not list the maintenance feature: the page shows no form then, and a
// POST that arrives anyway is not forwarded.
func (f *Front) maintenanceServed(w http.ResponseWriter, r *http.Request) bool {
	if _, maintenance := f.features(r.Context()); !maintenance {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (f *Front) maintenanceOn(w http.ResponseWriter, r *http.Request) {
	if !f.maintenanceServed(w, r) {
		return
	}
	scope, upstream := r.PostForm.Get("scope"), r.PostForm.Get("upstream")
	title := "Maintenance of " + maintenanceTitle(scope, upstream)
	until, ok := untilOf(r.PostForm.Get("until"), time.Now())
	if !ok {
		text := "The end time is not a duration (2h, 90m) or a UTC date and time (2026-09-29T15:00)."
		f.showResult(w, "upstreams", title, "/upstreams", result{Summary: text, Output: text})
		return
	}
	res, err := f.op.StartMaintenance(r.Context(), adminapi.MaintenanceRequest{Scope: scope, Upstream: upstream,
		Message: r.PostForm.Get("message"), Until: until})
	f.showResult(w, "upstreams", title, "/upstreams", actionResult(res.ActionResult, err))
}

func (f *Front) maintenanceOff(w http.ResponseWriter, r *http.Request) {
	if !f.maintenanceServed(w, r) {
		return
	}
	scope, upstream := r.PostForm.Get("scope"), r.PostForm.Get("upstream")
	res, err := f.op.EndMaintenance(r.Context(), adminapi.MaintenanceTarget{Scope: scope, Upstream: upstream})
	f.showResult(w, "upstreams", "End the maintenance of "+maintenanceTitle(scope, upstream), "/upstreams", actionResult(res.ActionResult, err))
}

// stateLabel is how a page names a backend state; an unknown one is shown
// as it came.
func stateLabel(s string) string {
	switch s {
	case adminapi.BackendUp:
		return "Up"
	case adminapi.BackendReconnecting:
		return "Reconnecting"
	case adminapi.BackendDown:
		return "Down"
	case adminapi.BackendMaintenance:
		return "In maintenance"
	case adminapi.BackendUnknown:
		return "Unknown"
	}
	return frontkit.VisibleText(s)
}

func showTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return showTime(*t)
}
