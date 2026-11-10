package gatteweb

// Planned maintenance of one backend (design/adr/0041, 0055), as the
// server-detail panel at DetailPanel Order 40. It is an operator action like a
// block, on the operator socket, so it needs neither the managing console nor
// the accounts socket: only the backend listing FeatureMaintenance. The
// gateway-wide maintenance is not offered here (design/adr/0055 §2).

import (
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

type maintenancePanelData struct {
	Server     string
	Base, CSRF string
	// Current is the backend's maintenance in force, nil when there is none.
	Current *adminapi.Maintenance
	ReadErr string
}

// maintenancePanel draws the start / update / end controls for one backend, or
// nothing when the backend does not serve maintenance. The state comes from the
// maintenance list rather than the health block, so a backend that serves
// maintenance without health still shows it. A failed read shows no form: a
// start drawn as if nothing were in force would overwrite a maintenance that is.
func (f *Front) maintenancePanel(r *http.Request, d adminapi.UpstreamDetail) (template.HTML, error) {
	if !f.feature(r.Context(), adminapi.FeatureMaintenance) {
		return "", nil
	}
	data := maintenancePanelData{Server: d.Name, Base: f.kit.Base(), CSRF: f.kit.CSRFToken()}
	list, err := f.op.ListMaintenance(r.Context())
	if err != nil {
		data.ReadErr = errText(err)
	}
	if i := slices.IndexFunc(list.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == d.Name }); i >= 0 {
		data.Current = &list.Upstreams[i].Maintenance
	}
	return f.renderFragment("panel_maintenance.html", data)
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
	if !f.feature(r.Context(), adminapi.FeatureMaintenance) {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (f *Front) maintenanceOn(w http.ResponseWriter, r *http.Request) {
	if !f.maintenanceServed(w, r) {
		return
	}
	name := r.PathValue("name")
	title := "Maintenance of " + frontkit.VisibleText(name)
	until, ok := untilOf(r.PostForm.Get("until"), time.Now())
	if !ok {
		text := "The end time is not a duration (2h, 90m) or a UTC date and time (2026-09-29T15:00)."
		f.showResult(w, r, "servers", title, serverBack(name), result{Summary: text, Output: text})
		return
	}
	res, err := f.op.StartMaintenance(r.Context(), adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: name,
		Message: r.PostForm.Get("message"), Until: until})
	f.showResult(w, r, "servers", title, serverBack(name), actionResult(res.ActionResult, err))
}

func (f *Front) maintenanceOff(w http.ResponseWriter, r *http.Request) {
	if !f.maintenanceServed(w, r) {
		return
	}
	name := r.PathValue("name")
	res, err := f.op.EndMaintenance(r.Context(), adminapi.MaintenanceTarget{Scope: adminapi.ScopeUpstream, Upstream: name})
	f.showResult(w, r, "servers", "End the maintenance of "+frontkit.VisibleText(name), serverBack(name), actionResult(res.ActionResult, err))
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
