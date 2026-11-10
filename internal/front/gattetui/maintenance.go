package gattetui

// Planned maintenance of one backend (design/adr/0041, 0055), as a panel of
// the server-detail page. It is an operator action on the operator socket,
// offered only when the backend lists FeatureMaintenance. Gateway-wide
// maintenance is not offered (design/adr/0055 §2).

import (
	"slices"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerDetailPanel(DetailPanel{ID: "maintenance", Order: 40, Rows: maintenancePanel})
}

func maintenancePanel(e env, d adminapi.UpstreamDetail) ([]row, error) {
	if !e.has(adminapi.FeatureMaintenance) {
		return nil, nil
	}
	rows := []row{heading("Maintenance")}
	list, err := e.op.ListMaintenance(ctx())
	if err != nil {
		// No control on a failed read: a start drawn as if nothing were in
		// force would overwrite a maintenance that is.
		return append(rows, textRow(stBad.Render("The maintenance state could not be read: "+vis(errText(err))))), nil
	}
	name := d.Name
	start := action{key: "m", label: "start maintenance", run: func() tea.Cmd { return startMaintenance(e, name) }}
	i := slices.IndexFunc(list.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == name })
	if i < 0 {
		return append(rows, row{text: stOK.Render("Not in maintenance"), actions: []action{start}}), nil
	}
	m := list.Upstreams[i].Maintenance
	text := stWarn.Render("In maintenance") + " since " + showTime(m.StartedAt) + " by " + vis(m.SetBy) + ": " + vis(m.Message)
	if m.Until != nil {
		text += stDim.Render("  until " + showTimePtr(m.Until))
		if m.UntilPassed {
			text += stBad.Render(" (passed)")
		}
	}
	start.label = "update maintenance"
	end := action{key: "e", label: "end maintenance", run: func() tea.Cmd {
		return confirm("End the maintenance of "+vis(name)+"?", func() tea.Cmd {
			return do(func() result {
				res, err := e.op.EndMaintenance(ctx(), adminapi.MaintenanceTarget{Scope: adminapi.ScopeUpstream, Upstream: name})
				return fromAction(res.ActionResult, err, "Ended the maintenance of "+name+".")
			})
		})
	}}
	return append(rows, row{text: text, actions: []action{start, end}}), nil
}

func startMaintenance(e env, name string) tea.Cmd {
	return ask("Message analysts see for "+vis(name), "", func(msg string) tea.Cmd {
		return ask("Ends (empty for no end, 2h, or UTC 2026-09-29T15:00)", "", func(raw string) tea.Cmd {
			until, ok := untilOf(raw, time.Now())
			if !ok {
				return do(func() result {
					return refused("Nothing was sent: the end is not a duration (2h, 90m) or a UTC date and time (2026-09-29T15:00).")
				})
			}
			return do(func() result {
				res, err := e.op.StartMaintenance(ctx(), adminapi.MaintenanceRequest{Scope: adminapi.ScopeUpstream, Upstream: name, Message: msg, Until: until})
				return fromAction(res.ActionResult, err, name+" is in maintenance.")
			})
		})
	})
}

// untilOf reads an end as the web console's form does: empty for none, a
// duration from now, or a UTC time. The range is the backend's to check.
func untilOf(raw string, now time.Time) (*time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, true
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		t := now.Add(d).UTC()
		return &t, true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			t = t.UTC()
			return &t, true
		}
	}
	return nil, false
}
