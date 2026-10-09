package gatteweb

// The Audit page: the trail filtered by the backend, a page at a time, and
// the same filtered rows as a download (design/adr/0046 item 1). Every
// filter is a parameter of GET /v1/audit; the page adds none and skips
// none. A filter the backend does not serve (an older backend without
// feature audit_filters) is refused here rather than sent: listAudit
// ignores a parameter it does not know, and the page would then show the
// whole trail under a filter it did not apply.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// exportMax is the most rows one download carries: ten pages of the
// backend's largest. A download that stops there says so in its file
// name, and the page says to narrow the window.
const exportMax = 10 * maxAuditLimit

type auditData struct {
	Records []adminapi.AuditRecord
	// What the operator typed, shown back in the form.
	Subject, Outcome, Tool, Server, Source, Since, Until string
	Limit                                                int
	Before                                               int
	More                                                 bool
	// Older is the query of the next page back; Filtered the query of the
	// filters alone (for the downloads and the first page). Both are
	// url.Values.Encode output, so already escaped for a query.
	Older, Filtered template.URL
	// Filters: the backend serves tool, server and until.
	Filters   bool
	ExportMax int
}

// auditForm reads the page's query into the backend's query. It refuses a
// time it cannot read and a filter the backend does not serve.
func (f *Front) auditForm(r *http.Request) (auditData, adminapi.AuditQuery, error) {
	q := r.URL.Query()
	d := auditData{Subject: strings.TrimSpace(q.Get("subject")), Outcome: q.Get("outcome"), Tool: strings.TrimSpace(q.Get("tool")),
		Server: strings.TrimSpace(q.Get("server")), Source: strings.TrimSpace(q.Get("source")),
		Since: strings.TrimSpace(q.Get("since")), Until: strings.TrimSpace(q.Get("until")), Limit: auditLimit, ExportMax: exportMax}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		d.Limit = min(n, maxAuditLimit)
	}
	if n, err := strconv.Atoi(q.Get("before")); err == nil && n > 0 {
		d.Before = n
	}
	switch d.Outcome {
	case adminapi.OutcomeAllowed, adminapi.OutcomeDenied, adminapi.OutcomeFailed:
	default:
		d.Outcome = ""
	}
	if me, err := f.op.WhoAmI(r.Context()); err == nil {
		d.Filters = slices.Contains(me.Features, adminapi.FeatureAuditFilters)
	}
	aq := adminapi.AuditQuery{Limit: d.Limit, Before: d.Before, Subject: d.Subject, Outcome: d.Outcome, Source: d.Source}
	var err error
	if aq.Since, err = formTime("From", d.Since); err != nil {
		return d, aq, err
	}
	if !d.Filters && (d.Tool != "" || d.Server != "" || d.Until != "") {
		return d, aq, fmt.Errorf("this management API does not filter by tool, backend or end time (feature %s); clear those fields", adminapi.FeatureAuditFilters)
	}
	aq.Tool, aq.Server = d.Tool, d.Server
	if aq.Until, err = formTime("To", d.Until); err != nil {
		return d, aq, err
	}
	filters := url.Values{}
	for k, v := range map[string]string{"subject": d.Subject, "outcome": d.Outcome, "tool": d.Tool, "server": d.Server,
		"source": d.Source, "since": d.Since, "until": d.Until} {
		if v != "" {
			filters.Set(k, v)
		}
	}
	d.Filtered = template.URL(filters.Encode()) // #nosec G203 -- url.Values.Encode escapes every value
	return d, aq, nil
}

// formTime reads a time field: RFC 3339, or a date or a date and minute
// taken as UTC, which the page says. Empty is no bound.
func formTime(label, v string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%s %q: use 2026-09-30, 2026-09-30 14:00 (UTC) or 2026-09-30T14:00:00Z", label, frontkit.VisibleText(v))
}

func (f *Front) auditPage(w http.ResponseWriter, r *http.Request) {
	d, aq, err := f.auditForm(r)
	if err != nil {
		f.render(w, r, "audit", "Audit trail", page{Data: d, Error: err.Error()})
		return
	}
	p, err := f.op.ListAudit(r.Context(), aq)
	d.Records, d.More = p.Records, p.More
	if p.More && p.NextBefore > 0 {
		older, _ := url.ParseQuery(string(d.Filtered))
		older.Set("before", strconv.Itoa(p.NextBefore))
		older.Set("limit", strconv.Itoa(d.Limit))
		d.Older = template.URL(older.Encode()) // #nosec G203 -- url.Values.Encode escapes every value
	}
	f.render(w, r, "audit", "Audit trail", page{Data: d, Error: errText(err)})
}

// auditExport serves the filtered rows as a download, newest first, from
// as many pages of the backend as it takes, up to exportMax. It changes
// nothing, so GET is right.
func (f *Front) auditExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "csv" && format != "jsonl" {
		http.Error(w, "format must be csv or jsonl", http.StatusBadRequest)
		return
	}
	_, aq, err := f.auditForm(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	aq.Limit, aq.Before = maxAuditLimit, 0
	var rows []adminapi.AuditRecord
	partial := false
	for {
		p, err := f.op.ListAudit(r.Context(), aq)
		if err != nil {
			http.Error(w, errText(err), http.StatusBadGateway)
			return
		}
		// A page is oldest first; the download is newest first.
		for i := len(p.Records) - 1; i >= 0 && len(rows) < exportMax; i-- {
			rows = append(rows, p.Records[i])
		}
		if !p.More || p.NextBefore <= 0 {
			break
		}
		if len(rows) >= exportMax {
			partial = true
			break
		}
		aq.Before = p.NextBefore
	}
	var b bytes.Buffer
	ctype := "text/csv; charset=utf-8"
	if format == "csv" {
		writeAuditCSV(&b, rows)
	} else {
		ctype = "application/x-ndjson; charset=utf-8"
		enc := json.NewEncoder(&b)
		for _, rec := range rows {
			_ = enc.Encode(rec)
		}
	}
	name := "gatte-audit-" + time.Now().UTC().Format("20060102T150405Z")
	if partial {
		name += "-first" + strconv.Itoa(exportMax)
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+"."+format+`"`)
	_, _ = w.Write(b.Bytes()) // #nosec G705 -- an attachment of text/csv or ndjson, with nosniff from frontkit
}

// auditCSVHeader is the CSV's columns, the API's field names.
var auditCSVHeader = []string{"position", "timestamp", "analyst_identity", "analyst_name", "tool", "target_upstream", "outcome", "reason", "source_address"}

// writeAuditCSV writes rows as CSV, every cell through frontkit.CSVCell:
// formula-guarded and with hidden code points written visibly.
func writeAuditCSV(b *bytes.Buffer, rows []adminapi.AuditRecord) {
	cw := csv.NewWriter(b)
	_ = cw.Write(auditCSVHeader)
	for _, r := range rows {
		cells := []string{strconv.Itoa(r.Position), r.Timestamp.UTC().Format(time.RFC3339Nano), r.AnalystIdentity, r.AnalystName,
			r.Tool, r.TargetUpstream, r.Outcome, r.Reason, r.SourceAddress}
		for i, c := range cells {
			cells[i] = frontkit.CSVCell(c)
		}
		_ = cw.Write(cells)
	}
	cw.Flush()
}
