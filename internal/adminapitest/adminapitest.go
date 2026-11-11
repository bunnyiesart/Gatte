// Package adminapitest is a seeded, in-memory fake of Gatte's management API
// (api/admin.openapi.yaml, pkg/adminapi). It serves the operator and accounts
// route surface with realistic sample rows for every entity, including empty
// and error states, and mutates that state so a caller sees its own CRUD take
// effect.
//
// It opens no real socket of the running service, no database, no backend and
// no vault; it holds no real secret and makes no network call. Both frontend
// tracks (the web console and the TUI) and the mock console preview
// (cmd/gatte-preview) build on it, so neither needs a running gateway to be
// developed or tested.
//
// Use Handler for an http.Handler, or Start to run it on a temporary UNIX
// socket and get pkg/adminapi clients wired to it.
package adminapitest

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// base is the fixed reference time the seed is built around, so tests that
// read it are deterministic.
var base = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

// Operator-row labels, as the real backend writes them in an audit row's Tool
// field (internal/admin). A frontend only displays whatever the backend
// returns, so the fake just has to produce the same strings.
const (
	rowToolApprove        = "(tool approve)"
	rowToolApproveSet     = "(tool approve set)"
	rowToolRevoke         = "(tool revoke)"
	rowToolClear          = "(tool clear)"
	rowAccessBlock        = "(access block)"
	rowAccessUnblock      = "(access unblock)"
	rowAccountAdd         = "(account add)"
	rowAccountGroups      = "(account groups)"
	rowAccountDisable     = "(account disable)"
	rowAccountEnable      = "(account enable)"
	rowAccountReset       = "(account reset password)"
	rowAccountDelete      = "(account delete)"
	rowAccountOffboard    = "(account offboard)"
	rowUpstreamUpdate     = "(upstream update)"
	rowUpstreamDeregister = "(upstream deregister)"
	rowUpstreamSign       = "(upstream sign)"
	rowSecretSet          = "(secret set)"
	rowSecretDelete       = "(secret delete)"
	rowRolesWrite         = "(roles write)"
	rowMaintenanceOn      = "(maintenance on)"
	rowMaintenanceOff     = "(maintenance off)"
)

// Server is a fake management API. It is safe for concurrent use. The zero
// value is not usable; call New.
type Server struct {
	mu sync.Mutex

	operator adminapi.Operator
	features []string

	tools       []adminapi.Tool
	definitions map[string]definition // keyed by server+"\x00"+tool
	blocks      []adminapi.Block
	audit       []adminapi.AuditRecord
	upstreams   []*adminapi.UpstreamDetail
	secrets     map[string]*adminapi.Secret
	secretOrder []string
	roles       adminapi.RolesText
	maint       adminapi.MaintenanceList
	accounts    map[string]*adminapi.Account
	acctOrder   []string
	groups      []adminapi.AssignableGroup
	people      adminapi.People
	peopleReads int // GET /v1/people answered: the read that touches the trail
	quota       []adminapi.QuotaUsage

	serveReqs map[int64]adminapi.ServeRequest
	nextServe int64

	mux *http.ServeMux
}

// definition holds the observed (and optionally approved) tool definition a
// review shows.
type definition struct {
	observed adminapi.Definition
	approved *adminapi.Definition
	diff     []adminapi.DiffLine
	callable []adminapi.RoleCoverage
}

// New returns a fake seeded with sample data for every entity.
func New() *Server {
	s := &Server{
		serveReqs: map[int64]adminapi.ServeRequest{},
	}
	s.seed()
	s.routes()
	return s
}

// PeopleReads is how many times GET /v1/people was answered. That is the
// read for which the real gateway reads the audit trail; a front that shows
// roles only must leave it at zero.
func (s *Server) PeopleReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peopleReads
}

// Handler is the fake's HTTP surface. Mount it on a listener, or serve it from
// an httptest server, to back a pkg/adminapi client.
func (s *Server) Handler() http.Handler { return s.mux }

// ServeHTTP lets a Server be used directly as an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, e *adminapi.Error) {
	writeJSON(w, e.Status, adminapi.ErrorResponse{Error: e})
}

// decode reads a JSON body into v, answering bad_request on malformed input.
// An empty body is allowed (v is left at its zero value).
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, adminapi.NewError(adminapi.CodeBadRequest, "malformed JSON body: %v", err))
		return false
	}
	return true
}

// row builds the operator audit row an action reports back.
func (s *Server) row(tool, reason string) *adminapi.OperatorRow {
	return &adminapi.OperatorRow{
		Identity:  s.operator.Identity,
		Tool:      tool,
		Reason:    reason + " [ui]",
		Timestamp: base.Add(72 * time.Hour),
	}
}
