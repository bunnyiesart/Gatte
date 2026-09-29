package adminhttp

import (
	"net/http"
	"strconv"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Route is one operation this backend serves, as api/admin.openapi.yaml
// names it. A contract test holds the two to each other.
type Route struct {
	Method      string
	Path        string
	OperationID string
	Sockets     []string
}

type handle func(s *Server, r *request) (int, any, error)

type route struct {
	Route
	h handle
}

var (
	opSock   = []string{adminapi.SocketOperator}
	accSock  = []string{adminapi.SocketAccounts}
	bothSock = []string{adminapi.SocketOperator, adminapi.SocketAccounts}
)

// table is every route. Read-only handlers ignore the actor; state changes
// pass it to the service, which records it.
var table = []route{
	{Route{"GET", "/v1/whoami", "whoAmI", bothSock}, whoami},
	{Route{"GET", "/v1/overview", "overview", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.Overview(r.Context())
		return 200, v, err
	}},
	{Route{"GET", "/v1/tools", "listTools", opSock}, func(s *Server, r *request) (int, any, error) {
		q := r.URL.Query()
		v, err := s.o.Service.ListTools(r.Context(), q.Get("server"), q.Get("show"))
		return 200, v, err
	}},
	{Route{"GET", "/v1/tools/review", "reviewTool", opSock}, func(s *Server, r *request) (int, any, error) {
		q := r.URL.Query()
		v, err := s.o.Service.ReviewTool(r.Context(), q.Get("server"), q.Get("tool"))
		return 200, v, err
	}},
	{Route{"POST", "/v1/tools/approve", "approveTool", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.ApproveRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.ApproveTool(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"POST", "/v1/tools/revoke", "revokeTool", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.ToolRef
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.RevokeTool(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"GET", "/v1/access/blocks", "listBlocks", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.ListBlocks(r.Context())
		return 200, v, err
	}},
	{Route{"POST", "/v1/access/block", "blockSubject", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.BlockRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.Block(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"POST", "/v1/access/unblock", "unblockSubject", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.BlockRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.Unblock(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"GET", "/v1/audit", "listAudit", opSock}, listAudit},
	{Route{"POST", "/v1/audit/verify", "verifyAudit", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.VerifyRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.VerifyAudit(r.Context(), req)
		return 200, v, err
	}},
	{Route{"GET", "/v1/upstreams", "listUpstreams", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.Upstreams(r.Context())
		return 200, v, err
	}},
	{Route{"GET", "/v1/maintenance", "listMaintenance", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.ListMaintenance(r.Context())
		return 200, v, err
	}},
	{Route{"POST", "/v1/maintenance/on", "startMaintenance", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.MaintenanceRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.StartMaintenance(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"POST", "/v1/maintenance/off", "endMaintenance", opSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.MaintenanceTarget
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.EndMaintenance(r.Context(), r.actor, req)
		return 200, v, err
	}},
	{Route{"GET", "/v1/quota", "quotaUsage", opSock}, func(s *Server, r *request) (int, any, error) {
		q := r.URL.Query()
		qq := adminapi.QuotaQuery{Analyst: q.Get("analyst"), Account: q.Get("account")}
		if v := q.Get("since"); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return 0, nil, adminapi.NewError(adminapi.CodeBadRequest, "since must be an RFC 3339 time").With("field", "since")
			}
			qq.Since = t
		}
		v, err := s.o.Service.Quota(r.Context(), qq)
		return 200, v, err
	}},
	{Route{"GET", "/v1/people", "people", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.People(r.Context())
		return 200, v, err
	}},
	{Route{"GET", "/v1/connect", "connect", opSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.Connect(r.Context(), r.URL.Query().Get("username"))
		return 200, v, err
	}},
	{Route{"GET", "/v1/connect/script", "connectScript", opSock}, func(s *Server, r *request) (int, any, error) {
		q := r.URL.Query()
		sc, err := s.o.Service.ConnectScript(r.Context(), q.Get("os"), q.Get("username"))
		if err != nil {
			return 0, nil, err
		}
		r.w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		r.w.Header().Set("Content-Disposition", `attachment; filename="`+sc.Filename+`"`)
		r.w.WriteHeader(200)
		_, _ = r.w.Write([]byte(sc.Content))
		return 0, nil, nil
	}},
	{Route{"GET", "/v1/groups", "assignableGroups", accSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.AssignableGroups(r.Context())
		return 200, v, err
	}},
	{Route{"GET", "/v1/accounts", "listAccounts", accSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.Accounts(r.Context())
		return 200, v, err
	}},
	{Route{"POST", "/v1/accounts", "addAccount", accSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.NewAccount
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.AddAccount(r.Context(), r.actor, req)
		return 201, v, err
	}},
	{Route{"POST", "/v1/account-check", "checkAccount", accSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.AccountDraft
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.CheckAccount(r.Context(), req)
		return 200, v, err
	}},
	{Route{"GET", "/v1/accounts/{username}", "getAccount", accSock}, func(s *Server, r *request) (int, any, error) {
		v, err := s.o.Service.Account(r.Context(), r.PathValue("username"))
		return 200, v, err
	}},
	{Route{"POST", "/v1/accounts/{username}/groups", "setAccountGroups", accSock}, func(s *Server, r *request) (int, any, error) {
		var req adminapi.GroupsRequest
		if err := r.decode(&req); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.SetAccountGroups(r.Context(), r.actor, r.PathValue("username"), req)
		return 200, v, err
	}},
	{Route{"POST", "/v1/accounts/{username}/disable", "disableAccount", accSock}, setDisabled(true)},
	{Route{"POST", "/v1/accounts/{username}/enable", "enableAccount", accSock}, setDisabled(false)},
	{Route{"POST", "/v1/accounts/{username}/reset-password", "resetAccountPassword", accSock}, func(s *Server, r *request) (int, any, error) {
		var none struct{}
		if err := r.decode(&none); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.ResetAccountPassword(r.Context(), r.actor, r.PathValue("username"))
		return 200, v, err
	}},
}

func setDisabled(disabled bool) handle {
	return func(s *Server, r *request) (int, any, error) {
		var none struct{}
		if err := r.decode(&none); err != nil {
			return 0, nil, err
		}
		v, err := s.o.Service.SetAccountDisabled(r.Context(), r.actor, r.PathValue("username"), disabled)
		return 200, v, err
	}
}

func whoami(s *Server, r *request) (int, any, error) {
	return 200, adminapi.WhoAmI{
		APIVersions:     []string{"v1"},
		ContractVersion: adminapi.ContractVersion,
		// A front asks for a feature, not a version.
		Features:       []string{adminapi.FeatureMaintenance, adminapi.FeatureBackendHealth},
		GatewayVersion: s.o.GatewayVersion,
		Socket:         s.o.Socket,
		ConfigPath:     s.o.ConfigPath,
		Operator:       adminapi.Operator{UID: r.peer.uid, Name: r.peer.name, Identity: admin.OperatorIdentity(r.peer.name), Via: r.peer.via},
		Front:          r.front,
	}, nil
}

func listAudit(s *Server, r *request) (int, any, error) {
	q := r.URL.Query()
	aq := adminapi.AuditQuery{Subject: q.Get("subject"), Outcome: q.Get("outcome"), Source: q.Get("source")}
	for _, f := range []struct {
		name string
		dst  *int
	}{{"limit", &aq.Limit}, {"before", &aq.Before}} {
		if v := q.Get(f.name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return 0, nil, adminapi.NewError(adminapi.CodeBadRequest, "%s must be a positive integer", f.name).With("field", f.name)
			}
			*f.dst = n
		}
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return 0, nil, adminapi.NewError(adminapi.CodeBadRequest, "since must be an RFC 3339 time").With("field", "since")
		}
		aq.Since = t
	}
	v, err := s.o.Service.Audit(r.Context(), aq)
	return 200, v, err
}

// Routes lists every route served, on either socket.
func Routes() []Route {
	out := make([]Route, 0, len(table))
	for _, r := range table {
		out = append(out, r.Route)
	}
	return out
}

// routes builds this server's mux: every path of the table, dispatched by
// method, answering wrong_socket for the other socket's routes and
// unknown_route for anything else.
func (s *Server) routes() *http.ServeMux {
	byPath := map[string]map[string]route{}
	var order []string
	for _, r := range table {
		if byPath[r.Path] == nil {
			byPath[r.Path] = map[string]route{}
			order = append(order, r.Path)
		}
		byPath[r.Path][r.Method] = r
	}
	mux := http.NewServeMux()
	for _, path := range order {
		methods := byPath[path]
		mux.HandleFunc(path, func(w http.ResponseWriter, hr *http.Request) {
			rt, ok := methods[hr.Method]
			if !ok {
				writeErr(w, adminapi.NewError(adminapi.CodeMethodNotAllowed, "%s is not served on %s", hr.Method, hr.URL.Path))
				return
			}
			if !contains(rt.Sockets, s.o.Socket) {
				writeErr(w, adminapi.NewError(adminapi.CodeWrongSocket, "%s %s is served by the %s socket", hr.Method, path, rt.Sockets[0]).With("socket", rt.Sockets[0]))
				return
			}
			p := hr.Context().Value(peerKey{}).(*peer)
			front := hr.Header.Get(adminapi.FrontHeader)
			req := &request{Request: hr, w: w, peer: p, front: front,
				actor: admin.Actor{Name: p.name, Via: p.via, Front: front, Root: p.uid == 0}}
			status, body, err := rt.h(s, req)
			if err != nil {
				writeErr(w, err)
				return
			}
			if status != 0 {
				writeJSON(w, status, body)
			}
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, hr *http.Request) {
		writeErr(w, adminapi.NewError(adminapi.CodeUnknownRoute, "no route %s %s in this backend (older backend, or wrong path)", hr.Method, hr.URL.Path))
	})
	return mux
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
