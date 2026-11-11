package adminapitest

import (
	"cmp"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func (s *Server) listUpstreams(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := adminapi.UpstreamList{Upstreams: make([]adminapi.Upstream, 0, len(s.upstreams))}
	for _, u := range s.upstreams {
		out.Upstreams = append(out.Upstreams, u.Upstream)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getUpstream(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.findUpstream(name(r))
	if u == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no backend %q", name(r)))
		return
	}
	d := *u
	d.Tools = s.toolsOf(u.Name)
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) registerUpstream(w http.ResponseWriter, r *http.Request) {
	var req adminapi.RegisterUpstreamRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if req.Name == "" {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "register must name the backend"))
		return
	}
	if s.findUpstream(req.Name) != nil {
		writeErr(w, adminapi.NewError(adminapi.CodeUpstreamExists, "a backend named %q is already registered", req.Name))
		return
	}
	if req.Transport != adminapi.UpstreamTransportRemote && req.RemoteKind != "" {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "remote_kind is not a field of a %s backend", cmp.Or(req.Transport, "http")).With("field", "remote_kind"))
		return
	}
	switch req.Transport {
	case adminapi.UpstreamTransportOCI:
		s.registerOCI(w, req)
		return
	case adminapi.UpstreamTransportRemote:
		s.registerRemote(w, req)
		return
	}
	auth := adminapi.UpstreamAuth{Kind: req.AuthKind, Name: req.AuthName, Secret: req.KeyName}
	if auth.Kind == "" {
		auth.Kind = "none"
	}
	now := base.Add(72 * time.Hour)
	ops := []adminapi.UpstreamOperation{{Name: "get_item", Method: "GET", Path: "/items/{id}", Class: adminapi.ClassSafe}}
	env := []string{}
	if req.KeyName != "" {
		env = append(env, req.KeyName)
	}
	u := &adminapi.UpstreamDetail{
		Upstream: adminapi.Upstream{Name: req.Name, Transport: "http", URL: req.URL, Network: "egress-guarded",
			EnvVarNames: env, Signature: "no", CreatedAt: now, UpdatedAt: now,
			Health: &adminapi.BackendHealth{Name: req.Name, State: adminapi.BackendUnknown}},
		Auth: &auth, Operations: ops, OperationsSHA256: "sha256:" + req.Name,
	}
	s.upstreams = append(s.upstreams, u)
	s.tools = append(s.tools, adminapi.Tool{Server: req.Name, Tool: "get_item", Status: adminapi.StatusPending,
		ObservedHash: "sha256:new-" + req.Name, FirstSeenAt: now, UpdatedAt: now})
	s.definitions[key(req.Name, "get_item")] = definition{observed: textDef("get_item", "Fetch one item.", "sha256:new-"+req.Name)}

	res := adminapi.RegisterUpstreamResult{Name: req.Name, Transport: "http", URL: req.URL, Source: "document",
		Auth: auth, Tools: ops, Skipped: []string{}, IngestWarnings: []string{}, Signature: "no"}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"registered " + req.Name}
	res.Audit = s.row(rowUpstreamUpdate, "register "+req.Name)
	writeJSON(w, http.StatusOK, res)
}

// registerOCI is the fake's oci register: a digest pin and a network from
// --network=VALUE, nothing more; the real rules are the backend's. Called
// with s.mu held.
func (s *Server) registerOCI(w http.ResponseWriter, req adminapi.RegisterUpstreamRequest) {
	if !strings.Contains(req.Image, "@sha256:") {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "image %q is not pinned by digest: use NAME@sha256:<64 hex>", req.Image).With("field", "image"))
		return
	}
	network := "none"
	for _, a := range req.Args {
		if v, ok := strings.CutPrefix(a, "--network="); ok {
			network = v
		}
	}
	env := slices.Clone(req.EnvVarNames)
	if env == nil {
		env = []string{}
	}
	now := base.Add(72 * time.Hour)
	s.upstreams = append(s.upstreams, &adminapi.UpstreamDetail{
		Upstream: adminapi.Upstream{Name: req.Name, Transport: "oci", Image: req.Image, Args: slices.Clone(req.Args), Network: network,
			EnvVarNames: env, Signature: "no", CreatedAt: now, UpdatedAt: now,
			Health: &adminapi.BackendHealth{Name: req.Name, State: adminapi.BackendUnknown}},
	})
	res := adminapi.RegisterUpstreamResult{Name: req.Name, Transport: "oci", Image: req.Image, Network: network, EnvVarNames: env,
		Auth: adminapi.UpstreamAuth{Kind: "none"}, Tools: []adminapi.UpstreamOperation{}, Skipped: []string{}, IngestWarnings: []string{}, Signature: "no"}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"registered " + req.Name}
	res.Audit = s.row(rowUpstreamUpdate, "register "+req.Name)
	writeJSON(w, http.StatusOK, res)
}

// registerRemote is the fake's remote register. It refuses, by field, what
// the backend refuses from the console's form, so a front tested here sees
// the refusals it will see in production; no message repeats a value.
// Called with s.mu held.
func (s *Server) registerRemote(w http.ResponseWriter, req adminapi.RegisterUpstreamRequest) {
	if err := remoteRefusal(req); err != nil {
		writeErr(w, err)
		return
	}
	auth := adminapi.UpstreamAuth{Kind: req.AuthKind, Name: req.AuthName, Secret: req.KeyName}
	env := []string{}
	if auth.Kind == "" || auth.Kind == "none" {
		auth = adminapi.UpstreamAuth{Kind: "none"}
	} else {
		env = append(env, req.KeyName)
	}
	kind := req.RemoteKind
	if kind == "" {
		kind = adminapi.RemoteKindStreamable
	}
	now := base.Add(72 * time.Hour)
	s.upstreams = append(s.upstreams, &adminapi.UpstreamDetail{
		Upstream: adminapi.Upstream{Name: req.Name, Transport: "remote", URL: req.URL, RemoteKind: kind, Network: "host",
			EnvVarNames: env, Signature: "no", CreatedAt: now, UpdatedAt: now,
			Health: &adminapi.BackendHealth{Name: req.Name, State: adminapi.BackendUnknown}},
		Auth: &auth,
	})
	res := adminapi.RegisterUpstreamResult{Name: req.Name, Transport: "remote", URL: req.URL, RemoteKind: kind, EnvVarNames: env,
		Auth: auth, Tools: []adminapi.UpstreamOperation{}, Skipped: []string{}, IngestWarnings: []string{}, Signature: "no"}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"registered " + req.Name}
	res.Audit = s.row(rowUpstreamUpdate, "register "+req.Name)
	writeJSON(w, http.StatusOK, res)
}

// remoteRefusal mirrors the backend's remote register rules the console can
// reach: foreign fields, the URL, the auth descriptor and the remote kind.
func remoteRefusal(req adminapi.RegisterUpstreamRequest) *adminapi.Error {
	invalid := func(field, msg string) *adminapi.Error {
		return adminapi.NewError(adminapi.CodeInvalidArgument, "%s", msg).With("field", field)
	}
	for _, f := range []struct {
		field string
		set   bool
	}{{"args", len(req.Args) > 0}, {"env_var_names", len(req.EnvVarNames) > 0}, {"image", req.Image != ""},
		{"openapi_document", req.OpenAPIDocument != ""}, {"openapi_url", req.OpenAPIURL != ""}} {
		if f.set {
			return invalid(f.field, f.field+" is not a field of a remote backend")
		}
	}
	u, err := url.Parse(req.URL)
	switch {
	case strings.TrimSpace(req.URL) == "":
		return invalid("url", "a remote backend needs url")
	case err != nil:
		return invalid("url", "url is not a valid URL")
	case u.User != nil:
		return invalid("url", "url carries userinfo")
	case u.Scheme != "http" && u.Scheme != "https":
		return invalid("url", "url must use scheme http or https")
	case u.Host == "":
		return invalid("url", "url has no host")
	case u.RawQuery != "" || u.ForceQuery:
		return invalid("url", "url carries a query")
	case u.Fragment != "" || u.RawFragment != "":
		return invalid("url", "url carries a fragment")
	}
	switch req.AuthKind {
	case "", "none":
		if req.KeyName != "" {
			return invalid("key_name", "auth kind is keyless but key_name is set")
		}
		if req.AuthName != "" {
			return invalid("auth_name", "auth kind is keyless but auth_name is set")
		}
	case "bearer", "header":
		if req.KeyName == "" {
			return invalid("key_name", "a keyed auth kind needs key_name")
		}
		if req.AuthKind == "bearer" && req.AuthName != "" {
			return invalid("auth_name", "auth kind bearer takes no auth_name")
		}
		if req.AuthKind == "header" && req.AuthName == "" {
			return invalid("auth_name", "auth kind header needs auth_name")
		}
	default:
		return invalid("auth_kind", "auth kind is not none, bearer or header")
	}
	if strings.ContainsAny(req.AuthName, ": \t\r\n") {
		return invalid("auth_name", "auth_name looks like a header line")
	}
	if req.RemoteKind != "" && req.RemoteKind != adminapi.RemoteKindStreamable {
		return invalid("remote_kind", "remote kind is not streamable")
	}
	return nil
}

func (s *Server) deregisterUpstream(w http.ResponseWriter, r *http.Request) {
	var req adminapi.DeregisterRequest
	if !decode(w, r, &req) {
		return
	}
	nm := name(r)
	if req.Confirm != nm {
		writeErr(w, adminapi.NewError(adminapi.CodeBadRequest, "confirm must repeat the name %q", nm))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	had := s.findUpstream(nm) != nil
	forgot := len(s.toolsOf(nm))
	s.upstreams = slices.DeleteFunc(s.upstreams, func(u *adminapi.UpstreamDetail) bool { return u.Name == nm })
	s.tools = slices.DeleteFunc(s.tools, func(t adminapi.Tool) bool { return t.Server == nm })
	res := adminapi.DeregisterResult{Name: nm, Registered: had, SignatureRemoved: had, ToolsForgotten: forgot}
	res.Changed, res.Recorded, res.Messages = had, true, []string{"deregistered " + nm}
	res.Audit = s.row(rowUpstreamDeregister, "deregister "+nm)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) signUpstream(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.findUpstream(name(r))
	if u == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no backend %q", name(r)))
		return
	}
	u.Signature = "yes"
	res := adminapi.SignResult{Name: u.Name, KeyFingerprint: "sha256:fake-signing-key", Trusted: true}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"signed " + u.Name}
	res.Audit = s.row(rowUpstreamSign, "sign "+u.Name)
	writeJSON(w, http.StatusOK, res)
}

// --- secrets ---

func (s *Server) listSecrets(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := adminapi.SecretList{Secrets: make([]adminapi.Secret, 0, len(s.secretOrder)), RegistryRead: true}
	for _, n := range s.secretOrder {
		out.Secrets = append(out.Secrets, *s.secrets[n])
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setSecret(w http.ResponseWriter, r *http.Request) {
	var body adminapi.SecretValue
	if !decode(w, r, &body) {
		return
	}
	nm := name(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, existed := s.secrets[nm]
	if !existed {
		sec = &adminapi.Secret{Name: nm}
		s.secrets[nm] = sec
		s.secretOrder = append(s.secretOrder, nm)
	}
	wasInVault := sec.InVault
	sec.InVault = true
	res := adminapi.SecretResult{Name: nm, Existed: wasInVault}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"set " + nm}
	res.Audit = s.row(rowSecretSet, "set "+nm)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) deleteSecret(w http.ResponseWriter, r *http.Request) {
	nm := name(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[nm]
	existed := ok && sec.InVault
	if ok {
		sec.InVault = false
		if len(sec.DeclaredBy) == 0 {
			delete(s.secrets, nm)
			s.secretOrder = slices.DeleteFunc(s.secretOrder, func(n string) bool { return n == nm })
		}
	}
	res := adminapi.SecretResult{Name: nm, Existed: existed}
	res.Changed, res.Recorded, res.Messages = existed, true, []string{"deleted " + nm}
	res.Audit = s.row(rowSecretDelete, "delete "+nm)
	writeJSON(w, http.StatusOK, res)
}

// --- roles ---

func (s *Server) getRoles(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.roles)
}

func (s *Server) putRoles(w http.ResponseWriter, r *http.Request) {
	var req adminapi.RolesRequest
	if !decode(w, r, &req) {
		return
	}
	if err := validateRoles(req.Text); err != nil {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "the roles text would not load, so it was not written: %v", err).With("field", "text"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roles.Text = req.Text
	s.roles.SHA256 = "sha256:roles-" + strconv.Itoa(len(req.Text))
	res := adminapi.RolesResult{Path: s.roles.Path, SHA256: s.roles.SHA256, ReloadNeeded: true}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"wrote roles; reload to apply"}
	res.Audit = s.row(rowRolesWrite, "write roles")
	writeJSON(w, http.StatusOK, res)
}

// validateRoles applies the role rules the real backend's PutRoles applies
// through config.ValidateRolesText, so a front cannot pass a test with an
// edit production refuses. It has no main configuration to load, so it
// checks the roles alone.
func validateRoles(text string) error {
	var doc struct {
		Roles       []config.Role     `toml:"role"`
		GroupToRole map[string]string `toml:"group_to_role"`
	}
	if _, err := toml.Decode(text, &doc); err != nil {
		return err
	}
	for _, r := range doc.Roles {
		if err := access.ValidateRole(access.Role{Name: r.Name, Tools: r.Tools, Grants: r.Grants, NonRead: r.NonRead}); err != nil {
			return err
		}
		if r.NonRead && len(r.Tools) == 0 {
			return fmt.Errorf("role %q: non_read = true but `tools` is empty", r.Name)
		}
	}
	return nil
}

// --- maintenance ---

func (s *Server) listMaintenance(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.maint)
}

func (s *Server) startMaintenance(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MaintenanceRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := base.Add(72 * time.Hour)
	m := adminapi.Maintenance{Message: req.Message, Until: req.Until, StartedAt: now, SetBy: s.operator.Name, SetAt: now}
	res := adminapi.MaintenanceResult{Scope: req.Scope, Upstream: req.Upstream, Maintenance: &m}
	if req.Scope == adminapi.ScopeGateway {
		s.maint.Gateway = &m
	} else {
		s.maint.Upstreams = slices.DeleteFunc(s.maint.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == req.Upstream })
		s.maint.Upstreams = append(s.maint.Upstreams, adminapi.UpstreamMaintenance{Maintenance: m, Upstream: req.Upstream})
	}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"maintenance on"}
	res.Audit = s.row(rowMaintenanceOn, "maintenance on "+req.Scope)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) endMaintenance(w http.ResponseWriter, r *http.Request) {
	var req adminapi.MaintenanceTarget
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res := adminapi.MaintenanceResult{Scope: req.Scope, Upstream: req.Upstream}
	if req.Scope == adminapi.ScopeGateway {
		res.Previous = s.maint.Gateway
		s.maint.Gateway = nil
	} else {
		s.maint.Upstreams = slices.DeleteFunc(s.maint.Upstreams, func(u adminapi.UpstreamMaintenance) bool { return u.Upstream == req.Upstream })
	}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"maintenance off"}
	res.Audit = s.row(rowMaintenanceOff, "maintenance off "+req.Scope)
	writeJSON(w, http.StatusOK, res)
}

// --- serve control ---

func (s *Server) reload(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := s.newServeReq(adminapi.ServeKindReload, "")
	req.Reload = &adminapi.ReloadChanges{Roles: []adminapi.RoleChange{}, Groups: []adminapi.GroupChange{}, Quota: []adminapi.QuotaChange{}}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) redialUpstream(w http.ResponseWriter, r *http.Request) {
	var req adminapi.RedialRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findUpstream(req.Upstream) == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no backend %q", req.Upstream))
		return
	}
	sr := s.newServeReq(adminapi.ServeKindRedial, req.Upstream)
	sr.Redial = &adminapi.RedialOutcome{WasConnected: true, Live: true}
	writeJSON(w, http.StatusOK, sr)
}

func (s *Server) serveRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	s.mu.Lock()
	defer s.mu.Unlock()
	sr, ok := s.serveReqs[id]
	if err != nil || !ok {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no serve request %s", r.PathValue("id")))
		return
	}
	writeJSON(w, http.StatusOK, sr)
}

// newServeReq files a done serve request so a caller can read it back by id.
// The caller holds s.mu.
func (s *Server) newServeReq(kind, upstream string) adminapi.ServeRequest {
	s.nextServe++
	now := base.Add(72 * time.Hour)
	sr := adminapi.ServeRequest{ID: s.nextServe, Kind: kind, Upstream: upstream, RequestedBy: s.operator.Name,
		RequestedAt: now, State: adminapi.ServeStateDone, Outcome: adminapi.ServeOutcomeApplied, DoneAt: &now,
		Recorded: true, Messages: []string{"applied"}, Audit: s.row("("+kind+")", kind)}
	s.serveReqs[sr.ID] = sr
	return sr
}

// --- small shared helpers ---

// name is the {name} path segment. ServeMux returns it already decoded.
func name(r *http.Request) string { return r.PathValue("name") }

func (s *Server) findUpstream(nm string) *adminapi.UpstreamDetail {
	for _, u := range s.upstreams {
		if u.Name == nm {
			return u
		}
	}
	return nil
}

func (s *Server) toolsOf(server string) []adminapi.Tool {
	out := []adminapi.Tool{}
	for _, t := range s.tools {
		if t.Server == server {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) recentDenied() []adminapi.AuditRecord {
	out := []adminapi.AuditRecord{}
	for i := len(s.audit) - 1; i >= 0 && len(out) < 5; i-- {
		if s.audit[i].Outcome == adminapi.OutcomeDenied {
			out = append(out, s.audit[i])
		}
	}
	return out
}

func (s *Server) health() *adminapi.Health {
	boot := base
	round := base.Add(71 * time.Hour)
	h := &adminapi.Health{
		Serve:    adminapi.ServeStatus{State: adminapi.ServeRunning, Boot: &boot, LastRoundAt: &round, RoundIntervalSeconds: 30},
		Backends: []adminapi.BackendHealth{},
	}
	for _, u := range s.upstreams {
		if u.Health != nil {
			h.Backends = append(h.Backends, *u.Health)
		}
	}
	return h
}
