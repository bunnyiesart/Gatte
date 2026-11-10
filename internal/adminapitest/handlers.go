package adminapitest

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// routes registers every operator and accounts operation of the contract. The
// fake serves both socket surfaces on one handler: nothing here enforces the
// socket split, which is a privilege boundary of the real backend, not a thing
// a frontend's rendering depends on.
func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/whoami", s.whoAmI)
	m.HandleFunc("GET /v1/overview", s.overview)

	m.HandleFunc("GET /v1/tools", s.listTools)
	m.HandleFunc("GET /v1/tools/review", s.reviewTool)
	m.HandleFunc("POST /v1/tools/approve", s.approveTool)
	m.HandleFunc("GET /v1/tools/review-set", s.reviewToolSet)
	m.HandleFunc("POST /v1/tools/approve-set", s.approveToolSet)
	m.HandleFunc("POST /v1/tools/revoke", s.revokeTool)
	m.HandleFunc("POST /v1/tools/clear", s.clearTool)

	m.HandleFunc("GET /v1/access/blocks", s.listBlocks)
	m.HandleFunc("POST /v1/access/block", s.blockSubject)
	m.HandleFunc("POST /v1/access/unblock", s.unblockSubject)

	m.HandleFunc("GET /v1/audit", s.listAudit)
	m.HandleFunc("POST /v1/audit/verify", s.verifyAudit)

	m.HandleFunc("GET /v1/upstreams", s.listUpstreams)
	m.HandleFunc("POST /v1/upstreams", s.registerUpstream)
	m.HandleFunc("POST /v1/upstreams/redial", s.redialUpstream)
	m.HandleFunc("GET /v1/upstreams/{name}", s.getUpstream)
	m.HandleFunc("DELETE /v1/upstreams/{name}", s.deregisterUpstream)
	m.HandleFunc("POST /v1/upstreams/{name}/sign", s.signUpstream)

	m.HandleFunc("GET /v1/secrets", s.listSecrets)
	m.HandleFunc("PUT /v1/secrets/{name}", s.setSecret)
	m.HandleFunc("DELETE /v1/secrets/{name}", s.deleteSecret)

	m.HandleFunc("GET /v1/roles", s.getRoles)
	m.HandleFunc("PUT /v1/roles", s.putRoles)

	m.HandleFunc("GET /v1/maintenance", s.listMaintenance)
	m.HandleFunc("POST /v1/maintenance/on", s.startMaintenance)
	m.HandleFunc("POST /v1/maintenance/off", s.endMaintenance)

	m.HandleFunc("POST /v1/reload", s.reload)
	m.HandleFunc("GET /v1/serve-requests/{id}", s.serveRequest)
	m.HandleFunc("GET /v1/quota", s.quotaHandler)

	m.HandleFunc("GET /v1/people", s.peopleHandler)
	m.HandleFunc("GET /v1/connect", s.connect)
	m.HandleFunc("GET /v1/connect/script", s.connectScript)
	m.HandleFunc("GET /v1/groups", s.assignableGroups)

	m.HandleFunc("GET /v1/accounts", s.listAccounts)
	m.HandleFunc("POST /v1/accounts", s.addAccount)
	m.HandleFunc("POST /v1/account-check", s.checkAccount)
	m.HandleFunc("GET /v1/accounts/{username}", s.getAccount)
	m.HandleFunc("DELETE /v1/accounts/{username}", s.deleteAccount)
	m.HandleFunc("POST /v1/accounts/{username}/offboard", s.offboardAccount)
	m.HandleFunc("POST /v1/accounts/{username}/groups", s.setAccountGroups)
	m.HandleFunc("POST /v1/accounts/{username}/disable", s.disableAccount)
	m.HandleFunc("POST /v1/accounts/{username}/enable", s.enableAccount)
	m.HandleFunc("POST /v1/accounts/{username}/reset-password", s.resetAccountPassword)

	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, adminapi.NewError(adminapi.CodeUnknownRoute, "no route %s %s in the fake", r.Method, r.URL.Path))
	})
	s.mux = m
}

// --- read surface ---

func (s *Server) whoAmI(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, adminapi.WhoAmI{
		APIVersions:     []string{"v1"},
		ContractVersion: adminapi.ContractVersion,
		Features:        slices.Clone(s.features),
		GatewayVersion:  "fake-0",
		Socket:          adminapi.SocketOperator,
		ConfigPath:      "/etc/mcp-gateway/config.toml",
		Operator:        s.operator,
		Front:           r.Header.Get(adminapi.FrontHeader),
	})
}

func (s *Server) overview(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := adminapi.OverviewCounts{Upstreams: len(s.upstreams), Blocked: s.activeBlocks()}
	for _, t := range s.tools {
		counts.Tools++
		if t.Usable {
			counts.ApprovedUsable++
		}
		if t.Status != adminapi.StatusApproved {
			counts.Review++
		}
	}
	var attn []adminapi.Attention
	for _, t := range s.tools {
		switch t.Status {
		case adminapi.StatusPending:
			attn = append(attn, adminapi.Attention{Kind: adminapi.AttentionPending, Title: "Tool waits for review",
				Detail: t.Server + "." + t.Tool, Server: t.Server, Tool: t.Tool})
		case adminapi.StatusChanged:
			attn = append(attn, adminapi.Attention{Kind: adminapi.AttentionChanged, Title: "Tool definition changed",
				Detail: t.Server + "." + t.Tool, Server: t.Server, Tool: t.Tool})
		}
	}
	for _, u := range s.upstreams {
		if u.Signature != "yes" {
			attn = append(attn, adminapi.Attention{Kind: adminapi.AttentionUnsigned, Title: "Backend is not signed",
				Detail: u.Name, Upstream: u.Name})
		}
	}
	writeJSON(w, http.StatusOK, adminapi.Overview{
		Attention:    attn,
		Counts:       counts,
		RecentDenied: s.recentDenied(),
		Health:       s.health(),
	})
}

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, show := r.URL.Query().Get("server"), r.URL.Query().Get("show")
	out := adminapi.ToolList{Tools: []adminapi.Tool{}}
	for _, t := range s.tools {
		// Counts are over every entry of the filtered server, whatever the
		// show filter, matching the real backend.
		if server != "" && t.Server != server {
			continue
		}
		out.Counts.All++
		switch t.Status {
		case adminapi.StatusApproved:
			out.Counts.Approved++
		default:
			out.Counts.Review++
		}
		switch show {
		case "approved":
			if t.Status != adminapi.StatusApproved {
				continue
			}
		case "review":
			if t.Status == adminapi.StatusApproved {
				continue
			}
		}
		out.Tools = append(out.Tools, t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) reviewTool(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	server, tool := r.URL.Query().Get("server"), r.URL.Query().Get("tool")
	t := s.findTool(server, tool)
	if t == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no tool %q on %q", tool, server))
		return
	}
	d := s.definitions[key(server, tool)]
	writeJSON(w, http.StatusOK, adminapi.ToolReview{
		Tool:       *t,
		Observed:   d.observed,
		Approved:   d.approved,
		Diff:       d.diff,
		CallableBy: d.callable,
		ReviewText: "name: " + tool + "\ndescription: " + descOf(d.observed),
	})
}

func (s *Server) approveTool(w http.ResponseWriter, r *http.Request) {
	var req adminapi.ApproveRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findTool(req.Server, req.Tool)
	if t == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no tool %q on %q", req.Tool, req.Server))
		return
	}
	if req.Fingerprint == "" {
		writeErr(w, adminapi.NewError(adminapi.CodeFingerprintRequired, "approve must name the fingerprint it approves"))
		return
	}
	if req.Fingerprint != t.ObservedHash {
		writeErr(w, adminapi.NewError(adminapi.CodeFingerprintMismatch,
			"the definition changed since it was shown; review it again").With("observed_hash", t.ObservedHash))
		return
	}
	prev := t.Status
	t.Status = adminapi.StatusApproved
	t.ApprovedHash = req.Fingerprint
	t.Usable = t.Class != adminapi.ClassSensitive
	t.UpdatedAt = base.Add(72 * time.Hour)
	res := adminapi.ApproveResult{PreviousStatus: prev, Tool: *t, CallableBy: s.definitions[key(req.Server, req.Tool)].callable}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"approved"}
	res.Audit = s.row(rowToolApprove, "approve "+req.Server+"."+req.Tool)
	if t.Class == adminapi.ClassSensitive {
		res.Warnings = []adminapi.Warning{{Code: adminapi.WarnSensitiveUncleared,
			Message: "approved and not served until it is cleared"}}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) reviewToolSet(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	server := r.URL.Query().Get("server")
	set := adminapi.ToolReviewSet{Server: server, Tools: []adminapi.ToolReview{}}
	for i := range s.tools {
		t := &s.tools[i]
		if t.Server != server || t.Status == adminapi.StatusApproved {
			continue
		}
		d := s.definitions[key(t.Server, t.Tool)]
		set.Tools = append(set.Tools, adminapi.ToolReview{Tool: *t, Observed: d.observed, CallableBy: d.callable})
		if t.Status == adminapi.StatusChanged {
			set.Changed++
		} else {
			set.Pending++
		}
	}
	if len(set.Tools) > 0 {
		set.Approvable = true
		set.Manifest = s.manifest(server)
	} else {
		set.Reason = "nothing waits for review on " + server
	}
	writeJSON(w, http.StatusOK, set)
}

// manifest is the token naming the set of tools that waits for review on a
// server right now. It changes when that set changes, so a stale manifest sent
// to approve-set no longer matches. The caller holds s.mu.
func (s *Server) manifest(server string) string {
	pending := 0
	for _, t := range s.tools {
		if t.Server == server && t.Status != adminapi.StatusApproved {
			pending++
		}
	}
	return "fake-manifest:" + server + ":" + strconv.Itoa(pending)
}

func (s *Server) approveToolSet(w http.ResponseWriter, r *http.Request) {
	var req adminapi.ApproveSetRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.manifest(req.Server) != req.Manifest {
		writeErr(w, adminapi.NewError(adminapi.CodeManifestMismatch,
			"the set changed since it was reviewed; review it again"))
		return
	}
	res := adminapi.ApproveSetResult{Server: req.Server, Manifest: req.Manifest, Approved: []adminapi.ApprovedTool{}, Rows: []adminapi.OperatorRow{}}
	sensitive := false
	for i := range s.tools {
		t := &s.tools[i]
		if t.Server != req.Server || t.Status == adminapi.StatusApproved {
			continue
		}
		prev := t.Status
		t.Status = adminapi.StatusApproved
		t.ApprovedHash = t.ObservedHash
		t.Usable = t.Class != adminapi.ClassSensitive
		if t.Class == adminapi.ClassSensitive {
			sensitive = true
		}
		res.Approved = append(res.Approved, adminapi.ApprovedTool{PreviousStatus: prev, Tool: *t,
			CallableBy: s.definitions[key(t.Server, t.Tool)].callable})
		res.Rows = append(res.Rows, *s.row(rowToolApprove, "approve "+t.Server+"."+t.Tool))
	}
	if len(res.Approved) == 0 {
		writeErr(w, adminapi.NewError(adminapi.CodeManifestMismatch, "nothing waits for review on %q", req.Server))
		return
	}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"approved set"}
	if sensitive {
		res.Warnings = []adminapi.Warning{{Code: adminapi.WarnSensitiveUncleared,
			Message: "a sensitive tool was approved and is not served until it is cleared"}}
	}
	res.Audit = s.row(rowToolApproveSet, "approve set "+req.Server)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) revokeTool(w http.ResponseWriter, r *http.Request) {
	var req adminapi.ToolRef
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findTool(req.Server, req.Tool)
	if t == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no tool %q on %q", req.Tool, req.Server))
		return
	}
	was := t.ApprovedHash
	t.Status = adminapi.StatusPending
	t.Usable = false
	t.ApprovedHash = ""
	t.SensitiveClearedHash = ""
	res := adminapi.RevokeResult{WasApprovedAt: was, Tool: *t}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"revoked"}
	res.Audit = s.row(rowToolRevoke, "revoke "+req.Server+"."+req.Tool)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) clearTool(w http.ResponseWriter, r *http.Request) {
	var req adminapi.ToolRef
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.findTool(req.Server, req.Tool)
	if t == nil {
		writeErr(w, adminapi.NewError(adminapi.CodeNotFound, "no tool %q on %q", req.Tool, req.Server))
		return
	}
	if t.Class != adminapi.ClassSensitive {
		writeErr(w, adminapi.NewError(adminapi.CodeNotSensitive, "%q is not a sensitive tool", req.Tool))
		return
	}
	if t.Status != adminapi.StatusApproved {
		writeErr(w, adminapi.NewError(adminapi.CodeNotApproved, "approve %q before clearing it", req.Tool))
		return
	}
	t.SensitiveClearedHash = t.ApprovedHash
	t.Usable = true
	res := adminapi.ClearResult{Tool: *t, ClearedBy: s.definitions[key(req.Server, req.Tool)].callable}
	res.Changed, res.Recorded, res.Messages = true, true, []string{"cleared"}
	res.Audit = s.row(rowToolClear, "clear "+req.Server+"."+req.Tool)
	writeJSON(w, http.StatusOK, res)
}

// --- access ---

func (s *Server) listBlocks(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, adminapi.BlockList{Blocks: slices.Clone(s.blocks)})
}

func (s *Server) blockSubject(w http.ResponseWriter, r *http.Request) {
	var req adminapi.BlockRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Subject == "" {
		writeErr(w, adminapi.NewError(adminapi.CodeInvalidArgument, "block must name a subject"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := slices.IndexFunc(s.blocks, func(b adminapi.Block) bool { return b.Subject == req.Subject })
	b := adminapi.Block{Subject: req.Subject, BlockedBy: s.operator.Name, BlockedAt: base.Add(72 * time.Hour), Reason: req.Reason, Until: req.Until}
	if idx >= 0 {
		s.blocks[idx] = b
	} else {
		s.blocks = append(s.blocks, b)
	}
	s.blockResult(w, req.Subject, rowAccessBlock, "block "+req.Subject)
}

func (s *Server) unblockSubject(w http.ResponseWriter, r *http.Request) {
	var req adminapi.BlockRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blocks = slices.DeleteFunc(s.blocks, func(b adminapi.Block) bool { return b.Subject == req.Subject })
	s.blockResult(w, req.Subject, rowAccessUnblock, "unblock "+req.Subject)
}

func (s *Server) blockResult(w http.ResponseWriter, subject, tool, reason string) {
	res := adminapi.BlockResult{Subject: subject}
	res.Changed, res.Recorded, res.Messages = true, true, []string{reason}
	res.Audit = s.row(tool, reason)
	writeJSON(w, http.StatusOK, res)
}

// --- audit ---

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := r.URL.Query()
	limit := 200
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = v
	}
	out := []adminapi.AuditRecord{}
	for i := len(s.audit) - 1; i >= 0 && len(out) < limit; i-- {
		rec := s.audit[i]
		if sub := q.Get("subject"); sub != "" && rec.AnalystIdentity != sub {
			continue
		}
		if oc := q.Get("outcome"); oc != "" && rec.Outcome != oc {
			continue
		}
		if tl := q.Get("tool"); tl != "" && rec.Tool != tl {
			continue
		}
		out = append(out, rec)
	}
	writeJSON(w, http.StatusOK, adminapi.AuditPage{Records: out, Limit: limit})
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	var req adminapi.VerifyRequest
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	head := "sha256:" + strings.Repeat("ab", 16)
	res := adminapi.VerifyResult{Intact: true, Count: len(s.audit), Head: head,
		SIEM: &adminapi.SIEMAnchor{Path: "/var/log/mcp-gateway/audit.jsonl", Chain: head}}
	if req.ExpectHead != "" {
		match := req.ExpectHead == head
		res.HeadMatches = &match
	}
	writeJSON(w, http.StatusOK, res)
}

// --- quota / people / connect ---

func (s *Server) quotaHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	analyst := r.URL.Query().Get("analyst")
	out := []adminapi.QuotaUsage{}
	for _, u := range s.quota {
		if analyst != "" && u.AnalystIdentity != analyst {
			continue
		}
		out = append(out, u)
	}
	writeJSON(w, http.StatusOK, adminapi.QuotaList{Usage: out})
}

func (s *Server) peopleHandler(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, s.people)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	username := r.URL.Query().Get("username")
	if username == "" {
		username = "ana.lima"
	}
	writeJSON(w, http.StatusOK, adminapi.Connect{
		Ready: true, URL: "https://gatte.example/mcp", ClientID: "soc-gateway",
		ServerName: "soc-gateway", Username: username, HasCA: true,
		Command: "mcp-gateway connect",
		Scripts: []adminapi.ConnectScript{{OS: adminapi.OSMacOS, Name: "macOS", Filename: "connect-macos.sh",
			Run: "sh connect-macos.sh", Content: "#!/bin/sh\n# fake connect script for " + username + "\n"}},
	})
}

func (s *Server) connectScript(w http.ResponseWriter, r *http.Request) {
	os := r.URL.Query().Get("os")
	if os == "" {
		os = adminapi.OSMacOS
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "connect-"+os+".sh"))
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "#!/bin/sh\n# fake connect script (%s)\n", os)
}

func (s *Server) assignableGroups(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, http.StatusOK, adminapi.GroupList{Groups: slices.Clone(s.groups)})
}

// --- helpers ---

func key(server, tool string) string { return server + "\x00" + tool }

func (s *Server) findTool(server, tool string) *adminapi.Tool {
	for i := range s.tools {
		if s.tools[i].Server == server && s.tools[i].Tool == tool {
			return &s.tools[i]
		}
	}
	return nil
}

func (s *Server) activeBlocks() int {
	n := 0
	for _, b := range s.blocks {
		if !b.Expired {
			n++
		}
	}
	return n
}

func descOf(d adminapi.Definition) string {
	if d.Description != nil {
		return d.Description.Raw
	}
	return ""
}
