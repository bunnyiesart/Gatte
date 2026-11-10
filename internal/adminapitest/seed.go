package adminapitest

import (
	"time"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// seed fills the fake with sample rows for every entity. It aims for a mix
// that exercises each frontend's rendering: approved, pending, changed and
// sensitive tools; backends up, down and in maintenance; a secret declared
// but not in the vault; an active and an expired block; a disabled account;
// and collections that are legitimately empty (gateway maintenance, quota for
// one analyst). Error states are reached by asking for things that do not
// exist (a 404) or by a fingerprint or confirmation mismatch.
func (s *Server) seed() {
	s.operator = adminapi.Operator{UID: 1000, Name: "alice.ops", Identity: "(operator:alice.ops)"}
	s.features = []string{
		adminapi.FeatureMaintenance, adminapi.FeatureBackendHealth, adminapi.FeatureToolReviewSet,
		adminapi.FeatureToolClear, adminapi.FeatureServeControl, adminapi.FeatureAuditFilters,
		adminapi.FeatureBlockUntil, adminapi.FeatureAccountDelete, adminapi.FeatureOffboard,
		adminapi.FeatureConsoleManages,
	}

	s.definitions = map[string]definition{}
	s.seedToolsAndUpstreams()
	s.seedBlocks()
	s.seedAudit()
	s.seedSecrets()
	s.seedRolesAndPeople()
	s.seedAccounts()
	s.seedQuota()
}

func (s *Server) seedToolsAndUpstreams() {
	now := base
	up := func(name, state, cause string) *adminapi.UpstreamDetail {
		h := &adminapi.BackendHealth{Name: name, State: state, Live: state == adminapi.BackendUp, Since: &now, Cause: cause}
		return &adminapi.UpstreamDetail{Upstream: adminapi.Upstream{
			Name: name, Transport: "stdio", Command: "docker", Args: []string{"run", "--rm", name},
			Network: "none", EnvVarNames: []string{}, Signature: "yes", CreatedAt: now, UpdatedAt: now, Health: h,
		}, Tools: []adminapi.Tool{}}
	}
	s.upstreams = []*adminapi.UpstreamDetail{
		up("casemgmt", adminapi.BackendUp, ""),
		up("logsearch", adminapi.BackendUp, ""),
		up("docsearch", adminapi.BackendMaintenance, ""),
		up("threatintel", adminapi.BackendDown, "stream closed"),
	}
	s.upstreams[3].NetworkError = "last dial refused"
	// Declared secret names, so the per-server Secrets panel has rows: a key
	// shared by two backends, and threatintel's three (one missing from the
	// vault, see seedSecrets).
	s.upstreams[0].EnvVarNames = []string{"SIEM_TOKEN"}
	s.upstreams[1].EnvVarNames = []string{"SIEM_TOKEN"}
	s.upstreams[3].EnvVarNames = []string{"THREATINTEL_API_KEY", "VIRUSTOTAL_KEY", "SHODAN_KEY"}

	add := func(server, tool, status, class string, usable bool) {
		fp := "sha256:" + server + "-" + tool
		t := adminapi.Tool{Server: server, Tool: tool, Status: status, Usable: usable,
			ObservedHash: fp, FirstSeenAt: base.Add(-48 * time.Hour), UpdatedAt: base, Class: class}
		if status == adminapi.StatusApproved {
			t.ApprovedHash = fp
			if class == adminapi.ClassSensitive && usable {
				t.SensitiveClearedHash = fp
			}
		}
		if status == adminapi.StatusChanged {
			t.ApprovedHash = "sha256:" + server + "-" + tool + "-old"
		}
		s.tools = append(s.tools, t)
		def := textDef(tool, descFor(tool), fp)
		var cov []adminapi.RoleCoverage
		if class == adminapi.ClassSensitive {
			cov = []adminapi.RoleCoverage{{Role: "ir-lead", How: "tools = [...]", NonRead: true}}
		} else {
			cov = []adminapi.RoleCoverage{{Role: "tier1-analyst", How: "role.grants"}}
		}
		d := definition{observed: def, callable: cov}
		if status == adminapi.StatusChanged {
			old := textDef(tool, "Older description.", t.ApprovedHash)
			d.approved = &old
			d.diff = []adminapi.DiffLine{
				{Op: adminapi.DiffDel, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "Older description."}}},
				{Op: adminapi.DiffAdd, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: descFor(tool)}}},
			}
		}
		s.definitions[key(server, tool)] = d
	}
	add("casemgmt", "get_case", adminapi.StatusApproved, adminapi.ClassSafe, true)
	add("casemgmt", "close_case", adminapi.StatusApproved, adminapi.ClassSensitive, true)
	add("casemgmt", "create_case", adminapi.StatusApproved, adminapi.ClassSensitive, false) // approved, not cleared
	add("logsearch", "search_relative", adminapi.StatusApproved, adminapi.ClassSafe, true)
	add("logsearch", "search_absolute", adminapi.StatusPending, adminapi.ClassSafe, false)
	add("docsearch", "find_document", adminapi.StatusChanged, adminapi.ClassSafe, false)
	add("threatintel", "lookup_ip", adminapi.StatusPending, adminapi.ClassSafe, false)
}

func (s *Server) seedBlocks() {
	expired := base.Add(-time.Hour)
	s.blocks = []adminapi.Block{
		{Subject: "sub-mallory", BlockedBy: "alice.ops", BlockedAt: base.Add(-24 * time.Hour), Reason: "credential stuffing [ui]"},
		{Subject: "sub-leaver", BlockedBy: "bob.ops", BlockedAt: base.Add(-96 * time.Hour), Reason: "offboarded [ui]", Until: &expired, Expired: true},
	}
}

func (s *Server) seedAudit() {
	mk := func(pos int, ago time.Duration, who, tool, server, outcome, reason string) adminapi.AuditRecord {
		return adminapi.AuditRecord{Position: pos, Timestamp: base.Add(-ago), AnalystIdentity: who,
			Tool: tool, TargetUpstream: server, Outcome: outcome, Reason: reason}
	}
	s.audit = []adminapi.AuditRecord{
		mk(1, 6*time.Hour, "sub-ana", "logsearch.search_relative", "logsearch", adminapi.OutcomeAllowed, ""),
		mk(2, 5*time.Hour, "sub-ana", "casemgmt.get_case", "casemgmt", adminapi.OutcomeAllowed, ""),
		mk(3, 4*time.Hour, "sub-mallory", "casemgmt.close_case", "casemgmt", adminapi.OutcomeDenied, "blocked subject"),
		mk(4, 3*time.Hour, "sub-ivan", "threatintel.lookup_ip", "threatintel", adminapi.OutcomeFailed, "backend down"),
		mk(5, 1*time.Hour, "(unauthenticated)", "(none)", "(gateway)", adminapi.OutcomeDenied, "no credential"),
	}
}

func (s *Server) seedSecrets() {
	s.secrets = map[string]*adminapi.Secret{}
	set := func(name string, inVault bool, declaredBy ...string) {
		s.secrets[name] = &adminapi.Secret{Name: name, InVault: inVault, DeclaredBy: declaredBy}
		s.secretOrder = append(s.secretOrder, name)
	}
	set("SIEM_TOKEN", true, "casemgmt", "logsearch") // shared across two backends
	set("THREATINTEL_API_KEY", true, "threatintel")
	set("VIRUSTOTAL_KEY", true, "threatintel")
	set("SHODAN_KEY", false, "threatintel") // declared by an entry, missing from the vault
	set("ORPHAN_KEY", true)                 // in the vault, declared by nothing
}

func (s *Server) seedRolesAndPeople() {
	// A coherent roles file: the comments are load-bearing (design/adr/0009),
	// and the grants match the People view below so the Roles matrix shows a
	// wildcard, an explicit grant, and a non_read sensitive grant.
	s.roles = adminapi.RolesText{
		Path:   "/etc/mcp-gateway/roles.toml",
		SHA256: "sha256:roles-seed",
		Text: "# SOC roles. Keep the approver note on each grant: it is read at 3am.\n" +
			"[[role]]\n" +
			"name = \"tier1-analyst\"   # triage; read-only. reviewed 2026-10 by alice.ops\n\n" +
			"  [role.grants]\n" +
			"  logsearch = [\"*\"]        # all read-only log search\n" +
			"  casemgmt  = [\"get_case\"]\n\n" +
			"[[role]]\n" +
			"name = \"ir-lead\"          # may act; reviewed 2026-10 by alice.ops\n" +
			"non_read = true\n" +
			"tools = [\"casemgmt.close_case\", \"casemgmt.create_case\"]\n\n" +
			"[group_to_role]\n" +
			"\"soc-tier1\" = \"tier1-analyst\"\n" +
			"\"soc-ir\"    = \"ir-lead\"\n",
	}
	s.people = adminapi.People{
		Roles: []adminapi.Role{
			{Name: "tier1-analyst", Groups: []string{"soc-tier1"}, Tools: []string{"logsearch.*", "casemgmt.get_case"}},
			{Name: "ir-lead", Groups: []string{"soc-ir"}, Tools: []string{"casemgmt.close_case", "casemgmt.create_case"}},
		},
		Groups: []adminapi.Group{{Name: "soc-tier1", Role: "tier1-analyst"}, {Name: "soc-ir", Role: "ir-lead"}},
		Seen: []adminapi.Seen{
			{Identity: "sub-ana", Name: "ana.lima", LastCall: base.Add(-2 * time.Hour), Calls: 142},
			{Identity: "sub-mallory", Name: "", LastCall: base.Add(-4 * time.Hour), Calls: 8, Blocked: true},
		},
	}
	s.groups = []adminapi.AssignableGroup{
		{Name: "soc-tier1", Role: "tier1-analyst", Tools: []string{"logsearch.*", "casemgmt.get_case"}},
		{Name: "soc-ir", Role: "ir-lead", Tools: []string{"casemgmt.close_case", "casemgmt.create_case"}},
	}
	// Gateway maintenance is legitimately empty; one backend is in maintenance.
	s.maint = adminapi.MaintenanceList{Upstreams: []adminapi.UpstreamMaintenance{{
		Maintenance: adminapi.Maintenance{Message: "index rebuild", StartedAt: base.Add(-time.Hour), SetBy: "alice.ops", SetAt: base.Add(-time.Hour)},
		Upstream:    "docsearch",
	}}}
}

func (s *Server) seedAccounts() {
	s.accounts = map[string]*adminapi.Account{}
	add := func(u, display, email string, groups []string, disabled bool) {
		s.accounts[u] = &adminapi.Account{Username: u, DisplayName: display, Email: email, Groups: groups, Disabled: disabled}
		s.acctOrder = append(s.acctOrder, u)
	}
	add("ana.lima", "Ana Lima", "ana.lima@example.org", []string{"soc-tier1"}, false)
	add("bruno.sa", "Bruno Sá", "bruno.sa@example.org", []string{"soc-ir"}, false)
	add("old.intern", "Old Intern", "", []string{}, true)
}

func (s *Server) seedQuota() {
	limit := 500
	remaining := 358
	end := base.Add(18 * time.Hour)
	s.quota = []adminapi.QuotaUsage{{
		AnalystIdentity: "sub-ana", Account: "ana.lima", WindowStart: base.Add(-6 * time.Hour), WindowEnd: &end,
		Used: 142, Limit: &limit, Remaining: &remaining,
	}}
}

// textDef builds a tool definition with a name, a description and a short
// canonical review body.
func textDef(name, desc, fingerprint string) adminapi.Definition {
	return adminapi.Definition{
		Fingerprint: fingerprint,
		Kept:        true,
		Name:        &adminapi.Text{Raw: name, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: name}}},
		Description: &adminapi.Text{Raw: desc, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: desc}}},
		Lines: []adminapi.ReviewLine{
			{Depth: 0, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "name: " + name}}},
			{Depth: 0, Segments: []adminapi.Segment{{Kind: adminapi.SegmentText, Text: "description: " + desc}}},
		},
	}
}

func descFor(tool string) string {
	switch tool {
	case "get_case":
		return "Return one case by id."
	case "close_case":
		return "Close a case. Acts on the case-management system."
	case "create_case":
		return "Open a new case. Acts on the case-management system."
	case "search_relative":
		return "Search logs over a relative time window."
	case "search_absolute":
		return "Search logs between two timestamps."
	case "find_document":
		return "Find a document by query."
	case "lookup_ip":
		return "Look up reputation for an IP address."
	default:
		return "A tool."
	}
}
