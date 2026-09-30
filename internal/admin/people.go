package admin

import (
	"context"
	"sort"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/quota"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Groups is every [group_to_role] key and its role, sorted: the only groups
// an account may be given.
func Groups(cfg *config.Config) []adminapi.Group {
	out := []adminapi.Group{}
	for g, r := range cfg.GroupToRole {
		out = append(out, adminapi.Group{Name: g, Role: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RoleTools is the backend.tool names and patterns a role grants, sorted.
func RoleTools(r config.Role) []string {
	tools := append([]string{}, r.Tools...)
	for backend, ids := range r.Grants {
		for _, t := range ids {
			tools = append(tools, backend+"."+t)
		}
	}
	sort.Strings(tools)
	return tools
}

// People returns the roles with their groups and tools, and the analysts
// the trail has seen, most recent first.
func (s *Service) People(ctx context.Context) (adminapi.People, error) {
	cfg, err := s.config()
	if err != nil {
		return adminapi.People{}, err
	}
	p := adminapi.People{Roles: []adminapi.Role{}, Groups: Groups(cfg), Seen: []adminapi.Seen{}}
	for _, role := range cfg.Roles {
		r := adminapi.Role{Name: role.Name, Groups: []string{}, Tools: RoleTools(role)}
		for _, g := range p.Groups {
			if g.Role == role.Name {
				r.Groups = append(r.Groups, g.Name)
			}
		}
		p.Roles = append(p.Roles, r)
	}
	if err := need(s.d.Trail != nil, "audit trail"); err != nil {
		return p, err
	}
	seen, err := s.d.Trail.Analysts(ctx)
	if err != nil {
		return p, s.storeErr("audit trail", err)
	}
	blocked := map[string]bool{}
	if s.d.Blocks != nil {
		if bs, err := s.d.Blocks.Blocks(ctx); err == nil {
			blocked = activeBlocks(bs, s.d.Now())
		}
	}
	for _, a := range seen {
		p.Seen = append(p.Seen, adminapi.Seen{Identity: a.Identity, Name: a.Name, Calls: a.Calls, LastCall: a.LastCall, Blocked: blocked[a.Identity]})
	}
	sort.Slice(p.Seen, func(i, j int) bool { return p.Seen[i].LastCall.After(p.Seen[j].LastCall) })
	return p, nil
}

// Quota returns the counters matching q against the declared plan, newest
// window first.
func (s *Service) Quota(ctx context.Context, q adminapi.QuotaQuery) (adminapi.QuotaList, error) {
	if err := need(s.d.Quota != nil, "quota counters"); err != nil {
		return adminapi.QuotaList{}, err
	}
	cfg, err := s.config()
	if err != nil {
		return adminapi.QuotaList{}, err
	}
	plan, err := cfg.ToQuotaPlan()
	if err != nil {
		return adminapi.QuotaList{}, adminapi.NewError(adminapi.CodeConfigUnavailable, "quota: %v", err).With("problem", "does_not_load")
	}
	declared := map[string]quota.Provider{}
	for _, p := range plan.Providers() {
		declared[p.Name] = p
	}
	counters, err := s.d.Quota.Usage(ctx)
	if err != nil {
		return adminapi.QuotaList{}, s.storeErr("quota counters", err)
	}
	var matching []quota.Usage
	for _, u := range counters {
		if q.Analyst != "" && u.Analyst != q.Analyst || q.Account != "" && u.Provider != q.Account || !q.Since.IsZero() && u.WindowStart.Before(q.Since) {
			continue
		}
		matching = append(matching, u)
	}
	sort.SliceStable(matching, func(i, j int) bool {
		a, b := matching[i], matching[j]
		if !a.WindowStart.Equal(b.WindowStart) {
			return a.WindowStart.After(b.WindowStart)
		}
		if a.Analyst != b.Analyst {
			return a.Analyst < b.Analyst
		}
		return a.Provider < b.Provider
	})
	out := adminapi.QuotaList{Usage: []adminapi.QuotaUsage{}}
	for _, u := range matching {
		row := adminapi.QuotaUsage{AnalystIdentity: u.Analyst, Account: u.Provider, WindowStart: u.WindowStart, Used: u.Used}
		if p, ok := declared[u.Provider]; ok {
			limit, remaining, end := p.Limit, max(p.Limit-u.Used, 0), u.WindowStart.Add(p.Window)
			row.Limit, row.Remaining, row.WindowEnd = &limit, &remaining, &end
		}
		out.Usage = append(out.Usage, row)
	}
	return out, nil
}

// Upstreams returns the registered backends.
func (s *Service) Upstreams(ctx context.Context) (adminapi.UpstreamList, error) {
	cfg, err := s.config()
	if err != nil {
		return adminapi.UpstreamList{}, err
	}
	if s.d.Upstreams == nil {
		return adminapi.UpstreamList{Upstreams: []adminapi.Upstream{}}, nil
	}
	ups, err := s.d.Upstreams(ctx, cfg)
	if err != nil {
		return adminapi.UpstreamList{}, s.storeErr("upstream registry", err)
	}
	if ups == nil {
		ups = []adminapi.Upstream{}
	}
	if s.d.Health != nil {
		names := make([]string, len(ups))
		for i, u := range ups {
			names[i] = u.Name
		}
		// A health that cannot be read leaves the list as it is: the
		// registry is what this answers, and the overview says the part
		// is missing.
		if h, _, err := s.health(ctx, names); err != nil {
			s.d.Log.Warn("admin: backend health not read", "detail", err.Error())
		} else {
			byName := map[string]adminapi.BackendHealth{}
			for _, b := range h.Backends {
				byName[b.Name] = b
			}
			for i := range ups {
				b := byName[ups[i].Name]
				ups[i].Health = &b
			}
		}
	}
	return adminapi.UpstreamList{Upstreams: ups}, nil
}
