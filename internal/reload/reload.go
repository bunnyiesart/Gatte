// Package reload decides what a configuration reload of a running gateway
// changes (design/adr/0044), before anything is changed: which keys it
// applies, which keys differ and are NOT applied until a restart, and who
// gains and loses which tool.
//
// It holds no state and touches nothing. The composition root reads the
// file, asks this package for the plan and the diff, hands the new policy
// and quota gate to the Gateway, and records the diff on the trail.
package reload

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/config"
)

// Reloadable are the top-level configuration keys a reload applies. The
// operator's lines for analysts ([analyst], design/adr/0042 item 3) are
// not among them: the MCP endpoint builds its instructions once, when
// serve starts, so a change to them is reported by NotReloaded until the
// next restart.
var Reloadable = []string{"role", "group_to_role", "quota"}

// RoleChange is what one role reaches before and after the reload, over
// the tools the gateway routes now.
type RoleChange struct {
	Role    string
	Added   bool
	Removed bool
	// Gained and Lost are namespaced tool names, sorted.
	Gained []string
	Lost   []string
}

// GroupChange is one [group_to_role] key whose role changed. From or To is
// empty when the group was added or removed.
type GroupChange struct {
	Group string
	From  string
	To    string
}

// QuotaChange is one account of [quota] that was added, removed or
// changed, with a one-line summary of each side.
type QuotaChange struct {
	Account string
	Change  string // "added", "removed" or "changed"
	From    string
	To      string
}

// Changes is the whole diff of one reload.
type Changes struct {
	Roles  []RoleChange
	Groups []GroupChange
	Quota  []QuotaChange
	// FreeToolsChanged reports a change to quota.free_tools.
	FreeToolsChanged bool
	// NotReloaded are the keys (dotted, e.g. "signer.trusted_keys") whose
	// value differs from the file the process booted with and which a
	// reload does not apply. They take effect at the next restart.
	NotReloaded []string
}

// Empty reports a reload that changes nothing the gateway applies.
func (c Changes) Empty() bool {
	return len(c.Roles) == 0 && len(c.Groups) == 0 && len(c.Quota) == 0 && !c.FreeToolsChanged
}

// Diff compares the configuration in force (old) with the one just read
// and validated (next). routed is the set of namespaced tools the gateway
// routes now, the set reachability is measured over.
func Diff(old, next *config.Config, routed []string) Changes {
	var c Changes
	c.Roles = roleChanges(old.Roles, next.Roles, routed)
	c.Groups = groupChanges(old.GroupToRole, next.GroupToRole)
	c.Quota = quotaChanges(old.Quota.Providers, next.Quota.Providers)
	c.FreeToolsChanged = !slices.Equal(sortedCopy(old.Quota.FreeTools), sortedCopy(next.Quota.FreeTools))
	c.NotReloaded = NotReloaded(old, next)
	return c
}

func sortedCopy(xs []string) []string {
	out := slices.Clone(xs)
	slices.Sort(out)
	return out
}

func toAccess(r config.Role) access.Role {
	return access.Role{Name: r.Name, Tools: r.Tools, Grants: r.Grants}
}

func reach(r config.Role, routed []string) map[string]bool {
	ar := toAccess(r)
	out := map[string]bool{}
	for _, t := range routed {
		if ar.Allows(t) {
			out[t] = true
		}
	}
	return out
}

func roleChanges(old, next []config.Role, routed []string) []RoleChange {
	before := map[string]config.Role{}
	for _, r := range old {
		before[r.Name] = r
	}
	after := map[string]config.Role{}
	for _, r := range next {
		after[r.Name] = r
	}
	names := slices.Sorted(maps.Keys(before))
	for n := range after {
		if _, ok := before[n]; !ok {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	var out []RoleChange
	for _, n := range names {
		b, hadB := before[n]
		a, hasA := after[n]
		var rb, ra map[string]bool
		if hadB {
			rb = reach(b, routed)
		}
		if hasA {
			ra = reach(a, routed)
		}
		ch := RoleChange{Role: n, Added: !hadB, Removed: !hasA}
		for t := range ra {
			if !rb[t] {
				ch.Gained = append(ch.Gained, t)
			}
		}
		for t := range rb {
			if !ra[t] {
				ch.Lost = append(ch.Lost, t)
			}
		}
		slices.Sort(ch.Gained)
		slices.Sort(ch.Lost)
		// A role whose grant was rewritten but reaches the same tools is
		// not a change of reachability; an added or removed role is always
		// shown, even reaching nothing.
		if ch.Added || ch.Removed || len(ch.Gained) > 0 || len(ch.Lost) > 0 {
			out = append(out, ch)
		}
	}
	return out
}

func groupChanges(old, next map[string]string) []GroupChange {
	keys := slices.Sorted(maps.Keys(old))
	for k := range next {
		if _, ok := old[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []GroupChange
	for _, k := range keys {
		if old[k] != next[k] {
			out = append(out, GroupChange{Group: k, From: old[k], To: next[k]})
		}
	}
	return out
}

func quotaSummary(p config.QuotaProvider) string {
	tools := slices.Clone(p.Tools)
	slices.Sort(tools)
	return fmt.Sprintf("%d per %s on %s: %s", p.Limit, p.Window, p.Upstream, strings.Join(tools, ", "))
}

func quotaChanges(old, next []config.QuotaProvider) []QuotaChange {
	before := map[string]config.QuotaProvider{}
	for _, p := range old {
		before[p.Name] = p
	}
	after := map[string]config.QuotaProvider{}
	for _, p := range next {
		after[p.Name] = p
	}
	names := slices.Sorted(maps.Keys(before))
	for n := range after {
		if _, ok := before[n]; !ok {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	var out []QuotaChange
	for _, n := range names {
		b, hadB := before[n]
		a, hasA := after[n]
		switch {
		case !hadB:
			out = append(out, QuotaChange{Account: n, Change: "added", To: quotaSummary(a)})
		case !hasA:
			out = append(out, QuotaChange{Account: n, Change: "removed", From: quotaSummary(b)})
		case quotaSummary(a) != quotaSummary(b):
			out = append(out, QuotaChange{Account: n, Change: "changed", From: quotaSummary(b), To: quotaSummary(a)})
		}
	}
	return out
}

// NotServe are the keys serve never reads: the commands that use them read
// the file on every run (sign reads signer.key_file; the management backend
// reads [idp], [connect] and [admin] per request), so a difference in them
// needs no restart and is not reported as one.
var NotServe = []string{"signer.key_file", "idp", "connect", "admin"}

func notServe(key string) bool {
	for _, k := range NotServe {
		if key == k || strings.HasPrefix(key, k+".") {
			return true
		}
	}
	return false
}

// NotReloaded lists, dotted and sorted, the keys outside Reloadable whose
// value differs between old and next: a struct-valued key is compared one
// level down ("signer.trusted_keys"), anything else as a whole ("listen").
// The keys of NotServe are left out.
func NotReloaded(old, next *config.Config) []string {
	var out []string
	ov, nv := reflect.ValueOf(*old), reflect.ValueOf(*next)
	t := ov.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		key := tomlKey(f)
		if key == "" || slices.Contains(Reloadable, key) {
			continue
		}
		a, b := ov.Field(i), nv.Field(i)
		if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Time{}) {
			for j := 0; j < f.Type.NumField(); j++ {
				sub := tomlKey(f.Type.Field(j))
				if sub == "" {
					continue
				}
				if !notServe(key+"."+sub) && !reflect.DeepEqual(a.Field(j).Interface(), b.Field(j).Interface()) {
					out = append(out, key+"."+sub)
				}
			}
			continue
		}
		if !notServe(key) && !reflect.DeepEqual(a.Interface(), b.Interface()) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

func tomlKey(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	tag, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
	if tag == "-" {
		return ""
	}
	return tag
}

// Summary renders c as one line for an audit row's reason, at most max
// bytes: what the reload applied, then what it did not. Tool and role
// names come from the operator's own file and the gateway's routing
// table; they are quoted where they could carry a separator.
func Summary(c Changes, max int) string {
	var parts []string
	for _, r := range c.Roles {
		var s strings.Builder
		fmt.Fprintf(&s, "role %q", r.Role)
		switch {
		case r.Added:
			s.WriteString(" added")
		case r.Removed:
			s.WriteString(" removed")
		}
		for _, t := range r.Gained {
			s.WriteString(" +" + t)
		}
		for _, t := range r.Lost {
			s.WriteString(" -" + t)
		}
		parts = append(parts, s.String())
	}
	for _, g := range c.Groups {
		parts = append(parts, fmt.Sprintf("group %q: %s -> %s", g.Group, orNone(g.From), orNone(g.To)))
	}
	for _, q := range c.Quota {
		parts = append(parts, fmt.Sprintf("quota %q %s", q.Account, q.Change))
	}
	if c.FreeToolsChanged {
		parts = append(parts, "quota.free_tools changed")
	}
	if len(parts) == 0 {
		parts = append(parts, "no change to roles, groups or quota")
	}
	out := strings.Join(parts, "; ")
	if len(c.NotReloaded) > 0 {
		out += "; NOT applied until restart: " + strings.Join(c.NotReloaded, ", ")
	}
	if max > 0 && len(out) > max {
		const cut = " ... (truncated; the full diff is in the request result)"
		n := max - len(cut)
		if n < 0 {
			n = 0
		}
		for n > 0 && !utf8.RuneStart(out[n]) {
			n--
		}
		out = out[:n] + cut
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("%q", s)
}
