package reload

import (
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/config"
)

// design/adr/0048 Decisão 5 named this package's toAccess as the reason a
// check made only at clearance time would not survive a reload: it rebuilt
// every role from Name, Tools and Grants and dropped the non_read marking.
// These tests hold the two fixes: the marking survives the conversion, and
// a reload that flips it is reported, since it changes which sensitive
// tools the role reaches from the next call on.

func TestToAccess_PreservesNonRead(t *testing.T) {
	for _, nonRead := range []bool{true, false} {
		r := config.Role{Name: "actor", Tools: []string{"casemgmt.close_case"}, NonRead: nonRead}
		if got := toAccess(r); got.NonRead != nonRead {
			t.Errorf("toAccess(NonRead=%v).NonRead = %v: the marking is dropped on reload", nonRead, got.NonRead)
		}
	}
}

func TestDiff_AFlippedNonReadMarkingIsReported(t *testing.T) {
	old, next := base(), base()
	old.Roles = append(old.Roles, config.Role{Name: "actor", Tools: []string{"casemgmt.close_case"}})
	next.Roles = append(next.Roles, config.Role{Name: "actor", Tools: []string{"casemgmt.close_case"}, NonRead: true})
	c := Diff(old, next, routed)
	if len(c.Roles) != 1 || c.Roles[0].Role != "actor" || !c.Roles[0].NonReadChanged || !c.Roles[0].NonRead {
		t.Fatalf("Diff = %+v, want the actor role with non_read flipped on", c.Roles)
	}
	// Allows is class-blind, so reach over the routed tools is unchanged:
	// the marking is the only thing the row says.
	if len(c.Roles[0].Gained)+len(c.Roles[0].Lost)+len(c.Roles[0].GrantsAdded)+len(c.Roles[0].GrantsRemoved) != 0 {
		t.Errorf("a flipped marking moved tools or grants: %+v", c.Roles[0])
	}
	if c.Empty() {
		t.Error("a reload that flips non_read reports Empty")
	}
	if s := Summary(c, 0); !strings.Contains(s, `role "actor" non_read=true`) {
		t.Errorf("Summary = %q, want the flipped marking named", s)
	}

	// Unchanged either way: not a row.
	same := Diff(next, next, routed)
	if len(same.Roles) != 0 {
		t.Errorf("an unchanged marking produced a row: %+v", same.Roles)
	}
}
