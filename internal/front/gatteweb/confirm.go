package gatteweb

// The confirm interstitial (design/adr/0036: zero script). The TUI stops at a
// y/N before every state change; the web console used to fire the consequential
// ones on a single click. This is the parity: a GET "Confirm <action>" page with
// one sentence and one POST button, so the change still takes two deliberate
// steps. The POST is the same-named management action (design/adr/0040 §6), with
// the form token and Origin check frontkit holds on every POST unchanged; this
// page adds no rule and only draws the pause.
//
// Idempotent or reversible actions (Reconnect, Reload, Approve again) stay one
// click: a second click is no safer there. The destructive ones -- Revoke
// approval, Disable, Offboard, Clear -- route through here.

import "net/http"

// confirmView is a "Confirm <action>" page: the back link, one sentence of
// consequence, an optional louder warning, the POST that carries it out, and the
// single button that sends it.
type confirmView struct {
	// Back is where the back arrow and Cancel return to (the page the action
	// was reached from), base included.
	Back      string
	BackLabel string
	// Lead is the one sentence that says what the action does.
	Lead string
	// Warn, when set, is a louder consequence drawn in a danger notice (the
	// offboard whose empty subject blocks nothing).
	Warn string
	// Caption is quieter supporting text under the button.
	Caption string
	// Action is the POST target, base included: the same-named API action.
	Action string
	// Hidden are the form fields the GET could not put in the path (a username),
	// carried through to the POST.
	Hidden []confirmHidden
	// Fields are visible inputs the action still needs (the offboard subject and
	// reason). Empty for a plain confirm.
	Fields []confirmField
	// Button is the confirm button's label. Danger draws it as destructive and
	// the icon in the danger colour; a consequential-but-not-destroying action
	// (Clear) leaves it off.
	Button string
	Danger bool
}

// confirmHidden is one hidden form field repeated on the POST.
type confirmHidden struct{ Name, Value string }

// confirmField is one visible input on a confirm page.
type confirmField struct {
	Name, Label, Placeholder string
	Mono                     bool
}

// confirm renders the interstitial. nav keeps the right tab current; title is
// the page's "Confirm <action>" heading.
func (f *Front) confirm(w http.ResponseWriter, r *http.Request, nav, title string, v confirmView) {
	f.render(w, r, "confirm", title, page{Nav: nav, Data: v})
}
