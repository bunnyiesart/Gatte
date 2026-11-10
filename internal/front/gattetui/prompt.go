package gattetui

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// A prompt is the one line of input the front asks for: a value, a value
// typed hidden (a secret), or a yes/no. It is the terminal's form: what it
// collects is sent to the API as typed, and the API decides.
type prompt struct {
	label  string
	masked bool
	yesNo  bool
	buf    []rune
	done   func(string) tea.Cmd
}

// ask prompts for one value; initial pre-fills it.
func ask(label, initial string, done func(string) tea.Cmd) tea.Cmd {
	p := &prompt{label: label, buf: []rune(initial), done: done}
	return func() tea.Msg { return promptMsg{p} }
}

// askHidden prompts for a value that is never drawn: a secret's value.
func askHidden(label string, done func(string) tea.Cmd) tea.Cmd {
	p := &prompt{label: label, masked: true, done: done}
	return func() tea.Msg { return promptMsg{p} }
}

// confirm asks a yes/no question; anything but y sends nothing.
func confirm(question string, then func() tea.Cmd) tea.Cmd {
	p := &prompt{label: question + " (y/N)", yesNo: true, done: func(string) tea.Cmd { return then() }}
	return func() tea.Msg { return promptMsg{p} }
}

// wipe clears what was typed, so a secret does not outlive the prompt.
func (p *prompt) wipe() {
	for i := range p.buf {
		p.buf[i] = 0
	}
	p.buf = nil
}

func (p *prompt) view() string {
	if p.yesNo {
		return stWarn.Render(p.label) + " "
	}
	shown := string(p.buf)
	if p.masked {
		shown = strings.Repeat("*", len(p.buf))
	}
	return stBold.Render(p.label) + ": " + vis(shown) + stCursor.Render(" ")
}

// ---- results

// A result is what the front shows after an action: one plain sentence, and
// what the backend said under it. secret is a one-time password, shown on
// this result only and wiped by the next key. back pops the page (the thing
// it showed is gone); next runs right after it is shown (a follow-up
// question, such as reloading after a roles write).
type result struct {
	ok      bool
	summary string
	output  []string
	secret  string
	label   string
	back    bool
	next    tea.Cmd
}

func (r *result) lines() []string {
	st := stBad
	if r.ok {
		st = stOK
	}
	out := []string{st.Render(vis(r.summary))}
	for _, l := range r.output {
		out = append(out, "  "+vis(l))
	}
	if r.secret != "" {
		out = append(out, stWarn.Render("  "+r.label+": ")+stBold.Render(vis(r.secret)),
			stDim.Render("  Shown once and never kept. Hand it over now; the next key wipes it."))
	}
	return out
}

// errText is what the front says about a failed call: the backend's own
// sentence for a refusal, and that it did not answer otherwise.
func errText(err error) string {
	if err == nil {
		return ""
	}
	var ae *adminapi.Error
	if errors.As(err, &ae) {
		return ae.Message
	}
	if errors.Is(err, adminapi.ErrImpostor) {
		return err.Error()
	}
	return "The management API did not answer: " + err.Error()
}

func refused(msg string) result { return result{summary: msg} }

// fromAction is the result of a state change, as the web console reads it:
// a change the trail could not record is shown as made and unrecorded, since
// it is in force and the operator has to know the trail lacks it.
func fromAction(res adminapi.ActionResult, err error, done string) result {
	if err != nil {
		text := errText(err)
		return result{summary: "Refused: " + firstLine(text), output: restLines(text)}
	}
	r := result{ok: true, summary: done}
	r.output = append(r.output, res.Messages...)
	for _, w := range res.Warnings {
		r.output = append(r.output, "WARNING: "+w.Message)
	}
	if res.Changed && !res.Recorded {
		why := "the audit trail could not record it"
		for _, w := range res.Warnings {
			if w.Code == adminapi.WarnAuditWriteFailed {
				why += ": " + w.Message
			}
		}
		r.ok, r.summary = false, "The change was made, but "+why
	}
	if res.Audit != nil {
		r.output = append(r.output, "Recorded as "+res.Audit.Tool+" by "+res.Audit.Identity+".")
	}
	return r
}

func firstLine(text string) string {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			return l
		}
	}
	return ""
}

func restLines(text string) []string {
	ls := strings.Split(strings.TrimSpace(text), "\n")
	if len(ls) <= 1 {
		return nil
	}
	return ls[1:]
}
