package gattetui

import (
	"strconv"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// A form is the terminal's multi-field form: a page with one row per field.
// enter on a row edits that field (a prompt for text, a menu for a fixed
// choice), and one page action sends the whole form. The front checks a
// typed value only for what must never be drawn again (a credential pasted
// into a name or a URL); every other rule is the API's.
type form struct {
	title string
	intro []string
	// submitKey and submitLabel are the page action that sends the form.
	submitKey, submitLabel string
	fields                 []*field
	// send runs off the update loop with a copy of the values, by field id.
	send func(e env, v map[string]string) result

	// mu guards the values: a field is set on the update loop and read by
	// the page's fill and by send, which run off it.
	mu sync.Mutex
}

// A field is one row of a form. With choices it is set from a menu and
// holds one choice's value; otherwise it is typed.
type field struct {
	id, label, hint string
	choices         []choice
	value           string
	// guard returns why a typed value is not kept, without repeating it, or
	// "" to keep it.
	guard func(string) string
}

type choice struct{ value, label string }

func (f *form) values() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := make(map[string]string, len(f.fields))
	for _, fl := range f.fields {
		v[fl.id] = fl.value
	}
	return v
}

func (f *form) set(fl *field, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl.value = v
}

func (f *form) get(fl *field) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fl.value
}

func formPage(f *form) *page {
	return newPage(f.title, func(e env) content { return f.fill(e) })
}

func (f *form) fill(e env) content {
	var c content
	for _, l := range f.intro {
		c.rows = append(c.rows, para(l, stDim)...)
	}
	if len(f.intro) > 0 {
		c.rows = append(c.rows, blank())
	}
	for _, fl := range f.fields {
		c.rows = append(c.rows, row{text: cols([]int{28}, fl.label, f.shown(fl)), actions: []action{{key: "enter", label: "edit", run: func() tea.Cmd { return f.edit(fl) }}}})
	}
	c.actions = []action{{key: f.submitKey, label: f.submitLabel, run: func() tea.Cmd {
		v := f.values()
		return do(func() result { return f.send(e, v) })
	}}}
	return c
}

// shown is a field's value as drawn: a choice by its label, an empty text
// field by its hint.
func (f *form) shown(fl *field) string {
	v := f.get(fl)
	for _, ch := range fl.choices {
		if ch.value == v {
			return ch.label
		}
	}
	if v == "" {
		return stDim.Render(fl.hint)
	}
	return vis(v)
}

func (f *form) edit(fl *field) tea.Cmd {
	if len(fl.choices) > 0 {
		items := make([]action, 0, len(fl.choices))
		for i, ch := range fl.choices {
			items = append(items, action{key: strconv.Itoa(i + 1), label: ch.label, run: func() tea.Cmd {
				f.set(fl, ch.value)
				return fieldSet(fl.label)
			}})
		}
		return openMenu(fl.label, items)
	}
	return ask(fl.label, f.get(fl), func(typed string) tea.Cmd {
		typed = strings.TrimSpace(typed)
		if fl.guard != nil {
			if why := fl.guard(typed); why != "" {
				return do(func() result { return refused("Not kept: " + why) })
			}
		}
		f.set(fl, typed)
		return fieldSet(fl.label)
	})
}

// para is running text wrapped into rows, so a sentence is not cut at the
// panel's edge. s is already escaped.
func para(s string, st lipgloss.Style) []row {
	var out []row
	for _, l := range strings.Split(lipgloss.NewStyle().Width(paraWidth).Render(s), "\n") {
		out = append(out, textRow(st.Render(strings.TrimRight(l, " "))))
	}
	return out
}

const paraWidth = 92

// fieldSet answers an edit; the result also has the form drawn again.
func fieldSet(label string) tea.Cmd {
	return do(func() result { return result{ok: true, summary: label + " set."} })
}
