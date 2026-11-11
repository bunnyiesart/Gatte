package gattetui

import (
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
	"github.com/bunnyiesart/Gatte/pkg/frontkit"
)

// The look is a classic system UI (design/adr/0061 §1): grey bars, line
// borders bevelled light on one side and dark on the other, square
// [ key Label ] buttons, plain text. Colour is kept for state only, never
// for decoration, and state is always words too, never an emoji or a glyph
// alone: green is fine, yellow needs a look, red is broken or refused. The
// ANSI 16 colours keep to the operator's own terminal palette, and lipgloss
// drops colour where NO_COLOR or a dumb terminal asks it to.
var (
	stOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	stWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	stBad    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	stDim    = lipgloss.NewStyle().Faint(true)
	stBold   = lipgloss.NewStyle().Bold(true)
	stCursor = lipgloss.NewStyle().Reverse(true)

	grey      = lipgloss.Color("7")
	light     = lipgloss.Color("15")
	dark      = lipgloss.Color("8")
	ink       = lipgloss.Color("0")
	stBar     = lipgloss.NewStyle().Background(grey).Foreground(ink)
	stButton  = lipgloss.NewStyle().Background(grey).Foreground(ink)
	stTabOn   = lipgloss.NewStyle().Background(grey).Foreground(ink).Bold(true)
	stTabOff  = lipgloss.NewStyle().Faint(true)
	stMenuSel = lipgloss.NewStyle().Reverse(true).Bold(true)
)

// bevel is a line border lit from the top left: raised for a popup, sunken
// for the page's panel, as a classic window draws them.
func bevel(raised bool) lipgloss.Style {
	hi, lo := light, dark
	if !raised {
		hi, lo = dark, light
	}
	return lipgloss.NewStyle().Border(lipgloss.NormalBorder()).
		BorderTopForeground(hi).BorderLeftForeground(hi).
		BorderBottomForeground(lo).BorderRightForeground(lo).
		Padding(0, 1)
}

// button draws an action as a square [ key Label ] button.
func button(key, label string) string {
	if label != "" {
		label = strings.ToUpper(label[:1]) + label[1:]
	}
	return stButton.Render("[ ") + stBold.Inherit(stButton).Render(key) + stButton.Render(" "+label+" ]")
}

// vis makes untrusted text safe to draw: a control character, an escape
// sequence or a hidden code point is written as \u{XXXX}.
func vis(s string) string { return frontkit.VisibleText(s) }

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

const timeLayout = "2006-01-02 15:04Z"

func showTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(timeLayout)
}

func showTimePtr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return showTime(*t)
}

// cols lays cells out in columns of the given widths; the last cell takes the
// rest of the line. A cell is already escaped and may be styled.
func cols(widths []int, cells ...string) string {
	var b strings.Builder
	for i, c := range cells {
		if i < len(widths) && i < len(cells)-1 {
			w := widths[i]
			c = lipgloss.NewStyle().MaxWidth(w).Render(c)
			c += strings.Repeat(" ", max(1, w-lipgloss.Width(c)+1))
		}
		b.WriteString(c)
	}
	return b.String()
}

func heading(s string) row { return textRow(stBold.Render(s)) }

func blank() row { return textRow("") }

// stateText is a backend's health state in words and colour; an unknown
// state is shown as it came.
func stateText(s string) string {
	switch s {
	case adminapi.BackendUp:
		return stOK.Render("Up")
	case adminapi.BackendReconnecting:
		return stWarn.Render("Reconnecting")
	case adminapi.BackendDown:
		return stBad.Render("Down")
	case adminapi.BackendMaintenance:
		return stWarn.Render("In maintenance")
	case adminapi.BackendUnknown:
		return stDim.Render("Unknown")
	}
	return vis(s)
}

// configText is a backend's signature state in the operator's words
// (design/adr/0061 §2): approving the configuration is an operator's
// signature over the entry, not a claim that the backend is safe.
func configText(s string) string {
	switch s {
	case "yes":
		return stOK.Render("Config approved")
	case "INVALID":
		return stBad.Render("Changed since approved")
	}
	return stBad.Render("Config not approved")
}

func toolStatusText(t adminapi.Tool) string {
	switch t.Status {
	case adminapi.StatusApproved:
		if t.Class == adminapi.ClassSensitive && !t.Usable {
			return stWarn.Render("approved, not cleared")
		}
		return stOK.Render("approved")
	case adminapi.StatusPending:
		return stWarn.Render("pending review")
	case adminapi.StatusChanged:
		return stBad.Render("changed, review again")
	}
	return vis(t.Status)
}

func classText(class string) string {
	if class == adminapi.ClassSensitive {
		return stWarn.Render("sensitive")
	}
	if class == adminapi.ClassSafe {
		return "safe"
	}
	return stWarn.Render(vis(class))
}

// segments draws review segments for the terminal, as frontkit.DrawSegments
// does for HTML: text escaped, a hidden code point or a bad byte as a marked
// \u{XXXX} or \x{XX}, a kind this front does not know shown visibly too.
func segments(segs []adminapi.Segment) string {
	var b strings.Builder
	for _, s := range segs {
		switch s.Kind {
		case adminapi.SegmentText:
			b.WriteString(vis(s.Text))
		case adminapi.SegmentHidden:
			b.WriteString(stBad.Reverse(true).Render(`\u{` + vis(strings.TrimPrefix(s.CodePoint, "U+")) + `}`))
		case adminapi.SegmentInvalidByte:
			b.WriteString(stBad.Reverse(true).Render(`\x{` + vis(s.Byte) + `}`))
		case adminapi.SegmentNewline:
			b.WriteString(" ")
		default:
			b.WriteString(stBad.Reverse(true).Render(vis(s.Text + s.CodePoint + s.Byte)))
		}
	}
	return b.String()
}

// segmentRows draws a multi-line field one row per line.
func segmentRows(indent string, segs []adminapi.Segment) []row {
	var out []row
	for _, line := range frontkit.SplitLines(segs) {
		out = append(out, textRow(indent+segments(line)))
	}
	return out
}

// splitList reads a comma- or space-separated list as typed.
func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}
