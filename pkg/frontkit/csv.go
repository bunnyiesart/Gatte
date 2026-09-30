package frontkit

import "strings"

// CSVCell is one cell of a CSV a front hands the operator to open in a
// spreadsheet (design/adr/0046 item 1). Every value in the trail is
// somebody else's text -- a subject is the IdP's, a tool name whatever a
// caller probed, a reason may quote either -- so the cell is made safe
// twice over:
//
//   - every code point a screen would not show is written visibly, as
//     VisibleText writes it, so a bidi override or a zero-width space
//     cannot make a row read as something else, and a newline cannot
//     split one row into two;
//   - a cell a spreadsheet would evaluate as a formula -- one starting
//     with =, +, -, @, a tab or a carriage return, raw or once escaped --
//     is prefixed with an apostrophe, which spreadsheets take as "this is
//     text" (CSV injection).
//
// Quoting of commas and double quotes is the CSV writer's job
// (encoding/csv), not this function's.
func CSVCell(s string) string {
	v := VisibleText(s)
	if formulaStart(s) || formulaStart(v) {
		return "'" + v
	}
	return v
}

func formulaStart(s string) bool {
	return s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0]))
}
