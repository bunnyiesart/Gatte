package gattetui

// Blocklist, a section of the Users tab (design/adr/0051), on the operator
// socket (design/adr/0031). A block cuts off an already-issued token: the
// gateway refuses the subject's next request whatever token they hold. It is
// not disabling an account, which only stops new sign-ins and lives in
// People (design/adr/0038).

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

func init() {
	registerUsersSection(UsersSection{ID: "blocklist", Order: 30, Rows: blocklistSection})
}

var blockCols = []int{18, 12, 18}

func blocklistSection(e env) ([]row, error) {
	rows := []row{heading("Blocklist"),
		// The block control stays usable through a failed read of the list.
		{text: stKey.Render("+ Block a subject"), actions: []action{{key: "enter", label: "block", run: func() tea.Cmd { return block(e) }}}}}
	list, err := e.op.ListBlocks(ctx())
	if err != nil {
		return append(rows, textRow(stBad.Render("The blocklist could not be read: "+vis(errText(err))))), nil
	}
	if len(list.Blocks) == 0 {
		rows = append(rows, textRow(stDim.Render("Nobody is blocked.")))
	}
	for _, b := range list.Blocks {
		subject := b.Subject
		end := stBad.Render("blocked")
		switch {
		case b.Expired:
			end = stDim.Render("expired " + showTimePtr(b.Until))
		case b.Until != nil:
			end = stBad.Render("until " + showTimePtr(b.Until))
		}
		rows = append(rows, row{
			text: cols(blockCols, vis(b.Subject), vis(b.BlockedBy), stDim.Render(showTime(b.BlockedAt)), end+"  "+vis(b.Reason)),
			actions: []action{{key: "u", label: "unblock", run: func() tea.Cmd {
				return confirm("Unblock "+vis(subject)+"? Their next request is served again.", func() tea.Cmd {
					return do(func() result {
						res, err := e.op.UnblockSubject(ctx(), adminapi.BlockRequest{Subject: subject})
						return fromAction(res.ActionResult, err, "Unblocked "+subject+".")
					})
				})
			}}},
		})
	}
	return rows, nil
}

func block(e env) tea.Cmd {
	return ask("Subject to block (the analyst identity, the token's sub)", "", func(subject string) tea.Cmd {
		return ask("Reason", "", func(reason string) tea.Cmd {
			send := func(until *time.Time) tea.Cmd {
				q := "Block " + vis(subject) + " from their next request on"
				if until != nil {
					q += " until " + showTimePtr(until)
				}
				return confirm(q+"?", func() tea.Cmd {
					return do(func() result {
						res, err := e.op.BlockSubject(ctx(), adminapi.BlockRequest{Subject: subject, Reason: strings.TrimSpace(reason), Until: until})
						return fromAction(res.ActionResult, err, "Blocked "+subject+".")
					})
				})
			}
			if !e.has(adminapi.FeatureBlockUntil) {
				return send(nil)
			}
			return ask("Ends (empty for no end, 8h, or UTC 2026-09-30 14:00)", "", func(raw string) tea.Cmd {
				until, ok := untilOf(raw, time.Now())
				if !ok {
					return do(func() result {
						return refused("Nothing was sent: \"" + vis(raw) + "\" is not a duration such as 8h or a UTC time such as 2026-09-30 14:00.")
					})
				}
				return send(until)
			})
		})
	})
}
