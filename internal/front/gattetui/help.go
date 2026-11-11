package gattetui

// The help screen, opened with ? from anywhere: the commands, the words the
// screens use, and where the guides are. One line each.

// Command is one mcp-gateway command and what it does.
type Command struct{ Name, Does string }

// Commands are the mcp-gateway commands. A test in cmd/mcp-gateway fails
// when its usage text lists a command missing here.
var Commands = []Command{
	{"serve", "Run the gateway."},
	{"upstream", "Register, list, update or remove a backend."},
	{"tool", "List, review, approve, revoke or clear tools."},
	{"sign", "Sign a registry entry so the gateway will serve it."},
	{"audit", "Read the audit trail."},
	{"quota", "Show the limits and what each analyst has spent."},
	{"access", "Block or unblock one analyst, or list who is blocked."},
	{"maintenance", "Announce planned maintenance, or list it."},
	{"reload", "Apply the roles file and quota to the running gateway."},
	{"admin", "Serve the management API (for the consoles)."},
	{"ui", "The operator console as a web page."},
	{"tui", "The operator console in this terminal."},
	{"check", "Check the configuration and files offline."},
	{"backup", "Copy the database while serve runs."},
	{"restore", "Replace the database from a backup."},
	{"version", "Print the build version."},
}

var helpWords = [][2]string{
	{"Config approved", "an operator approved this backend's entry"},
	{"Changed since approved", "the entry changed; approve it again"},
	{"Tool changed", "the tool changed since approved; review it again"},
	{"safe tool", "reads only; served once approved"},
	{"sensitive tool", "can change things; served once approved and cleared"},
	{"non_read", "a role marked non_read may hold sensitive tools it names"},
	{"roles file", "grants are written here; reload applies them"},
}

var helpKeys = [][2]string{
	{"tab, 1-9", "switch tab"},
	{"up/down, enter", "move, open"},
	{"space, g, v", "select, grant, revoke on a role page"},
	{"n", "turn non_read on or off on a role page"},
	{"esc, h, left, backspace", "back"},
	{"r", "refresh"},
	{"?", "this help"},
	{"q", "quit"},
}

var helpDocs = []string{
	"docs/command-guide.md",
	"docs/how-to/change-roles-and-quota.md",
	"docs/how-to/add-and-remove-people.md",
	"docs/how-to/review-and-approve-tools.md",
	"docs/explanation/quarantine-and-signing.md",
}

func helpPage() *page {
	p := newPage("Help", func(env) content {
		rows := []row{heading("Commands")}
		for _, c := range Commands {
			rows = append(rows, textRow(cols([]int{24}, "mcp-gateway "+c.Name, stDim.Render(c.Does))))
		}
		rows = append(rows, blank(), heading("Words"))
		for _, w := range helpWords {
			rows = append(rows, textRow(cols([]int{24}, w[0], stDim.Render(w[1]))))
		}
		rows = append(rows, blank(), heading("Keys"))
		for _, k := range helpKeys {
			rows = append(rows, textRow(cols([]int{24}, k[0], stDim.Render(k[1]))))
		}
		rows = append(rows, blank(), heading("Guides"))
		for _, d := range helpDocs {
			rows = append(rows, textRow(d))
		}
		return content{rows: rows}
	})
	p.help = true
	return p
}
