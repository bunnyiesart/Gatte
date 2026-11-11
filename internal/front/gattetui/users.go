package gattetui

// Tab 2, "Users" (design/adr/0051, 0061 §4): one page of sections, each with
// its own socket gate. People and Roles register from their own files.
// Blocking a subject is not a section: it stays in the CLI.

func init() {
	registerScreen(Screen{ID: "users", Title: "Users", Order: 20, Root: usersPage})
}

func usersPage() *page { return newPage("Users", fillUsers) }

func fillUsers(e env) content {
	var c content
	caps := e.caps()
	for _, s := range orderedUsersSections() {
		if s.Show != nil && !s.Show(caps) {
			continue
		}
		rows, err := s.Rows(e)
		if err != nil {
			c.problems = append(c.problems, s.ID+": "+errText(err))
			continue
		}
		if len(c.rows) > 0 {
			c.rows = append(c.rows, blank())
		}
		c.rows = append(c.rows, rows...)
	}
	return c
}
