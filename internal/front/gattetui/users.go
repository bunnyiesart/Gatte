package gattetui

// Tab 2, "Users" (design/adr/0051): one page of sections, each with its own
// socket gate. People, Roles and Blocklist register from their own files.
// People and Blocklist stay distinct: disabling an account is not blocking a
// subject (design/adr/0038).

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
