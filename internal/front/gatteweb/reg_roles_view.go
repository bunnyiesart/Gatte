package gatteweb

// The read-only Roles view takes the Roles slot (Order 20) exactly when the
// editable role list of reg_roles_panel.go does not, so the Users tab shows one
// Roles section either way: editable with the managing console and the
// accounts socket, read-only otherwise.
func init() {
	registerUsersSection(UsersSection{
		ID:     "roles-view",
		Order:  20,
		Show:   func(c Capabilities) bool { return !managesAndRoot(c) },
		Render: (*Front).rolesViewSection,
	})
}
