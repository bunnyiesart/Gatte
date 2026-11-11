package frontkit

import "strings"

// DefaultKeyName is the vault name a keyed backend gets when an add form
// leaves it empty: the backend name in capitals, then _API_KEY, as an
// environment variable name. Both fronts use it, so a backend added from
// either one gets the same name.
func DefaultKeyName(name string) string {
	var b strings.Builder
	for _, c := range strings.ToUpper(strings.TrimSpace(name)) {
		if c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return s + "_API_KEY"
}
