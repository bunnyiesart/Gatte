// Package autheliafile is the idp.Directory adapter for Authelia's file
// authentication backend: a YAML file mapping each username to its display
// name, argon2 password hash, email, groups and disabled flag.
//
// Edits go through the YAML node tree, so comments, key order and every
// account the edit does not touch are written back as they were. A write
// is a temporary file in the same directory, given the original's mode and
// owner, synced and renamed over it, so Authelia never reads half a file.
package autheliafile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/bunnyiesart/Gatte/internal/idp"
)

// File is one Authelia users database.
type File struct {
	path string
}

// New returns the adapter for the users file at path.
func New(path string) *File { return &File{path: path} }

var _ idp.Directory = (*File)(nil)

func (f *File) load() (*yaml.Node, *yaml.Node, error) {
	b, err := os.ReadFile(f.path)
	if err != nil {
		return nil, nil, fmt.Errorf("idp users file: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, nil, fmt.Errorf("idp users file %s: %w", f.path, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("idp users file %s: not a YAML mapping", f.path)
	}
	users := mapValue(doc.Content[0], "users")
	if users == nil || users.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("idp users file %s: no \"users\" map; is this an Authelia file-backend database?", f.path)
	}
	return &doc, users, nil
}

// Accounts returns every account, in file order.
func (f *File) Accounts() ([]idp.Account, error) {
	_, users, err := f.load()
	if err != nil {
		return nil, err
	}
	out := make([]idp.Account, 0, len(users.Content)/2)
	for i := 0; i+1 < len(users.Content); i += 2 {
		out = append(out, toAccount(users.Content[i].Value, users.Content[i+1]))
	}
	return out, nil
}

func toAccount(name string, n *yaml.Node) idp.Account {
	a := idp.Account{Username: name}
	if n.Kind != yaml.MappingNode {
		return a
	}
	if v := mapValue(n, "displayname"); v != nil {
		a.DisplayName = v.Value
	}
	if v := mapValue(n, "email"); v != nil {
		a.Email = v.Value
	}
	if v := mapValue(n, "disabled"); v != nil {
		a.Disabled = v.Value == "true"
	}
	if v := mapValue(n, "groups"); v != nil && v.Kind == yaml.SequenceNode {
		for _, g := range v.Content {
			a.Groups = append(a.Groups, g.Value)
		}
	}
	return a
}

// Add appends a new account holding passwordHash.
func (f *File) Add(a idp.Account, passwordHash string) error {
	if err := idp.ValidateAccount(a); err != nil {
		return err
	}
	doc, users, err := f.load()
	if err != nil {
		return err
	}
	if mapValue(users, a.Username) != nil {
		return fmt.Errorf("%q: %w", a.Username, idp.ErrExists)
	}
	acct := &yaml.Node{Kind: yaml.MappingNode}
	setScalar(acct, "disabled", boolString(a.Disabled), "!!bool")
	setScalar(acct, "displayname", a.DisplayName, "")
	setScalar(acct, "password", passwordHash, "")
	if a.Email != "" {
		setScalar(acct, "email", a.Email, "")
	}
	setGroups(acct, a.Groups)
	users.Content = append(users.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: a.Username}, acct)
	return f.write(doc)
}

// SetGroups replaces username's groups.
func (f *File) SetGroups(username string, groups []string) error {
	for _, g := range groups {
		if err := idp.ValidateGroup(g); err != nil {
			return err
		}
	}
	return f.edit(username, func(n *yaml.Node) { setGroups(n, groups) })
}

// SetDisabled sets username's disabled flag.
func (f *File) SetDisabled(username string, disabled bool) error {
	return f.edit(username, func(n *yaml.Node) { setScalar(n, "disabled", boolString(disabled), "!!bool") })
}

// SetPassword replaces username's password hash.
func (f *File) SetPassword(username, passwordHash string) error {
	return f.edit(username, func(n *yaml.Node) { setScalar(n, "password", passwordHash, "") })
}

// Delete removes username's entry, keeping every other account, comment
// and key order as they were.
func (f *File) Delete(username string) error {
	doc, users, err := f.load()
	if err != nil {
		return err
	}
	for i := 0; i+1 < len(users.Content); i += 2 {
		if users.Content[i].Value == username {
			users.Content = append(users.Content[:i:i], users.Content[i+2:]...)
			return f.write(doc)
		}
	}
	return fmt.Errorf("%q: %w", username, idp.ErrNotFound)
}

func (f *File) edit(username string, fn func(*yaml.Node)) error {
	doc, users, err := f.load()
	if err != nil {
		return err
	}
	n := mapValue(users, username)
	if n == nil || n.Kind != yaml.MappingNode {
		return fmt.Errorf("%q: %w", username, idp.ErrNotFound)
	}
	fn(n)
	return f.write(doc)
}

// write replaces the file atomically, keeping its mode and owner.
func (f *File) write(doc *yaml.Node) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("idp users file: encoding: %w", err)
	}
	if err := enc.Close(); err != nil {
		return err
	}
	st, err := os.Stat(f.path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), "."+filepath.Base(f.path)+".*")
	if err != nil {
		return fmt.Errorf("idp users file: %w", err)
	}
	name := tmp.Name()
	// Cleanup after a failed write is best effort: the error returned is
	// the one that stopped the write.
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("idp users file: %w", err)
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		return fail(err)
	}
	if uid, gid, ok := ownerOf(st); ok {
		if err := chownFile(tmp, int(uid), int(gid)); err != nil {
			if !errors.Is(err, os.ErrPermission) {
				return fail(err)
			}
			// Without the privilege to hand the file over, the rewrite is
			// fine only when the new file already has the original's owner
			// and group (the process owns the file). Otherwise the IdP,
			// reading it through its group (root:www 0640), would lose it
			// at its next reload while the change looked applied.
			tst, serr := tmp.Stat()
			if serr != nil {
				return fail(serr)
			}
			if tu, tg, tok := ownerOf(tst); !tok || tu != uid || tg != gid {
				return fail(fmt.Errorf("cannot keep the owner %d:%d of %s (%v); refusing to replace it with a file the identity provider may not read (the accounts backend needs CAP_CHOWN)", uid, gid, f.path, err))
			}
		}
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("idp users file: %w", err)
	}
	if err := os.Rename(name, f.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("idp users file: %w", err)
	}
	return nil
}

// chownFile and ownerOf are variables so a test can stand in for a process
// without CAP_CHOWN.
var chownFile = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

var ownerOf = func(fi os.FileInfo) (uint32, uint32, bool) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return sys.Uid, sys.Gid, true
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setScalar(m *yaml.Node, key, value, tag string) {
	if v := mapValue(m, key); v != nil {
		*v = yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: tag, Style: v.Style}
		if tag == "" && value != "" && needsQuote(value) {
			v.Style = yaml.DoubleQuotedStyle
		}
		return
	}
	v := &yaml.Node{Kind: yaml.ScalarNode, Value: value, Tag: tag}
	if tag == "" && needsQuote(value) {
		v.Style = yaml.DoubleQuotedStyle
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
}

func setGroups(m *yaml.Node, groups []string) {
	seq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, g := range groups {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: g})
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "groups" {
			m.Content[i+1] = seq
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "groups"}, seq)
}

// needsQuote reports whether a plain scalar would read back as something
// else: a hash starts with '$', a display name may contain ':' or '#'.
func needsQuote(v string) bool {
	var m map[string]any
	if yaml.Unmarshal([]byte("k: "+v), &m) != nil {
		return true
	}
	s, ok := m["k"].(string)
	return !ok || s != v
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
