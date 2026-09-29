// Package idp is the account side of the identity provider, for the one
// console mode that edits it (design/adr/0038-contas-do-idp-pelo-console.md).
//
// The gateway never reads accounts to decide anything: who may call is
// what the IdP's signed tokens say. This package exists so an operator can
// add a person, set their groups, disable them or reset their password
// without hand-editing the IdP's file. The adapter for Authelia's file
// backend is autheliafile.
package idp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/argon2"
)

// Account is one person in the IdP.
type Account struct {
	Username    string
	DisplayName string
	Email       string
	Groups      []string
	Disabled    bool
}

// Directory is the port the console edits accounts through.
type Directory interface {
	Accounts() ([]Account, error)
	Add(a Account, passwordHash string) error
	SetGroups(username string, groups []string) error
	SetDisabled(username string, disabled bool) error
	SetPassword(username, passwordHash string) error
}

// ErrNotFound is returned for an edit of an account that does not exist.
var ErrNotFound = errors.New("no such account")

// ErrExists is returned when Add names an account that already exists.
var ErrExists = errors.New("an account with that username already exists")

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateAccount refuses what an operator could not have meant: a
// username outside a conservative charset (it becomes a YAML key and a
// login name), control or invisible characters anywhere, an empty display
// name, an email that is not one address.
func ValidateAccount(a Account) error {
	if !usernameRe.MatchString(a.Username) {
		return fmt.Errorf("username %q: use 1-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit", a.Username)
	}
	if strings.TrimSpace(a.DisplayName) == "" || len(a.DisplayName) > 100 || hasControl(a.DisplayName) {
		return errors.New("display name: required, at most 100 characters, no control or invisible characters")
	}
	if a.Email != "" {
		addr, err := mail.ParseAddress(a.Email)
		if err != nil || addr.Address != a.Email || hasControl(a.Email) {
			return fmt.Errorf("email %q is not one plain address", a.Email)
		}
	}
	for _, g := range a.Groups {
		if err := ValidateGroup(g); err != nil {
			return err
		}
	}
	return nil
}

// ValidateGroup refuses an empty group or one with whitespace or control
// characters.
func ValidateGroup(g string) error {
	if g == "" || len(g) > 128 || strings.TrimSpace(g) != g || hasControl(g) || strings.ContainsAny(g, " \t\n") {
		return fmt.Errorf("group %q is not a plain group name", g)
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// passwordAlphabet leaves out 0, O, 1, l and I, which a person reading the
// password aloud or copying it by hand would confuse.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// passwordLength gives about 117 bits from crypto/rand.
const passwordLength = 20

// GeneratePassword returns a one-time password for a new account or a
// reset: shown once to the operator, stored only as its hash.
func GeneratePassword() (string, error) {
	max := big.NewInt(int64(len(passwordAlphabet)))
	b := make([]byte, passwordLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("idp: random password: %w", err)
		}
		b[i] = passwordAlphabet[n.Int64()]
	}
	return string(b), nil
}

// Authelia's default argon2id parameters, so a hash written here costs a
// guesser what Authelia's own do.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword returns password as the argon2id PHC string Authelia's file
// backend reads: $argon2id$v=19$m=65536,t=3,p=4$SALT$KEY.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("idp: salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}
