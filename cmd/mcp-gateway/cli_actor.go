// Operator Console -- who a CLI command attributes its rows to
// (design/adr/0040 §2).

package main

import (
	"io"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/peercred"
)

// cliLoginUID is the audit login uid of this process: on Linux, the kernel
// keeps it across sudo, so it names the person behind a shared account.
// A variable for tests.
var cliLoginUID = func() (uint32, bool) {
	if runtime.GOOS != "linux" {
		return 0, false
	}
	b, err := os.ReadFile("/proc/self/loginuid")
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || v == peercred.Unset {
		return 0, false
	}
	return uint32(v), true
}

// cliActor is who a CLI command's operator rows are attributed to, and the
// mark that says where the name came from: [cli] when the kernel said it
// (the loginuid, or the account database for this uid), [cli env] when it
// was SUDO_USER or USER. A row from the API says the kernel's peer
// credentials; a row from the terminal cannot, and the trail keeps the
// difference visible.
func cliActor() (admin.Actor, error) {
	if lu, ok := cliLoginUID(); ok {
		if u, err := user.LookupId(strconv.FormatUint(uint64(lu), 10)); err == nil && plainName(u.Username) {
			a := admin.Actor{Name: u.Username, Front: "cli"}
			if cur, err := user.Current(); err == nil && cur.Uid != u.Uid && plainName(cur.Username) {
				a.Via = cur.Username
			}
			return a, nil
		}
	}
	for _, env := range []string{"SUDO_USER", "USER"} {
		if name := os.Getenv(env); name != "" {
			if !plainName(name) {
				break
			}
			return admin.Actor{Name: name, Front: "cli env"}, nil
		}
	}
	name, err := operatorName()
	if err != nil {
		return admin.Actor{}, err
	}
	return admin.Actor{Name: name, Front: "cli"}, nil
}

// plainName is a name that can head an ANALYST column: no space, no
// control character, no parenthesis.
func plainName(s string) bool {
	return s != "" && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r == '(' || r == ')'
	}) < 0
}

// operator is the actor this command's rows go to: the one the command set
// (the web console sets its own), or the CLI's.
func (e *opEnv) operator() (admin.Actor, error) {
	if e.actor.Name != "" {
		return e.actor, nil
	}
	return cliActor()
}

// service is the management service over this command's store and
// configuration: the same rules the management API answers with.
func (e *opEnv) service() (*admin.Service, error) {
	cfg := e.cfg
	return newAdminService(e.db, func() (*config.Config, error) { return cfg, nil }, e.stderr, e.configPath, newLogger(io.Discard))
}
