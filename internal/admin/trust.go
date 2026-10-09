package admin

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// Problems CheckOwnedChain reports in details.problem.
const (
	ProblemNotRootOwned   = "not_root_owned"
	ProblemWritable       = "group_or_other_writable"
	ProblemSymlink        = "symlink"
	ProblemNotRegular     = "not_regular"
	ProblemDoesNotLoad    = "does_not_load"
	problemUnreadableStat = "does_not_load"
)

// CheckOwnedChain checks, with Lstat, each file in paths and every
// directory above it up to "/": owned by a uid trusted accepts (root, in
// production), no symbolic link, the file a regular file, nothing writable
// by group or others (design/adr/0040 §1). The accounts backend runs as
// root and reads these files; one the service account could write would
// let it point users_file anywhere, or widen account_group.
//
// Directories are checked from "/" down, so the first failure reported is
// the highest one. The error is config_unavailable with details.path and
// details.problem.
func CheckOwnedChain(paths []string, trusted func(uid uint32) bool) error {
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return unavailable(p, problemUnreadableStat, err.Error())
		}
		var chain []string
		for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
			chain = append([]string{d}, chain...)
			if d == filepath.Dir(d) {
				break
			}
		}
		for _, d := range chain {
			if err := checkOne(d, true, trusted); err != nil {
				return err
			}
		}
		if err := checkOne(abs, false, trusted); err != nil {
			return err
		}
	}
	return nil
}

// CheckServiceKey is CheckOwnedChain for the one file a root backend reads
// that is NOT root's by design: the vault's age identity, which belongs to
// the service account (README, "Who owns what"), because serve decrypts
// with it. Every directory above it is held to the root rule as usual; the
// file itself may be owned by a trusted uid or by serviceUID, and must be
// a regular file, no symbolic link, with no permission bit for group or
// others at all (design/adr/0050).
//
// Trusting the service account's file gives it nothing it lacks: whoever
// holds the age identity can already decrypt the vault, and the root
// backend never takes the recipients it encrypts for from this file while
// the vault names its own (sopsage.Store). Refusing it, as the plain rule
// did, made the console unable to write any secret on any install laid out
// as documented (found in the Docker image, 09 Oct 2026).
func CheckServiceKey(path string, trusted func(uid uint32) bool, serviceUID uint32) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return unavailable(path, problemUnreadableStat, err.Error())
	}
	var chain []string
	for d := filepath.Dir(abs); ; d = filepath.Dir(d) {
		chain = append([]string{d}, chain...)
		if d == filepath.Dir(d) {
			break
		}
	}
	for _, d := range chain {
		if err := checkOne(d, true, trusted); err != nil {
			return err
		}
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return unavailable(abs, problemUnreadableStat, err.Error())
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return unavailable(abs, ProblemSymlink, "is a symbolic link")
	case !fi.Mode().IsRegular():
		return unavailable(abs, ProblemNotRegular, "is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return unavailable(abs, ProblemNotRootOwned, "has no owner this system reports")
	}
	if !trusted(st.Uid) && st.Uid != serviceUID {
		return unavailable(abs, ProblemNotRootOwned, "is owned neither by root nor by the service account")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return unavailable(abs, ProblemWritable, "is readable or writable by group or others")
	}
	return nil
}

func checkOne(path string, dir bool, trusted func(uint32) bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return unavailable(path, problemUnreadableStat, err.Error())
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return unavailable(path, ProblemSymlink, "is a symbolic link")
	case dir && !fi.IsDir():
		return unavailable(path, ProblemNotRegular, "is not a directory")
	case !dir && !fi.Mode().IsRegular():
		return unavailable(path, ProblemNotRegular, "is not a regular file")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return unavailable(path, ProblemNotRootOwned, "has no owner this system reports")
	}
	if !trusted(st.Uid) {
		return unavailable(path, ProblemNotRootOwned, "is not owned by root")
	}
	if fi.Mode().Perm()&0o022 != 0 {
		// A sticky world-writable directory (/tmp) still lets anyone create
		// a file in it; it is refused as well.
		return unavailable(path, ProblemWritable, "is writable by group or others")
	}
	return nil
}

func unavailable(path, problem, why string) error {
	return adminapi.NewError(adminapi.CodeConfigUnavailable, "%s %s; the accounts backend runs as root and trusts only what root alone can write", path, why).
		With("path", path).With("problem", problem)
}

// RootConfig is the accounts backend's configuration loader: before every
// request it checks config.toml and its directories, loads it, then checks
// [idp] users_file and its directories, and roles_file and its
// directories when one is set. Nothing is written when a check fails.
func RootConfig(path string, trusted func(uint32) bool, load func(string) (*config.Config, error)) func() (*config.Config, error) {
	return func() (*config.Config, error) {
		if err := CheckOwnedChain([]string{path}, trusted); err != nil {
			return nil, err
		}
		cfg, err := load(path)
		if err != nil {
			return nil, adminapi.NewError(adminapi.CodeConfigUnavailable, "the configuration file does not load: %v", err).
				With("path", path).With("problem", ProblemDoesNotLoad)
		}
		if cfg.IdP.UsersFile != "" {
			if err := CheckOwnedChain([]string{cfg.IdP.UsersFile}, trusted); err != nil {
				return nil, err
			}
		}
		// The roles file decides which accounts the gateway manages
		// ([group_to_role]) and is written by this process
		// (design/adr/0050 §2): one the service account could write would
		// widen the account group's reach, or be swapped for a link that
		// root's atomic replace follows.
		if cfg.RolesFile != "" {
			if err := CheckOwnedChain([]string{cfg.RolesFile}, trusted); err != nil {
				return nil, err
			}
		}
		return cfg, nil
	}
}
