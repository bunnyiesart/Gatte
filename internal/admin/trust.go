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
// [idp] users_file and its directories. Nothing is written when a check
// fails.
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
		return cfg, nil
	}
}
