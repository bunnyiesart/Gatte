package gateway

import (
	"slices"
	"strings"
)

// codeLoadingEnvNames and codeLoadingEnvPrefixes are the variables whose
// VALUE a process reads as code at start-up: the dynamic loader (glibc
// ld.so, and dyld for completeness), iconv's module path, and the
// interpreters a backend is likely to be written in.
//
// They are refused as a credential name on every transport, and the reason
// is the signature, not the vault. A registry entry's EnvVarNames are
// covered by its Ed25519 signature; the values the vault resolves them to
// are not, by design (rotation must not break a signature). A name on this
// list would turn an unsigned vault value into code running in the process
// that holds every credential of the entry -- the backend itself under
// stdio, and under oci the podman client as well -- with the signature
// still valid (design/adr/0034 item 3).
//
// One list, here in the port package, because both adapters need it and
// neither may import the other (internal/fitness). It was the oci
// adapter's alone until 28 Sep 2026, which left the stdio child -- the same
// exposure without a container around it -- unchecked.
//
// Matching is exact for names and by prefix for the loader families. The
// interpreter names are exact on purpose: PYTHON_API_TOKEN is a credential
// name, PYTHONPATH is not.
var (
	codeLoadingEnvNames = []string{
		"GCONV_PATH",
		"NODE_OPTIONS", "NODE_PATH",
		"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONBREAKPOINT",
		"PERL5LIB", "PERL5OPT", "PERLLIB",
		"RUBYOPT", "RUBYLIB",
		"BASH_ENV", "ENV",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
	}
	codeLoadingEnvPrefixes = []string{"LD_", "DYLD_"}
)

// IsCodeLoadingEnvName reports whether name is a variable whose value the
// loader or an interpreter executes, and which therefore must never be an
// entry's credential name. See codeLoadingEnvNames.
func IsCodeLoadingEnvName(name string) bool {
	if slices.Contains(codeLoadingEnvNames, name) {
		return true
	}
	for _, prefix := range codeLoadingEnvPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
