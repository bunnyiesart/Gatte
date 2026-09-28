package stdio

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestDialRefusesAVariableWhoseValueIsCode is design/adr/0034 item 3 at the
// stdio boundary. A registry entry's EnvVarNames are signed; the values
// the vault resolves them to are not. A name the loader or an interpreter
// reads as code -- LD_PRELOAD, NODE_OPTIONS, PYTHONSTARTUP -- would turn an
// unsigned vault value into code running in the backend, beside every
// credential of the entry, with the signature still valid. The oci adapter
// has refused the loader half of these since 24 Sep 2026; the stdio child
// is the same exposure without the container, and was not checked.
func TestDialRefusesAVariableWhoseValueIsCode(t *testing.T) {
	secret := newSecret(t)
	for _, name := range []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "GCONV_PATH",
		"NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
		"PERL5OPT", "PERL5LIB", "RUBYOPT", "BASH_ENV", "JAVA_TOOL_OPTIONS",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			up, err := New().Dial(ctx, irisSpec(), map[string]string{name: secret})
			if err == nil {
				_ = up.Close()
				t.Fatalf("Dial accepted %s, whose value the child reads as code", name)
			}
			if !errors.Is(err, ErrCodeLoadingEnv) {
				t.Errorf("error = %v, want ErrCodeLoadingEnv", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("LEAK: the rejection quoted the resolved value")
			}
			if err := ValidateEnvVarNames([]string{name}); !errors.Is(err, ErrCodeLoadingEnv) {
				t.Errorf("ValidateEnvVarNames(%s) = %v, want the rule the dial applies", name, err)
			}
		})
	}

	// The control: ordinary credential names stay acceptable, or the rule
	// would be a rule against everything.
	if err := ValidateEnvVarNames([]string{"CASEMGMT_API_KEY", "MOCK_SECRET", "PYTHON_API_TOKEN"}); err != nil {
		t.Errorf("ValidateEnvVarNames refused ordinary names: %v", err)
	}
}
