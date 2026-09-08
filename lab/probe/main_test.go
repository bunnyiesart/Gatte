package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureBinaries holds the paths to the two compiled test fixtures,
// built once in TestMain and reused across subtests.
var fixtureBinaries struct {
	good  string
	leaky string
}

func TestMain(m *testing.M) {
	os.Exit(func() int {
		tmp, err := os.MkdirTemp("", "probe-fixtures-")
		if err != nil {
			panic(err)
		}
		defer os.RemoveAll(tmp)

		good := filepath.Join(tmp, "goodfixture")
		if out, err := exec.Command("go", "build", "-o", good, "./testdata/goodfixture").CombinedOutput(); err != nil {
			panic("build goodfixture: " + err.Error() + "\n" + string(out))
		}

		leaky := filepath.Join(tmp, "leakyfixture")
		if out, err := exec.Command("go", "build", "-o", leaky, "./testdata/leakyfixture").CombinedOutput(); err != nil {
			panic("build leakyfixture: " + err.Error() + "\n" + string(out))
		}

		fixtureBinaries.good = good
		fixtureBinaries.leaky = leaky

		return m.Run()
	}())
}

func TestRunGoodFixturePasses(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run("test_credcheck", []string{fixtureBinaries.good}, &stdout, &stderr)

	if code != exitOK {
		t.Fatalf("run() = %d, want %d (exitOK)\nstdout:\n%s\nstderr:\n%s", code, exitOK, stdout.String(), stderr.String())
	}
	if strings.Contains(stderr.String(), "LEAK") {
		t.Errorf("unexpected LEAK message against a correct fixture, stderr:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Errorf("expected PASS in stdout, got:\n%s", stdout.String())
	}
}

func TestRunLeakyToolDetectsLeak(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run("leaky_tool", []string{fixtureBinaries.leaky}, &stdout, &stderr)

	// Specifically exitFail, not just "nonzero": a leak must never be
	// reported as exitUsageErr, even though leaky_tool's response also
	// fails to parse as a CredCheckResult (it returns the raw secret as
	// plain text, not credcheck JSON) -- see the comment on
	// reportAndExit for the bug this guards against.
	if code != exitFail {
		t.Fatalf("run() = %d, want %d (exitFail) -- a leak must never be reported as exitUsageErr\nstdout:\n%s\nstderr:\n%s",
			code, exitFail, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "LEAK") {
		t.Errorf("expected LEAK message in stderr, got:\n%s", stderr.String())
	}
}

func TestRunBadCommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run("test_credcheck", []string{"/no/such/binary/here"}, &stdout, &stderr)

	if code != exitUsageErr {
		t.Fatalf("run() = %d, want %d (exitUsageErr)\nstdout:\n%s\nstderr:\n%s", code, exitUsageErr, stdout.String(), stderr.String())
	}
}
