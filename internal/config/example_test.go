package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// examplePath is the shipped, documented configuration file, from this
// package's directory.
const examplePath = "../../config.example.toml"

// TestShippedExampleLoads runs the real file through the real loader.
//
// It exists because config.example.toml is the one artifact in this repo
// that TELLS an operator what the gateway enforces, and until now nothing
// checked that the gateway agreed. The two ways that goes wrong are both
// this project's declared defect class:
//
//   - the example describes a control the code does not apply (ADR-0016
//     found exactly this: a boxed "NAO EXISTE CORINGA" that had become
//     half false);
//   - the example uses a key or a shape the loader refuses, so the file
//     an operator copied cannot start the process that shipped it.
//
// The second is what this test can decide mechanically, and it decides it
// against Load rather than against a hand-built Config: rejectUnknownKeys,
// rejectCollapsedMapKeys and Validate are all part of what "the shipped
// example is valid" has to mean.
func TestShippedExampleLoads(t *testing.T) {
	c, err := Load(filepath.FromSlash(examplePath))
	if err != nil {
		t.Fatalf("the shipped config.example.toml does not load: %v", err)
	}

	// The worked [role.grants] block the file documents has to BE in the
	// file, or this test passes over an example that only talks about the
	// form. Asserted by shape, not by role name, so renaming a role in the
	// example does not turn this into a maintenance chore.
	found := false
	for _, r := range c.Roles {
		if len(r.Grants) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("config.example.toml documents [role.grants] and contains no worked instance of it; the example is then untested prose")
	}
}

// TestShippedExampleShipsNoWildcardGrant pins a deliberate editorial
// choice, so that adding one is a conscious edit to this test rather than
// a line in a file people copy wholesale.
//
// "*" is valid, documented, and costly: under it, approving a definition
// in Tool Quarantine becomes the SOLE remaining human act between a tool
// and every analyst in the role (design/adr/0016). An example is where a
// default becomes a habit, and this one should not hand out that trade by
// being the thing everybody copies.
func TestShippedExampleShipsNoWildcardGrant(t *testing.T) {
	c, err := Load(filepath.FromSlash(examplePath))
	if err != nil {
		t.Fatalf("the shipped config.example.toml does not load: %v", err)
	}
	for _, r := range c.Roles {
		for backend, ids := range r.Grants {
			for _, id := range ids {
				if id == "*" {
					t.Errorf("role %q grants %q = [\"*\"] in the shipped example; see this test's doc before changing it", r.Name, backend)
				}
			}
		}
	}
}

// deploymentTemplate is the file the jail deployment actually installs.
const deploymentTemplate = "../../deploy/gateway-jail/config.toml.template"

// TestDeploymentTemplateLoads runs the deployed template through the real
// loader, with its one placeholder substituted the way provisioning does.
//
// config.example.toml being valid says nothing about this file: they are
// two different files, and the terse one is the one that starts the
// process on `bun`. The failure it guards against has a precedent in this
// repo -- the shipped example carried a docsearch role that granted
// nothing for weeks (GAB-30), silently -- and a template that does not
// load is the louder, cheaper version of the same class.
func TestDeploymentTemplateLoads(t *testing.T) {
	raw, err := os.ReadFile(filepath.FromSlash(deploymentTemplate))
	if err != nil {
		t.Fatalf("reading the deployment template: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "__TRUSTED_KEY__") {
		t.Fatal("the template no longer carries __TRUSTED_KEY__; this test substitutes a placeholder that is gone and would be testing nothing")
	}
	// Substituted, not removed: signer.trusted_keys must decode, and an
	// empty list with require_signed defaulting to true is refused --
	// correctly, and not what this test is about.
	body = strings.ReplaceAll(body, "__TRUSTED_KEY__", testTrustedKey)

	if _, err := Load(writeConfig(t, body)); err != nil {
		t.Fatalf("the deployed configuration template does not load: %v", err)
	}
}
