package adminapi_test

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// TestContractVersion_MatchesTheDocument: ContractVersion is what
// GET /v1/whoami reports, and a front decides from it what fields can
// appear, so it must be the info.version of the document it implements.
func TestContractVersion_MatchesTheDocument(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "admin.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Info struct {
			Version string `yaml:"version"`
		} `yaml:"info"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Info.Version != adminapi.ContractVersion {
		t.Errorf("adminapi.ContractVersion = %s, api/admin.openapi.yaml info.version = %s", adminapi.ContractVersion, doc.Info.Version)
	}
}
