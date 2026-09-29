package adminhttp_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
)

// contractRoute is one operation of api/admin.openapi.yaml.
type contractRoute struct {
	Method, Path, OperationID string
	Sockets                   []string
}

func (r contractRoute) key() string { return r.Method + " " + r.Path }

// loadContract reads every operation of the committed contract.
func loadContract(t *testing.T) []contractRoute {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "admin.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			OperationID string   `yaml:"operationId"`
			Socket      []string `yaml:"x-gatte-socket"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []contractRoute
	for path, ops := range doc.Paths {
		for method, op := range ops {
			out = append(out, contractRoute{Method: strings.ToUpper(method), Path: path, OperationID: op.OperationID, Sockets: op.Socket})
		}
	}
	return out
}

// TestContract_EveryDocumentedOperationIsServedAndEveryServedRouteIsDocumented
// is design/adr/0040 §7: api/admin.openapi.yaml is the contract, so the
// backend serves exactly it, on the sockets it names.
func TestContract_EveryDocumentedOperationIsServedAndEveryServedRouteIsDocumented(t *testing.T) {
	documented := map[string]contractRoute{}
	for _, r := range loadContract(t) {
		documented[r.key()] = r
	}
	served := map[string]adminhttp.Route{}
	for _, r := range adminhttp.Routes() {
		served[r.Method+" "+r.Path] = r
	}
	if len(documented) == 0 || len(served) == 0 {
		t.Fatalf("documented %d, served %d", len(documented), len(served))
	}
	var keys []string
	for k := range documented {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		d := documented[k]
		s, ok := served[k]
		if !ok {
			t.Errorf("%s (%s) is in the contract and not served", k, d.OperationID)
			continue
		}
		if s.OperationID != d.OperationID {
			t.Errorf("%s: served as %q, documented as %q", k, s.OperationID, d.OperationID)
		}
		if strings.Join(s.Sockets, ",") != strings.Join(d.Sockets, ",") {
			t.Errorf("%s: served on %v, documented on %v", k, s.Sockets, d.Sockets)
		}
	}
	for k := range served {
		if _, ok := documented[k]; !ok {
			t.Errorf("%s is served and not in api/admin.openapi.yaml", k)
		}
	}
}
