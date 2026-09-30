package adminapi_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// schemaProperties reads the property names of one schema of the contract.
func schemaProperties(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "api", "admin.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	s, ok := doc.Components.Schemas[name]
	if !ok {
		t.Fatalf("schema %s is not in the contract", name)
	}
	var out []string
	for k := range s.Properties {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonFields is the JSON names of a struct's fields.
func jsonFields(v any) []string {
	var out []string
	rt := reflect.TypeOf(v)
	for i := range rt.NumField() {
		tag := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			out = append(out, tag)
		}
	}
	sort.Strings(out)
	return out
}

// The health types are the contract's schemas, field for field: a front
// in another language reads the YAML, a Go front these types.
func TestHealthTypes_CarryExactlyTheContractsFields(t *testing.T) {
	for name, v := range map[string]any{
		"Health": adminapi.Health{}, "BackendHealth": adminapi.BackendHealth{}, "ServeStatus": adminapi.ServeStatus{},
		"Maintenance": adminapi.Maintenance{},
	} {
		if got, want := jsonFields(v), schemaProperties(t, name); !slices.Equal(got, want) {
			t.Errorf("%s fields %v, contract %v", name, got, want)
		}
	}
	for _, pair := range []struct {
		schema string
		field  string
		v      any
	}{{"Overview", "health", adminapi.Overview{}}, {"Upstream", "health", adminapi.Upstream{}}} {
		if !slices.Contains(jsonFields(pair.v), pair.field) || !slices.Contains(schemaProperties(t, pair.schema), pair.field) {
			t.Errorf("%s lacks %q", pair.schema, pair.field)
		}
	}
}

// backend_health is listed once health is served, and the overview then
// carries it over the socket.
func TestWhoAmI_ListsBackendHealthAndTheOverviewCarriesIt(t *testing.T) {
	b := newBackend(t)
	op := adminapi.New(serve(t, b, adminapi.SocketOperator), adminapi.WithFront("test"), adminapi.WithServerUID(uint32(os.Geteuid())))
	ctx := context.Background()
	me, err := op.WhoAmI(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{adminapi.FeatureMaintenance, adminapi.FeatureBackendHealth} {
		if !slices.Contains(me.Features, f) {
			t.Errorf("features %v lack %q", me.Features, f)
		}
	}
	ov, err := op.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Health == nil || ov.Health.Serve.State != adminapi.ServeNeverReported || ov.Health.Backends == nil {
		t.Fatalf("overview health = %+v", ov.Health)
	}
}

// The review-set types are the contract's schemas, field for field
// (design/adr/0043).
func TestReviewSetTypes_CarryExactlyTheContractsFields(t *testing.T) {
	for name, v := range map[string]any{
		"ToolReviewSet": adminapi.ToolReviewSet{}, "ApproveSetRequest": adminapi.ApproveSetRequest{}, "ApprovedTool": adminapi.ApprovedTool{},
	} {
		if got, want := jsonFields(v), schemaProperties(t, name); !slices.Equal(got, want) {
			t.Errorf("%s fields %v, contract %v", name, got, want)
		}
	}
	for _, c := range []string{adminapi.CodeManifestRequired, adminapi.CodeManifestMismatch} {
		if !slices.Contains(adminapi.Codes(), c) {
			t.Errorf("code %s has no status", c)
		}
	}
}
