package resthttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// These tests touch no network. They pin the OpenAPI ingestion: what a
// document produces, what is refused by name, and that the bytes are the
// same for the same document -- because those bytes are what the registry
// stores and the signer digests (ADR-0048 Decisão 2, 4).

// specJSON is the fixture most tests start from: one safe GET with a path
// parameter inherited from the path item, a query and a header parameter,
// a $ref'd object response; one sensitive POST with a oneOf body whose
// branches close themselves; a servers[] entry with a host and a base
// path; one apiKey security scheme.
const specJSON = `{
  "openapi": "3.0.3",
  "info": {"title": "t", "version": "1"},
  "servers": [{"url": "https://api.example.com/api/v2"}],
  "paths": {
    "/check/{ip}": {
      "parameters": [{"name": "ip", "in": "path", "required": true, "schema": {"type": "string"}}],
      "get": {
        "operationId": "check.ip",
        "summary": "Look an IP up",
        "parameters": [
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
          {"name": "X-Request-Id", "in": "header", "schema": {"type": "string"}}
        ],
        "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Check"}}}}}
      }
    },
    "/report": {
      "post": {
        "operationId": "report",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"oneOf": [{"$ref": "#/components/schemas/A"}, {"$ref": "#/components/schemas/B"}]}}}},
        "responses": {"201": {"description": "created"}}
      }
    }
  },
  "components": {
    "schemas": {
      "Check": {"type": "object", "properties": {"ip": {"type": "string"}}},
      "A": {"type": "object", "additionalProperties": false, "properties": {"ip": {"type": "string"}}},
      "B": {"type": "object", "additionalProperties": false, "properties": {"url": {"type": "string"}}}
    },
    "securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}
  }
}`

// specYAML is specJSON spelled in YAML, with anchors, a block scalar, a
// comment and a quoted key -- what a hand-written spec looks like.
const specYAML = `openapi: 3.0.3
info: {title: t, version: "1"}
servers:
  - url: https://api.example.com/api/v2   # host ignored, path folded
paths:
  /check/{ip}:
    parameters:
      - &ip {name: ip, in: path, required: true, schema: {type: string}}
    get:
      operationId: check.ip
      summary: >-
        Look an IP up
      parameters:
        - name: verbose
          in: query
          schema: {type: boolean}
        - name: X-Request-Id
          in: header
          schema: {type: string}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Check"}
  /report:
    post:
      operationId: report
      requestBody:
        required: true
        content:
          application/json:
            schema:
              oneOf:
                - $ref: "#/components/schemas/A"
                - $ref: "#/components/schemas/B"
      responses:
        "201": {description: created}
components:
  schemas:
    Check: {type: object, properties: {ip: {type: string}}}
    A: {type: object, additionalProperties: false, properties: {ip: {type: string}}}
    B: {type: object, additionalProperties: false, properties: {url: {type: string}}}
  securitySchemes:
    key: {type: apiKey, in: header, name: X-API-Key}
`

const wantCheckInput = `{"additionalProperties":false,"properties":{"header_X-Request-Id":{"type":"string"},"path_ip":{"type":"string"},"query_verbose":{"type":"boolean"}},"required":["path_ip"],"type":"object"}`
const wantReportInput = `{"additionalProperties":false,"properties":{"body":{"oneOf":[{"properties":{"ip":{"type":"string"}},"type":"object"},{"properties":{"url":{"type":"string"}},"type":"object"}]}},"required":["body"],"type":"object"}`

func header(kind, name string) IngestOptions {
	return IngestOptions{AuthKind: kind, AuthName: name, BaseURL: "https://registered.example.net"}
}

// mustIngest runs Ingest and the post-condition every success must meet:
// Decode(Encode(ops)) under the effective descriptor accepts the set and
// reproduces the bytes.
func mustIngest(t *testing.T, doc string, opts IngestOptions) IngestResult {
	t.Helper()
	res, err := Ingest([]byte(doc), opts)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	checkPostconditions(t, res)
	return res
}

func checkPostconditions(t *testing.T, res IngestResult) {
	t.Helper()
	ops, err := Decode(res.Operations, res.AuthKind, res.AuthName)
	if err != nil {
		t.Fatalf("Decode(Operations) refused the ingested set: %v", err)
	}
	re, err := Encode(ops)
	if err != nil {
		t.Fatalf("Encode(Decode(Operations)): %v", err)
	}
	if !bytes.Equal(re, res.Operations) {
		t.Fatalf("Operations are not the canonical bytes:\n got %s\nwant %s", res.Operations, re)
	}
	if len(ops) != len(res.Ops) {
		t.Fatalf("Ops has %d operations, Operations %d", len(res.Ops), len(ops))
	}
	for i := range ops {
		if !bytes.Equal(ops[i].InputSchema, res.Ops[i].InputSchema) || ops[i].Name != res.Ops[i].Name {
			t.Fatalf("Ops[%d] differs from the decoded set", i)
		}
	}
	if res.BaseURL != "" {
		if _, err := parseBase(res.BaseURL); err != nil {
			t.Fatalf("BaseURL %q is not accepted by parseBase: %v", res.BaseURL, err)
		}
	}
}

func opByName(t *testing.T, res IngestResult, name string) Operation {
	t.Helper()
	for _, op := range res.Ops {
		if op.Name == name {
			return op
		}
	}
	names := make([]string, 0, len(res.Ops))
	for _, op := range res.Ops {
		names = append(names, op.Name)
	}
	t.Fatalf("no operation %q; have %v", name, names)
	return Operation{}
}

func hasLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func TestIngest_MinimalHappyPath_JSONAndYAMLAgreeByteForByte(t *testing.T) {
	for _, c := range []struct{ name, doc string }{{"json", specJSON}, {"yaml", specYAML}} {
		t.Run(c.name, func(t *testing.T) {
			res := mustIngest(t, c.doc, header(AuthHeader, "X-API-Key"))
			if len(res.Ops) != 2 {
				t.Fatalf("want 2 operations, got %d: %s", len(res.Ops), res.Operations)
			}
			check := opByName(t, res, "check_ip")
			if check.Method != "GET" || check.Path != "/check/{ip}" || check.Description != "Look an IP up" {
				t.Errorf("check: %+v", check)
			}
			if string(check.InputSchema) != wantCheckInput {
				t.Errorf("check input schema:\n got %s\nwant %s", check.InputSchema, wantCheckInput)
			}
			if want := `{"properties":{"ip":{"type":"string"}},"type":"object"}`; string(check.OutputSchema) != want {
				t.Errorf("check output schema:\n got %s\nwant %s", check.OutputSchema, want)
			}
			if check.ToolDef().SecurityClass != quarantine.ClassSafe {
				t.Errorf("GET is not safe")
			}

			report := opByName(t, res, "report")
			if report.Method != "POST" || report.Description != "POST /report" {
				t.Errorf("report: %+v", report)
			}
			if string(report.InputSchema) != wantReportInput {
				t.Errorf("report input schema (oneOf under body, branches' additionalProperties:false neutralized):\n got %s\nwant %s", report.InputSchema, wantReportInput)
			}
			if report.OutputSchema != nil {
				t.Errorf("report: 201 without content must not yield an output schema; got %s", report.OutputSchema)
			}
			if report.ToolDef().SecurityClass != quarantine.ClassSensitive {
				t.Errorf("POST is not sensitive")
			}

			// servers[]: host ignored with a warning, base path folded.
			if res.BaseURL != "https://registered.example.net/api/v2" || res.BasePath != "/api/v2" {
				t.Errorf("base: url %q path %q", res.BaseURL, res.BasePath)
			}
			if !hasLine(res.Warnings, "servers[0].url names https://api.example.com:443; ignored") {
				t.Errorf("no warning about the ignored host: %v", res.Warnings)
			}
			if res.AuthDerived || res.AuthKind != AuthHeader || res.AuthName != "X-API-Key" {
				t.Errorf("auth: %q %q derived=%v", res.AuthKind, res.AuthName, res.AuthDerived)
			}
			if len(res.Skipped) != 0 {
				t.Errorf("skipped: %v", res.Skipped)
			}
		})
	}

	j := mustIngest(t, specJSON, header(AuthHeader, "X-API-Key"))
	y := mustIngest(t, specYAML, header(AuthHeader, "X-API-Key"))
	if !bytes.Equal(j.Operations, y.Operations) {
		t.Errorf("JSON and YAML spellings of one spec produce different bytes:\n json %s\n yaml %s", j.Operations, y.Operations)
	}
}

func TestIngest_IsDeterministic(t *testing.T) {
	first := mustIngest(t, specJSON, IngestOptions{BaseURL: "https://h"})
	for i := 0; i < 5; i++ {
		again := mustIngest(t, specJSON, IngestOptions{BaseURL: "https://h"})
		if !bytes.Equal(first.Operations, again.Operations) {
			t.Fatalf("run %d produced different bytes", i)
		}
		if strings.Join(first.Warnings, "\n") != strings.Join(again.Warnings, "\n") {
			t.Fatalf("run %d produced different warnings", i)
		}
	}
}

// spec builds a document around the given paths and components, so that
// each case below reads as the fragment it tests.
func spec(paths, components string) string {
	if components == "" {
		components = "{}"
	}
	return `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":` + paths + `,"components":` + components + `}`
}

func TestIngest_RefChainsAreResolvedAndCyclesRefused(t *testing.T) {
	chain := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/A"}}}},"responses":{}}}}`,
		`{"schemas":{"A":{"$ref":"#/components/schemas/B"},"B":{"$ref":"#/components/schemas/C"},"C":{"type":"object","properties":{"n":{"$ref":"#/components/schemas/N"}}},"N":{"type":"integer","minimum":1}}}`)
	res := mustIngest(t, chain, IngestOptions{})
	if want := `{"additionalProperties":false,"properties":{"body":{"properties":{"n":{"minimum":1,"type":"integer"}},"type":"object"}},"type":"object"}`; string(res.Ops[0].InputSchema) != want {
		t.Errorf("chained $ref:\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}

	cyclic := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}},"responses":{}}}}`,
		`{"schemas":{"Node":{"type":"object","properties":{"child":{"$ref":"#/components/schemas/Node"}}}}}`)
	_, err := Ingest([]byte(cyclic), IngestOptions{})
	if !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "cyclic") || !strings.Contains(err.Error(), "POST /a") {
		t.Errorf("cyclic body $ref: %v", err)
	}

	remote := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"$ref":"https://evil.tld/schema.json"}}}},"responses":{}}}}`, "")
	if _, err := Ingest([]byte(remote), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "remote") {
		t.Errorf("remote $ref: %v", err)
	}

	// A recursive RESPONSE type only drops the optional output schema.
	recursiveOut := spec(`{"/a":{"get":{"operationId":"a","responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}}}}}}`,
		`{"schemas":{"Node":{"type":"object","properties":{"child":{"$ref":"#/components/schemas/Node"}}}}}`)
	res = mustIngest(t, recursiveOut, IngestOptions{})
	if res.Ops[0].OutputSchema != nil || !hasLine(res.Warnings, "no output schema") {
		t.Errorf("recursive response: output %s warnings %v", res.Ops[0].OutputSchema, res.Warnings)
	}
}

func TestIngest_AllOfIsMergedAndConflictsRefused(t *testing.T) {
	merged := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"allOf":[{"$ref":"#/components/schemas/Base"},{"type":"object","required":["z"],"properties":{"z":{"type":"string"}}}],"description":"merged"}}}},"responses":{}}}}`,
		`{"schemas":{"Base":{"type":"object","required":["id"],"properties":{"id":{"type":"string"}}}}}`)
	res := mustIngest(t, merged, IngestOptions{})
	want := `{"additionalProperties":false,"properties":{"body":{"description":"merged","properties":{"id":{"type":"string"},"z":{"type":"string"}},"required":["id","z"],"type":"object"}},"type":"object"}`
	if string(res.Ops[0].InputSchema) != want {
		t.Errorf("allOf:\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}

	conflict := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"allOf":[{"type":"object"},{"type":"string"}]}}}},"responses":{}}}}`, "")
	if _, err := Ingest([]byte(conflict), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "conflicting types") {
		t.Errorf("type conflict: %v", err)
	}
	propConflict := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"allOf":[{"type":"object","properties":{"x":{"type":"string"}}},{"type":"object","properties":{"x":{"type":"integer"}}}]}}}},"responses":{}}}}`, "")
	if _, err := Ingest([]byte(propConflict), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), `property "x" is declared twice`) {
		t.Errorf("property conflict: %v", err)
	}
}

func TestIngest_AnyOfUnderBodyKeepsAlternationAndNeutralizesClosedBranches(t *testing.T) {
	doc := spec(`{"/a":{"put":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"anyOf":[{"type":"object","additionalProperties":false,"properties":{"p":{"type":"string"}}},{"type":"object","additionalProperties":{"type":"string"}}],"discriminator":{"propertyName":"p"},"x-vendor":1}}}},"responses":{}}}}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	// Branch 1's additionalProperties:false is gone; branch 2's schema-valued
	// additionalProperties stays; discriminator and x-* are dropped; the top
	// level's own additionalProperties:false (ours) stays.
	want := `{"additionalProperties":false,"properties":{"body":{"anyOf":[{"properties":{"p":{"type":"string"}},"type":"object"},{"additionalProperties":{"type":"string"},"type":"object"}]}},"type":"object"}`
	if string(res.Ops[0].InputSchema) != want {
		t.Errorf("anyOf:\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}
}

func TestIngest_NonObjectBodyBecomesTypedBodyProperty(t *testing.T) {
	doc := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"required":true,"content":{"application/json; charset=utf-8":{"schema":{"type":"array","items":{"type":"string","nullable":true,"minimum":1,"exclusiveMinimum":true}}}}},"responses":{}}}}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	want := `{"additionalProperties":false,"properties":{"body":{"items":{"exclusiveMinimum":1,"type":["string","null"]},"type":"array"}},"required":["body"],"type":"object"}`
	if string(res.Ops[0].InputSchema) != want {
		t.Errorf("array body (with nullable and boolean exclusiveMinimum translated):\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}

	// A media type with no schema is "any JSON".
	anyBody := spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{}}},"responses":{}}}}`, "")
	res = mustIngest(t, anyBody, IngestOptions{})
	if want := `{"additionalProperties":false,"properties":{"body":{}},"type":"object"}`; string(res.Ops[0].InputSchema) != want {
		t.Errorf("schemaless body:\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}
}

func TestIngest_PathLevelParametersAreInheritedAndOverridden(t *testing.T) {
	doc := spec(`{"/u/{id}":{
		"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}},{"name":"v","in":"query","schema":{"type":"string"},"deprecated":true,"description":"path-level"}],
		"get":{"operationId":"get","parameters":[{"name":"v","in":"query","required":true,"schema":{"type":"integer"}}],"responses":{}},
		"delete":{"operationId":"del","responses":{}}}}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	get := opByName(t, res, "get")
	if want := `{"additionalProperties":false,"properties":{"path_id":{"type":"integer"},"query_v":{"type":"integer"}},"required":["path_id","query_v"],"type":"object"}`; string(get.InputSchema) != want {
		t.Errorf("override:\n got %s\nwant %s", get.InputSchema, want)
	}
	del := opByName(t, res, "del")
	if want := `{"additionalProperties":false,"properties":{"path_id":{"type":"integer"},"query_v":{"deprecated":true,"description":"path-level","type":"string"}},"required":["path_id"],"type":"object"}`; string(del.InputSchema) != want {
		t.Errorf("inherited:\n got %s\nwant %s", del.InputSchema, want)
	}

	// A $ref'd parameter from components, and a path parameter whose name
	// does not match the template, which Validate refuses by name.
	refd := spec(`{"/u/{id}":{"get":{"operationId":"get","parameters":[{"$ref":"#/components/parameters/Id"}],"responses":{}}}}`,
		`{"parameters":{"Id":{"name":"id","in":"path","required":true,"schema":{"type":"string"}}}}`)
	mustIngest(t, refd, IngestOptions{})
	mismatch := spec(`{"/u/{id}":{"get":{"operationId":"get","parameters":[{"name":"uid","in":"path","required":true,"schema":{"type":"string"}}],"responses":{}}}}`, "")
	_, err := Ingest([]byte(mismatch), IngestOptions{})
	// Validate checks the two directions (template without property,
	// property without template) and reports the first; either names the
	// operation and the template.
	if !errors.Is(err, ErrInvalidOperations) || !strings.Contains(err.Error(), "GET /u/{id}") || !strings.Contains(err.Error(), "{id}") {
		t.Errorf("template/parameter mismatch: %v", err)
	}
}

func TestIngest_NamesAreDerivedDeterministicallyAndCollisionSafe(t *testing.T) {
	long := strings.Repeat("abcdefghij", 7) // 70 bytes
	doc := spec(`{
		"/users/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"get":{"responses":{}},"delete":{"operationId":"users.delete","responses":{}}},
		"/a":{"get":{"operationId":"dup","responses":{}}},
		"/b":{"get":{"operationId":"dup","responses":{}}},
		"/c":{"get":{"operationId":"`+long+`","responses":{}}},
		"/d":{"get":{"operationId":"  weird name/with.dots__and--dashes  ","responses":{}}}
	}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	names := map[string]bool{}
	for _, op := range res.Ops {
		names[op.Name] = true
	}
	for _, want := range []string{"get_users_id", "users_delete", "weird_name_with_dots_and--dashes"} {
		if !names[want] {
			t.Errorf("missing %q in %v", want, names)
		}
	}
	// Both "dup" operations get a suffix, neither keeps the bare name.
	if names["dup"] {
		t.Errorf("a colliding operationId kept the bare name")
	}
	a, b := "dup"+hashSuffix("GET", "/a"), "dup"+hashSuffix("GET", "/b")
	if !names[a] || !names[b] {
		t.Errorf("colliding names not suffixed as expected: want %q and %q in %v", a, b, names)
	}
	// The long one is truncated to fit the suffix.
	c := long[:gateway.MaxToolNameLen-1-nameHashLen] + hashSuffix("GET", "/c")
	if !names[c] || len(c) != gateway.MaxToolNameLen {
		t.Errorf("long operationId: want %q (%d bytes) in %v", c, len(c), names)
	}
	// Every name is legal, and the same document yields the same names.
	for n := range names {
		if !gateway.ValidToolName(n) {
			t.Errorf("illegal name %q", n)
		}
	}
	if again := mustIngest(t, doc, IngestOptions{}); !bytes.Equal(again.Operations, res.Operations) {
		t.Errorf("names are not deterministic")
	}
}

// TestIngest_RefusesWhatTheSpecMustNotDecide is the table for ADR-0048
// Decisão 6 at the ingestion edge, plus the document-level refusals.
func TestIngest_RefusesWhatTheSpecMustNotDecide(t *testing.T) {
	deepJSON := func(n int) string {
		return spec(`{"/a":{"get":{"operationId":"a","responses":{},"x-deep":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`}}}`, "")
	}
	cases := []struct {
		name     string
		doc      string
		opts     IngestOptions
		sentinel error
		want     []string // substrings of the error
	}{
		{name: "swagger 2.0", doc: `{"swagger":"2.0","info":{},"paths":{}}`, sentinel: ErrInvalidDocument, want: []string{"Swagger 2.0", "convert"}},
		{name: "unknown version", doc: `{"openapi":"4.0.0","paths":{}}`, sentinel: ErrInvalidDocument, want: []string{"4.0.0"}},
		{name: "no version", doc: `{"paths":{}}`, sentinel: ErrInvalidDocument, want: []string{"openapi"}},
		{name: "not an object", doc: `[1,2]`, sentinel: ErrInvalidDocument, want: []string{"top level"}},
		{name: "empty", doc: "", sentinel: ErrInvalidDocument, want: []string{"empty"}},
		{name: "invalid JSON", doc: `{"openapi": "3.0.0",`, sentinel: ErrInvalidDocument, want: []string{"parsed as JSON"}},
		{name: "invalid YAML", doc: "openapi: 3.0.0\npaths: [\n  - :\n", sentinel: ErrInvalidDocument, want: []string{"parsed as YAML"}},
		// An unquoted decimal key (200:) is read as its digits
		// (TestIngest_YAMLConversionMatchesJSON); any other non-string key
		// is refused, saying where and how to fix it.
		{name: "YAML non-string key", doc: "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      operationId: a\n      responses:\n        2.5: {description: ok}\n", sentinel: ErrInvalidDocument, want: []string{"not a string", "at /paths/~1a/get/responses (line 7)", "quote it"}},
		{name: "YAML key defined twice", doc: "openapi: 3.0.0\npaths:\n  /a:\n    get: {operationId: a, responses: {}}\n    get: {operationId: b, responses: {}}\n", sentinel: ErrInvalidDocument, want: []string{`"get" is defined twice`, "at /paths/~1a"}},
		{name: "YAML custom tag", doc: "openapi: 3.0.0\nx: !secret abc\npaths: {}\n", sentinel: ErrInvalidDocument, want: []string{`"!secret"`, "no JSON form", "at /x"}},
		{name: "YAML version unquoted", doc: "openapi: 3.0\npaths: {}\n", sentinel: ErrInvalidDocument, want: []string{"number 3.0", "quote it"}},
		// The billion-laughs shapes. Small on disk, acyclic, and expanding
		// geometrically: each is refused by its own ceiling, in
		// milliseconds, and none may be relied on to be someone else's.
		{name: "YAML alias bomb", doc: yamlAliasBomb(), sentinel: ErrInvalidDocument, want: []string{"excessive aliasing"}},
		{name: "$ref fan-out past the node budget", doc: refFanOut(6, 10), sentinel: ErrInvalidDocument, want: []string{"schema expansion exceeds", "nodes"}},
		{name: "$ref chain past the depth bound", doc: refChain(maxRefDepth + 8), sentinel: ErrInvalidDocument, want: []string{"deeper than 32"}},
		{name: "set past maxOperationsBytes", doc: bigSharedEnum(100, 50<<10), sentinel: ErrInvalidOperations, want: []string{"operation set", "over the limit", fmt.Sprint(maxOperationsBytes)}},
		{name: "YAML infinity", doc: "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      operationId: a\n      parameters: [{name: q, in: query, schema: {type: number, maximum: .inf}}]\n      responses: {}\n", sentinel: ErrInvalidDocument, want: []string{"infinity"}},
		{name: "document too large", doc: `{"openapi":"3.0.0","paths":{},"x":"` + strings.Repeat("a", maxDocumentBytes) + `"}`, sentinel: ErrInvalidDocument, want: []string{"over the", "limit"}},
		{name: "JSON too deep", doc: deepJSON(maxDocumentDepth + 1), sentinel: ErrInvalidDocument, want: []string{"levels deep"}},
		{name: "YAML flow too deep", doc: "openapi: 3.0.0\npaths: {}\nx: " + strings.Repeat("[", maxDocumentDepth+1) + strings.Repeat("]", maxDocumentDepth+1) + "\n", sentinel: ErrInvalidDocument, want: []string{"levels deep"}},
		{name: "YAML block sequence too deep", doc: "openapi: 3.0.0\npaths: {}\nx:\n  " + strings.Repeat("- ", maxDocumentDepth+1) + "1\n", sentinel: ErrInvalidDocument, want: []string{"levels deep"}},
		{name: "no paths", doc: `{"openapi":"3.1.0","webhooks":{}}`, sentinel: ErrInvalidDocument, want: []string{"paths"}},
		{name: "only unservable methods", doc: spec(`{"/a":{"trace":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"no operation", "1 skipped"}},

		// servers[]
		{name: "server variable", doc: `{"openapi":"3.0.0","servers":[{"url":"https://{region}.example.com/v1","variables":{"region":{"default":"eu"}}}],"paths":{"/a":{"get":{"operationId":"a","responses":{}}}}}`, sentinel: ErrInvalidDocument, want: []string{"server variable", "-url"}},
		{name: "server url with query", doc: `{"openapi":"3.0.0","servers":[{"url":"/v1?x=1"}],"paths":{"/a":{"get":{"operationId":"a","responses":{}}}}}`, sentinel: ErrInvalidDocument, want: []string{"query"}},
		{name: "server base path with ..", doc: `{"openapi":"3.0.0","servers":[{"url":"https://h/v1/../admin"}],"paths":{"/a":{"get":{"operationId":"a","responses":{}}}}}`, sentinel: ErrInvalidDocument, want: []string{"dot segment"}},
		{name: "server base path with //", doc: `{"openapi":"3.0.0","servers":[{"url":"//evil.tld//x"}],"paths":{"/a":{"get":{"operationId":"a","responses":{}}}}}`, sentinel: ErrInvalidDocument, want: []string{"//"}},

		// Paths: an SSRF inside signed bytes is refused before the operation is read.
		{name: "path with scheme", doc: spec(`{"https://evil.tld/x":{"get":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"exactly one"}},
		{name: "path with authority", doc: spec(`{"//evil.tld/x":{"get":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"//"}},
		{name: "path with dot segment", doc: spec(`{"/a/../b":{"get":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"dot segment"}},
		{name: "path with CRLF", doc: spec(`{"/a\r\nHost: x":{"get":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"outside the characters"}},
		{name: "path with query", doc: spec(`{"/a?x=1":{"get":{"operationId":"a","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"query and fragment"}},
		{name: "path item $ref", doc: spec(`{"/a":{"$ref":"#/components/pathItems/A"}}`, ""), sentinel: ErrInvalidDocument, want: []string{"path item $ref"}},

		// Parameter names: control headers and the auth slot, named with the operation and the parameter.
		{name: "header_Host", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"Host","in":"header","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"GET /x", `"header_Host"`, "control header"}},
		{name: "header_Transfer_Encoding (underscore)", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"Transfer_Encoding","in":"header","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"GET /x", "header_Transfer_Encoding", "control header"}},
		// A parameter on the credential's own slot is dropped, not refused:
		// TestIngest_AParameterOnTheAuthSlotIsDroppedNotServed.
		{name: "header with CRLF", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"X\r\nEvil","in":"header","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"GET /x", "HTTP token"}},
		{name: "cookie with semicolon", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"a;b","in":"cookie","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"GET /x", "cookie_a;b", "HTTP token"}},
		{name: "query name with space", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"a b","in":"query","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"GET /x", "printable ASCII"}},
		{name: "parameter in unknown location", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"a","in":"body","schema":{"type":"string"}}],"responses":{}}}}`, ""), sentinel: ErrInvalidDocument, want: []string{"GET /x", `"in" "body"`}},
		{name: "parameter without schema or content", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"a","in":"query"}],"responses":{}}}}`, ""), sentinel: ErrInvalidDocument, want: []string{"GET /x", "neither"}},
		{name: "parameter declared twice", doc: spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"a","in":"query","schema":{}},{"name":"a","in":"query","schema":{}}],"responses":{}}}}`, ""), sentinel: ErrInvalidDocument, want: []string{"GET /x", "twice"}},
		// A body on GET is skipped (TestIngest_SkipsAndWarnsRatherThanGuessing);
		// alone in a document it leaves nothing to serve.
		{name: "body on GET", doc: spec(`{"/x":{"get":{"operationId":"x","requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"no operation", "1 skipped"}},

		// Names and sizes.
		{name: "operationId not a string", doc: spec(`{"/x":{"get":{"operationId":7,"responses":{}}}}`, ""), sentinel: ErrInvalidDocument, want: []string{"operationId must be a string"}},
		{name: "names collide after hashing", doc: spec(`{"/x":{"get":{"operationId":"dup`+hashSuffix("GET", "/y")+`","responses":{}}},"/y":{"get":{"operationId":"dup","responses":{}},"post":{"operationId":"dup","responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"both derive the tool name"}},
		{name: "definition over the gateway's ceiling", doc: spec(`{"/x":{"post":{"operationId":"x","requestBody":{"content":{"application/json":{"schema":{"enum":["`+strings.Repeat("e", gateway.MaxToolDefinitionBytes)+`"]}}}},"responses":{}}}}`, ""), sentinel: ErrInvalidOperations, want: []string{"POST /x", "over the", "limit the gateway serves"}},
		{name: "too many operations", doc: spec(manyPaths(maxOperations+1), ""), sentinel: ErrInvalidDocument, want: []string{"more than"}},
		{name: "auth name without kind", doc: specJSON, opts: IngestOptions{AuthName: "X"}, sentinel: ErrInvalidOperations, want: []string{"without an auth kind"}},
		{name: "unknown auth kind", doc: specJSON, opts: IngestOptions{AuthKind: "basic"}, sentinel: ErrInvalidOperations, want: []string{"auth kind"}},
		{name: "operator URL refused", doc: specJSON, opts: IngestOptions{BaseURL: "ftp://h/"}, sentinel: ErrInvalidURL, want: []string{"scheme"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Ingest([]byte(c.doc), c.opts)
			if err == nil {
				t.Fatalf("accepted; wanted an error containing %q", c.want)
			}
			if !errors.Is(err, c.sentinel) {
				t.Errorf("error does not wrap %v: %v", c.sentinel, err)
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

// yamlAliasBomb is the billion-laughs document: nine levels of ten
// aliases, 10^9 leaves, a few hundred bytes.
func yamlAliasBomb() string {
	var b strings.Builder
	b.WriteString("openapi: 3.0.0\npaths: {}\nl0: &l0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n")
	for i := 1; i <= 9; i++ {
		fmt.Fprintf(&b, "l%d: &l%d [", i, i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "*l%d", i-1)
		}
		b.WriteString("]\n")
	}
	return b.String()
}

// refFanOut is the $ref shape of the same attack: components L0..L(levels-1)
// each a oneOf of width $refs to the next level, the last an empty schema.
// width^levels schema nodes from a few kilobytes -- and almost no bytes of
// kept keywords, so it is the node budget (maxSchemaNodes), not the byte
// charge, that has to stop it: the two guard different things.
func refFanOut(levels, width int) string {
	var comps []string
	for l := 0; l < levels; l++ {
		branches := make([]string, width)
		for w := range branches {
			branches[w] = fmt.Sprintf(`{"$ref":"#/components/schemas/L%d"}`, l+1)
		}
		comps = append(comps, fmt.Sprintf(`"L%d":{"oneOf":[%s]}`, l, strings.Join(branches, ",")))
	}
	comps = append(comps, fmt.Sprintf(`"L%d":{}`, levels))
	return spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/L0"}}}},"responses":{}}}}`,
		`{"schemas":{`+strings.Join(comps, ",")+`}}`)
}

// refChain is C0 -> C1 -> ... -> C(n-1) -> leaf.
func refChain(n int) string {
	comps := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		comps = append(comps, fmt.Sprintf(`"C%d":{"$ref":"#/components/schemas/C%d"}`, i, i+1))
	}
	comps = append(comps, fmt.Sprintf(`"C%d":{"type":"string"}`, n))
	return spec(`{"/a":{"post":{"operationId":"a","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/C0"}}}},"responses":{}}}}`,
		`{"schemas":{`+strings.Join(comps, ",")+`}}`)
}

// bigSharedEnum is ops operations whose body $refs one component holding an
// enum of about enumBytes: each definition under the 64 KiB ceiling, the
// set past maxOperationsBytes when ops*enumBytes is.
func bigSharedEnum(ops, enumBytes int) string {
	var paths []string
	for i := 0; i < ops; i++ {
		paths = append(paths, fmt.Sprintf(`"/p%d":{"post":{"operationId":"p%d","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/E"}}}},"responses":{}}}`, i, i))
	}
	values := make([]string, enumBytes/1024)
	for i := range values {
		values[i] = `"` + strings.Repeat(string(rune('a'+i%26)), 1020) + fmt.Sprintf("%03d", i%1000) + `"`
	}
	return spec("{"+strings.Join(paths, ",")+"}", `{"schemas":{"E":{"type":"string","enum":[`+strings.Join(values, ",")+`]}}}`)
}

func manyPaths(n int) string {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"/p%d":{"get":{"operationId":"p%d","responses":{}}}`, i, i)
	}
	b.WriteString("}")
	return b.String()
}

func TestIngest_SkipsAndWarnsRatherThanGuessing(t *testing.T) {
	doc := spec(`{
		"/upload":{"post":{"operationId":"upload","requestBody":{"content":{"multipart/form-data":{"schema":{"type":"object"}}}},"responses":{}}},
		"/xml":{"parameters":[{"name":"f","in":"query","content":{"application/xml":{"schema":{}}}}],"get":{"operationId":"xml","responses":{}},"post":{"operationId":"xml2","responses":{}}},
		"/echo":{"trace":{"operationId":"echo","responses":{}},"connect":{"operationId":"tunnel","responses":{}},"get":{"operationId":"echo","responses":{},"servers":[{"url":"https://other"}],
			"parameters":[{"name":"Authorization","in":"header","schema":{"type":"string"}},{"name":"Accept","in":"header","schema":{"type":"string"}},{"name":"q","in":"query","content":{"application/vnd.api+json":{"schema":{"type":"string"}}}}]}},
		"/search":{"get":{"operationId":"search","requestBody":{"content":{"application/json":{"schema":{"type":"object"}}}},"responses":{}}},
		"x-extension":{"get":{"operationId":"never"}}
	}`, "")
	res := mustIngest(t, doc, IngestOptions{BaseURL: "https://h/base"})
	if len(res.Ops) != 1 || res.Ops[0].Name != "echo" {
		t.Fatalf("want only echo; got %s", res.Operations)
	}
	// The ignored Authorization header did not become a property; the
	// +json parameter content did.
	if want := `{"additionalProperties":false,"properties":{"query_q":{"type":"string"}},"type":"object"}`; string(res.Ops[0].InputSchema) != want {
		t.Errorf("echo:\n got %s\nwant %s", res.Ops[0].InputSchema, want)
	}
	for _, want := range []string{
		"POST /upload: requestBody: no application/json media type (declared: multipart/form-data)",
		"GET /xml: path-level parameters:",
		"POST /xml: path-level parameters:",
		"TRACE /echo: method not served",
		"CONNECT /echo: method not served",
		// Skipped, not fatal: one GET with a body must not keep the rest of
		// the document out.
		"GET /search: requestBody on a safe method is not sent by this adapter",
	} {
		if !hasLine(res.Skipped, want) {
			t.Errorf("skipped lacks %q: %v", want, res.Skipped)
		}
	}
	if len(res.Skipped) != 6 {
		t.Errorf("want 6 skipped, got %d: %v", len(res.Skipped), res.Skipped)
	}
	for _, want := range []string{
		`header parameter "Authorization" ignored`,
		`header parameter "Accept" ignored`,
		"operation-level servers ignored",
		// A vendor extension of the Paths Object is not an operation, so it
		// is not Skipped, but it is reported.
		`paths["x-extension"]: vendor extension ignored`,
	} {
		if !hasLine(res.Warnings, want) {
			t.Errorf("warnings lack %q: %v", want, res.Warnings)
		}
	}
	// No servers[] in the document: the operator's URL is untouched.
	if res.BaseURL != "https://h/base" || res.BasePath != "" {
		t.Errorf("base: %q %q", res.BaseURL, res.BasePath)
	}
}

func TestIngest_ServersDecision(t *testing.T) {
	withServers := func(servers string) string {
		return `{"openapi":"3.0.0","servers":` + servers + `,"paths":{"/a":{"get":{"operationId":"a","responses":{}}}}}`
	}
	cases := []struct {
		name          string
		servers       string
		operatorURL   string
		wantURL       string
		wantPath      string
		wantWarn      string
		wantNoWarnHit string
	}{
		{name: "relative base path folded", servers: `[{"url":"/v1"}]`, operatorURL: "https://h", wantURL: "https://h/v1", wantPath: "/v1"},
		{name: "trailing slash on both sides", servers: `[{"url":"https://h/v1/"}]`, operatorURL: "https://h/", wantURL: "https://h/v1", wantPath: "/v1"},
		{name: "same host no warning", servers: `[{"url":"https://h:443/v1"}]`, operatorURL: "https://h", wantURL: "https://h/v1", wantPath: "/v1", wantNoWarnHit: "ignored"},
		{name: "different host warned", servers: `[{"url":"http://spec.example/v1"}]`, operatorURL: "https://h", wantURL: "https://h/v1", wantPath: "/v1", wantWarn: "servers[0].url names http://spec.example:80; ignored"},
		{name: "operator base path wins", servers: `[{"url":"https://h/v1"}]`, operatorURL: "https://h/v2", wantURL: "https://h/v2", wantPath: "", wantWarn: `already carries base path "/v2"`},
		{name: "operator base path equal, no warning", servers: `[{"url":"https://h/v2"}]`, operatorURL: "https://h/v2", wantURL: "https://h/v2", wantPath: "", wantNoWarnHit: "already carries"},
		{name: "several servers", servers: `[{"url":"/v1"},{"url":"/v2"}]`, operatorURL: "https://h", wantURL: "https://h/v1", wantPath: "/v1", wantWarn: "servers[] lists 2 entries"},
		{name: "root path is no base path", servers: `[{"url":"https://h/"}]`, operatorURL: "https://h", wantURL: "https://h", wantPath: ""},
		{name: "no operator url", servers: `[{"url":"https://spec.example/v1"}]`, operatorURL: "", wantURL: "", wantPath: "/v1", wantWarn: "the host is always the registered -url"},
		{name: "empty servers", servers: `[]`, operatorURL: "https://h/x", wantURL: "https://h/x", wantPath: ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustIngest(t, withServers(c.servers), IngestOptions{BaseURL: c.operatorURL})
			if res.BaseURL != c.wantURL || res.BasePath != c.wantPath {
				t.Errorf("url %q path %q; want %q %q", res.BaseURL, res.BasePath, c.wantURL, c.wantPath)
			}
			if c.wantWarn != "" && !hasLine(res.Warnings, c.wantWarn) {
				t.Errorf("warnings lack %q: %v", c.wantWarn, res.Warnings)
			}
			if c.wantNoWarnHit != "" && hasLine(res.Warnings, c.wantNoWarnHit) {
				t.Errorf("unexpected warning %q: %v", c.wantNoWarnHit, res.Warnings)
			}
		})
	}
}

func TestIngest_AuthDecision(t *testing.T) {
	withSchemes := func(schemes string) string {
		return spec(`{"/a":{"get":{"operationId":"a","responses":{}}}}`, `{"securitySchemes":`+schemes+`}`)
	}
	cases := []struct {
		name     string
		schemes  string
		opts     IngestOptions
		kind     string
		authName string
		derived  bool
		warn     string
	}{
		{name: "derived apiKey header", schemes: `{"k":{"type":"apiKey","in":"header","name":"X-API-Key"}}`, kind: AuthHeader, authName: "X-API-Key", derived: true, warn: "derived from securitySchemes.k (apiKey in header X-API-Key): kind header name X-API-Key"},
		{name: "derived apiKey query", schemes: `{"k":{"type":"apiKey","in":"query","name":"key"}}`, kind: AuthQuery, authName: "key", derived: true, warn: "kind query name key"},
		{name: "derived http bearer", schemes: `{"k":{"type":"http","scheme":"Bearer"}}`, kind: AuthBearer, derived: true, warn: "kind bearer"},
		{name: "operator wins over the spec", schemes: `{"k":{"type":"apiKey","in":"header","name":"X-Other"}}`, opts: IngestOptions{AuthKind: AuthBearer}, kind: AuthBearer, warn: "the operator's -auth-kind bearer wins"},
		{name: "operator header wins, with its name", schemes: `{"k":{"type":"http","scheme":"bearer"}}`, opts: IngestOptions{AuthKind: AuthHeader, AuthName: "X-Key"}, kind: AuthHeader, authName: "X-Key", warn: "the operator's -auth-kind header name X-Key wins"},
		{name: "NoDerive: keyless, the scheme reported as ignored", schemes: `{"k":{"type":"apiKey","in":"header","name":"X-API-Key"}}`, opts: IngestOptions{NoDerive: true}, kind: AuthNone, warn: "-auth-kind none: the document's security scheme was ignored and the entry is keyless (securitySchemes.k (apiKey in header X-API-Key))"},
		{name: "raw Authorization header is a legal slot", schemes: `{"k":{"type":"apiKey","in":"header","name":"Authorization"}}`, kind: AuthHeader, authName: "Authorization", derived: true, warn: "kind header name Authorization"},
		{name: "operator agrees with the spec, no warning", schemes: `{"k":{"type":"apiKey","in":"header","name":"x-api-key"}}`, opts: IngestOptions{AuthKind: AuthHeader, AuthName: "X-API-Key"}, kind: AuthHeader, authName: "X-API-Key"},
		{name: "two schemes: keyless with warning", schemes: `{"a":{"type":"apiKey","in":"header","name":"A"},"b":{"type":"http","scheme":"bearer"}}`, kind: AuthNone, warn: "declares 2 security schemes"},
		{name: "oauth2 only: keyless with warning", schemes: `{"o":{"type":"oauth2","flows":{}}}`, kind: AuthNone, warn: "not injectable"},
		{name: "cookie apiKey: keyless with warning", schemes: `{"c":{"type":"apiKey","in":"cookie","name":"s"}}`, kind: AuthNone, warn: "not injectable"},
		{name: "none: keyless silently", schemes: `{}`, kind: AuthNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustIngest(t, withSchemes(c.schemes), c.opts)
			if res.AuthKind != c.kind || res.AuthName != c.authName || res.AuthDerived != c.derived {
				t.Errorf("got %q %q derived=%v; want %q %q derived=%v", res.AuthKind, res.AuthName, res.AuthDerived, c.kind, c.authName, c.derived)
			}
			if c.warn != "" && !hasLine(res.Warnings, c.warn) {
				t.Errorf("warnings lack %q: %v", c.warn, res.Warnings)
			}
			if c.warn == "" && len(res.Warnings) != 0 {
				t.Errorf("unexpected warnings: %v", res.Warnings)
			}
		})
	}

	// A derived header name that is not an HTTP token is a document error,
	// never a descriptor the register would write.
	bad := withSchemes(`{"k":{"type":"apiKey","in":"header","name":"X Bad"}}`)
	if _, err := Ingest([]byte(bad), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "cannot derive") {
		t.Errorf("bad derived name: %v", err)
	}

	// The control-header denylist holds for the injection slot as it does
	// for a parameter: the spec cannot pick Connection by derivation, and
	// the operator cannot pick it by flag (the credential would be dropped
	// by net/http or stripped as hop-by-hop).
	for _, name := range []string{"Connection", "Proxy-Authorization", "Host", "transfer_encoding", "Cookie"} {
		derivedDoc := withSchemes(`{"k":{"type":"apiKey","in":"header","name":"` + name + `"}}`)
		if _, err := Ingest([]byte(derivedDoc), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "control header") {
			t.Errorf("derived %s: %v", name, err)
		}
		if _, err := Ingest([]byte(withSchemes(`{}`)), IngestOptions{AuthKind: AuthHeader, AuthName: name}); !errors.Is(err, ErrInvalidOperations) || !strings.Contains(err.Error(), "control header") {
			t.Errorf("-auth-name %s: %v", name, err)
		}
	}

	// NoDerive: the set is validated keyless, so a parameter on the slot
	// the scheme would have reserved is legal -- and NoDerive with a kind
	// is a contradiction.
	slot := spec(`{"/a":{"get":{"operationId":"a","parameters":[{"name":"X-API-Key","in":"header","schema":{"type":"string"}}],"responses":{}}}}`,
		`{"securitySchemes":{"k":{"type":"apiKey","in":"header","name":"X-API-Key"}}}`)
	// The derived descriptor reserves its slot: the parameter on it is
	// dropped (the server-side value is the one sent), with a warning.
	derived := mustIngest(t, slot, IngestOptions{})
	if derived.AuthKind != AuthHeader || strings.Contains(string(derived.Ops[0].InputSchema), "header_X-API-Key") ||
		!hasLine(derived.Warnings, `"X-API-Key" dropped`) {
		t.Errorf("derived descriptor must reserve its slot: kind %q schema %s warnings %v",
			derived.AuthKind, derived.Ops[0].InputSchema, derived.Warnings)
	}
	res := mustIngest(t, slot, IngestOptions{NoDerive: true})
	if res.AuthKind != AuthNone || res.AuthDerived || hasLine(res.Warnings, "derived") || hasLine(res.Warnings, "-env) is required") {
		t.Errorf("NoDerive: %q derived=%v warnings %v", res.AuthKind, res.AuthDerived, res.Warnings)
	}
	if _, err := Ingest([]byte(slot), IngestOptions{NoDerive: true, AuthKind: AuthBearer}); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("NoDerive with a kind: %v", err)
	}
}

// TestReservedSlots_RegistryMirrorsTheDenylist pins that registry.Validate
// refuses exactly the header injection slots reservedSlots refuses: the
// registry keeps a mirror of the denylist (it cannot import this package),
// and a drift would let a signed entry carry a slot the dialer refuses, or
// the reverse.
func TestReservedSlots_RegistryMirrorsTheDenylist(t *testing.T) {
	names := []string{"Host", "content-length", "Transfer_Encoding", "Connection", "Upgrade", "TE", "Trailer", "Keep-Alive",
		"Cookie", "Proxy-Authorization", "proxy-connection", "Proxy_X", "Authorization", "X-API-Key", "X_Api_Key", "Accept", "TEx"}
	for name := range controlHeaders {
		names = append(names, name, strings.ToUpper(name))
	}
	for _, name := range names {
		_, _, slotErr := reservedSlots(AuthHeader, name)
		entry := registry.UpstreamServer{Name: "r", Transport: registry.TransportHTTP, URL: "https://h.example",
			AuthKind: registry.AuthHeader, AuthName: name, EnvVarNames: []string{"K"}, Operations: []byte(`[{}]`)}
		regErr := entry.Validate()
		if (slotErr == nil) != (regErr == nil) {
			t.Errorf("%q: reservedSlots %v, registry.Validate %v -- the two must agree", name, slotErr, regErr)
		}
	}
}

func TestIngest_OutputSchemaOnlyWhenEvery2xxIsOneJSONObject(t *testing.T) {
	obj := `{"schema":{"type":"object","properties":{"id":{"type":"string"}}}}`
	cases := []struct {
		name      string
		responses string
		want      string
	}{
		{name: "one 200 json object", responses: `{"200":{"description":"","content":{"application/json":` + obj + `}},"404":{"description":"","content":{"text/plain":{}}}}`, want: `{"properties":{"id":{"type":"string"}},"type":"object"}`},
		{name: "2XX range and $ref'd response agree", responses: `{"2XX":{"$ref":"#/components/responses/R"},"201":{"description":"","content":{"application/problem+json":` + obj + `}}}`, want: `{"properties":{"id":{"type":"string"}},"type":"object"}`},
		{name: "204 beside 200", responses: `{"200":{"description":"","content":{"application/json":` + obj + `}},"204":{"description":"no content"}}`},
		{name: "a non-json media type beside json", responses: `{"200":{"description":"","content":{"application/json":` + obj + `,"text/csv":{}}}}`},
		{name: "two 2xx with different objects", responses: `{"200":{"description":"","content":{"application/json":` + obj + `}},"202":{"description":"","content":{"application/json":{"schema":{"type":"object"}}}}}`},
		{name: "array response", responses: `{"200":{"description":"","content":{"application/json":{"schema":{"type":"array","items":{}}}}}}`},
		{name: "nullable object (3.0)", responses: `{"200":{"description":"","content":{"application/json":{"schema":{"type":"object","nullable":true}}}}}`},
		{name: "media type without schema", responses: `{"200":{"description":"","content":{"application/json":{}}}}`},
		{name: "no 2xx", responses: `{"default":{"description":"","content":{"application/json":` + obj + `}}}`},
		{name: "no responses", responses: `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := spec(`{"/a":{"get":{"operationId":"a","responses":`+c.responses+`}}}`, `{"responses":{"R":{"description":"","content":{"application/json":`+obj+`}}}}`)
			res := mustIngest(t, doc, IngestOptions{})
			if string(res.Ops[0].OutputSchema) != c.want {
				t.Errorf("output schema:\n got %s\nwant %s", res.Ops[0].OutputSchema, c.want)
			}
		})
	}

	// HEAD and OPTIONS: never an output schema, even when the responses
	// (copied from the GET, as generators do) declare a JSON object -- the
	// adapter has no body to fill structuredContent from, and the gateway
	// refuses a result without it when an output schema is declared.
	for _, method := range []string{"head", "options"} {
		t.Run(method, func(t *testing.T) {
			doc := spec(`{"/a":{"`+method+`":{"operationId":"a","responses":{"200":{"description":"","content":{"application/json":`+obj+`}}}}}}`, "")
			res := mustIngest(t, doc, IngestOptions{})
			if res.Ops[0].OutputSchema != nil {
				t.Errorf("%s yields output schema %s", method, res.Ops[0].OutputSchema)
			}
			if !hasLine(res.Warnings, "response content ignored, no output schema") {
				t.Errorf("no warning for the ignored content: %v", res.Warnings)
			}
		})
	}
}

// TestIngest_SchemasAreHeldToWhatTheGatewayCompiles pins the decision on
// routesFor's per-tool refusals (ADR-0047 §3): an output schema the gateway
// would refuse at connect (gateway.CheckOutputSchema, jsonschema-go) is
// dropped at register with a warning, and an input schema is held to the
// gateway's input check only -- nothing compiles it, so a "pattern" RE2
// cannot read is kept as written.
func TestIngest_SchemasAreHeldToWhatTheGatewayCompiles(t *testing.T) {
	lookahead := `"^(?!admin).*$"`
	doc := spec(`{"/a":{"get":{"operationId":"a",
		"parameters":[{"name":"u","in":"query","schema":{"type":"string","pattern":`+lookahead+`}}],
		"responses":{"200":{"description":"","content":{"application/json":{"schema":{"type":"object","properties":{"u":{"type":"string","pattern":`+lookahead+`}}}}}}}}},
		"/b":{"get":{"operationId":"b","responses":{"200":{"description":"","content":{"application/json":{"schema":{"type":"object","properties":{"n":{"type":"integer","minimum":"1"}}}}}}}}}}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	a, b := opByName(t, res, "a"), opByName(t, res, "b")
	if a.OutputSchema != nil || b.OutputSchema != nil {
		t.Errorf("uncompilable output schemas kept: a %s, b %s", a.OutputSchema, b.OutputSchema)
	}
	for _, where := range []string{"GET /a: output schema will not compile, dropped", "GET /b: output schema will not compile, dropped"} {
		if !hasLine(res.Warnings, where) {
			t.Errorf("warnings lack %q: %v", where, res.Warnings)
		}
	}
	if !strings.Contains(string(a.InputSchema), `"pattern":"^(?!admin).*$"`) {
		t.Errorf("the input pattern was not kept as written: %s", a.InputSchema)
	}
	// What the register keeps, the gateway accepts at connect.
	for _, op := range res.Ops {
		if err := gateway.CheckOutputSchema(op.OutputSchema); err != nil {
			t.Errorf("%s: output schema refused by the gateway: %v", op.Name, err)
		}
		if err := gateway.CheckInputSchema(op.InputSchema); err != nil {
			t.Errorf("%s: input schema refused by the gateway: %v", op.Name, err)
		}
	}
}

// TestIngest_ExpansionIsChargedInBytesBeforeItIsSerialized is the
// amplification the node budget cannot see: one component whose enum is
// ~1 MiB, referenced from 300 properties. Each reference is one node; the
// serialization would write the enum 300 times (315 MB). The byte charge
// refuses at the first reference, and the refusal costs about what the
// document does, not what its expansion would.
func TestIngest_ExpansionIsChargedInBytesBeforeItIsSerialized(t *testing.T) {
	values := make([]string, 1024)
	for i := range values {
		values[i] = `"` + strings.Repeat("v", 1018) + fmt.Sprintf("%04d", i) + `"`
	}
	props := make([]string, 300)
	for i := range props {
		props[i] = fmt.Sprintf(`"p%d":{"$ref":"#/components/schemas/X"}`, i)
	}
	doc := spec(`{"/p":{"post":{"operationId":"p","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{`+strings.Join(props, ",")+`}}}}},"responses":{}}}}`,
		`{"schemas":{"X":{"type":"string","enum":[`+strings.Join(values, ",")+`]}}}`)

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := Ingest([]byte(doc), IngestOptions{})
	runtime.ReadMemStats(&after)

	if !errors.Is(err, ErrInvalidOperations) || !strings.Contains(err.Error(), "POST /p") || !strings.Contains(err.Error(), "over the 65536-byte limit") {
		t.Fatalf("amplified definition: %v", err)
	}
	alloc := after.TotalAlloc - before.TotalAlloc
	t.Logf("document %d bytes, refused after allocating %d KiB", len(doc), alloc>>10)
	if alloc > 50<<20 {
		t.Errorf("refusing a %d-byte document allocated %d MiB; the charge must refuse before the expansion is serialized", len(doc), alloc>>20)
	}
}

// TestIngest_YAMLNestingIsBoundedByTheParserNotAPreScan: a stray double
// quote in a plain scalar used to hide every bracket after it from the
// removed pre-scan. Nothing crashes: yaml.v3 refuses past 10000 levels in
// milliseconds, and checkDepth holds a shallower document to 64.
func TestIngest_YAMLNestingIsBoundedByTheParserNotAPreScan(t *testing.T) {
	const levels = 1_500_000
	doc := "openapi: 3.0.0\nk: v\"\npaths: {}\nz: " + strings.Repeat("[", levels) + strings.Repeat("]", levels) + "\n"
	_, err := Ingest([]byte(doc), IngestOptions{})
	if !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "exceeded max depth") {
		t.Errorf("1.5 M levels: %v", err)
	}
	shallow := "openapi: 3.0.0\nk: v\"\npaths: {}\nz: " + strings.Repeat("[", 200) + strings.Repeat("]", 200) + "\n"
	if _, err := Ingest([]byte(shallow), IngestOptions{}); !errors.Is(err, ErrInvalidDocument) || !strings.Contains(err.Error(), "levels deep") {
		t.Errorf("200 levels after a stray quote: %v", err)
	}
}

// TestIngest_ReportedTextFromTheDocumentIsEscaped: what Skipped, Warnings
// and errors quote from the document reaches the operator's terminal, so a
// control or bidi character in it is written visibly (internal/visible),
// never as the byte that would repaint the tool table.
func TestIngest_ReportedTextFromTheDocumentIsEscaped(t *testing.T) {
	esc := `\u001b[2J\u001b[H`
	doc := spec(`{"/x":{"post":{"operationId":"x","requestBody":{"content":{"text/plain`+esc+`HIDDEN":{}}},"responses":{}}},"/y":{"get":{"operationId":"y","responses":{}}}}`,
		`{"securitySchemes":{"k`+esc+`LABEL":{"type":"apiKey","in":"header","name":"X-Key"}}}`)
	res := mustIngest(t, doc, IngestOptions{})
	all := strings.Join(append(append([]string{}, res.Skipped...), res.Warnings...), "\n")
	if strings.ContainsRune(all, 0x1b) || !strings.Contains(all, `\u{001B}`) {
		t.Errorf("document text not escaped in the report:\n%q", all)
	}
	bad := spec(`{"/y":{"get":{"operationId":"y","responses":{}}}}`, `{"securitySchemes":{"k`+esc+`":{"type":"apiKey","in":"header","name":"Bad Name"}}}`)
	_, err := Ingest([]byte(bad), IngestOptions{})
	if err == nil || strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), `\u{001B}`) {
		t.Errorf("derivation refusal not escaped: %q", err)
	}
}

func TestIngest_DescriptionRule(t *testing.T) {
	long := strings.Repeat("d", maxDescriptionBytes+10)
	doc := spec(`{
		"/s":{"get":{"operationId":"s","summary":"  Summary wins  ","description":"not this","responses":{}}},
		"/d":{"get":{"operationId":"d","description":"Description second","responses":{}}},
		"/n":{"get":{"operationId":"n","responses":{}}},
		"/l":{"get":{"operationId":"l","summary":"`+long+`","responses":{}}}
	}`, "")
	res := mustIngest(t, doc, IngestOptions{})
	want := map[string]string{"s": "Summary wins", "d": "Description second", "n": "GET /n", "l": long[:maxDescriptionBytes] + " [truncated]"}
	for name, w := range want {
		if got := opByName(t, res, name).Description; got != w {
			t.Errorf("%s: got %q want %q", name, got, w)
		}
	}
}

// TestIngest_YAMLConversionMatchesJSON pins yamlConverter's number, date
// and key handling: the YAML and JSON spellings of one schema canonicalize
// alike -- 1.0 stays 1.0, an unquoted date stays the date as written, an
// integer past 2^64 stays exact, an unquoted 200: is the key "200", and a
// merge key merges.
func TestIngest_YAMLConversionMatchesJSON(t *testing.T) {
	y := "openapi: 3.1.0\n" +
		"x-anchors: {d: &date {type: string, format: date}}\n" +
		"paths:\n  /a:\n    get:\n      operationId: a\n      parameters:\n" +
		"        - name: n\n          in: query\n          schema: {type: integer, minimum: 1.0, maximum: 10.5, default: -3, enum: [1, 2.5, true, null, \"x\", 123456789012345678901234567890, 0x1F]}\n" +
		"        - name: d\n          in: query\n          schema: {<<: *date, example: 2024-01-01, default: 2024-01-02T10:00:00Z}\n" +
		"      responses:\n        200:\n          description: ok\n          content:\n            application/json:\n              schema: {type: object}\n" +
		"components:\n  schemas:\n    D: {type: string, format: date}\n"
	j := `{"openapi":"3.1.0","x-anchors":{"d":{"type":"string","format":"date"}},"paths":{"/a":{"get":{"operationId":"a","parameters":[` +
		`{"name":"n","in":"query","schema":{"type":"integer","minimum":1.0,"maximum":10.5,"default":-3,"enum":[1,2.5,true,null,"x",123456789012345678901234567890,31]}},` +
		`{"name":"d","in":"query","schema":{"type":"string","format":"date","example":"2024-01-01","default":"2024-01-02T10:00:00Z"}}],` +
		`"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object"}}}}}}}},` +
		`"components":{"schemas":{"D":{"type":"string","format":"date"}}}}`
	ry, rj := mustIngest(t, y, IngestOptions{}), mustIngest(t, j, IngestOptions{})
	if !bytes.Equal(ry.Operations, rj.Operations) {
		t.Errorf("YAML and JSON differ:\n yaml %s\n json %s", ry.Operations, rj.Operations)
	}
	var probe []map[string]any
	if err := json.Unmarshal(ry.Operations, &probe); err != nil {
		t.Fatal(err)
	}
}

// TestIngest_AParameterOnTheAuthSlotIsDroppedNotServed pins the decision of
// 09 Oct 2026, taken against the public Petstore document, whose
// DELETE /pet/{petId} declares the api_key header the credential goes in: a
// parameter on the credential's slot -- in any case, with '_' for '-', at
// path or operation level, for header and query descriptors -- is dropped
// from the tool with a warning naming the operation, and never becomes a
// property the analyst's model could set. Refusing it kept the whole API
// out for a declaration the server-wins rule makes redundant.
func TestIngest_AParameterOnTheAuthSlotIsDroppedNotServed(t *testing.T) {
	cases := []struct {
		name     string
		paths    string
		opts     IngestOptions
		gone     string
		kept     string
		warnLike string
	}{
		{
			name:     "header, other case",
			paths:    `{"/pet/{petId}":{"delete":{"operationId":"deletePet","parameters":[{"name":"API_KEY","in":"header","schema":{"type":"string"}},{"name":"petId","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{}}}}`,
			opts:     header(AuthHeader, "api-key"),
			gone:     "header_API_KEY",
			kept:     "path_petId",
			warnLike: `DELETE /pet/{petId}: header parameter "API_KEY" dropped`,
		},
		{
			name:     "header, declared at path level",
			paths:    `{"/x":{"parameters":[{"name":"X-API-Key","in":"header","schema":{"type":"string"}}],"get":{"operationId":"x","parameters":[{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{}}}}`,
			opts:     header(AuthHeader, "X-API-Key"),
			gone:     "header_X-API-Key",
			kept:     "query_q",
			warnLike: `GET /x: header parameter "X-API-Key" dropped`,
		},
		{
			name:     "query",
			paths:    `{"/x":{"get":{"operationId":"x","parameters":[{"name":"KEY","in":"query","schema":{"type":"string"}},{"name":"q","in":"query","schema":{"type":"string"}}],"responses":{}}}}`,
			opts:     IngestOptions{AuthKind: AuthQuery, AuthName: "key"},
			gone:     "query_KEY",
			kept:     "query_q",
			warnLike: `GET /x: query parameter "KEY" dropped`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustIngest(t, spec(tc.paths, ""), tc.opts)
			schema := string(res.Ops[0].InputSchema)
			if strings.Contains(schema, tc.gone) {
				t.Errorf("the auth slot became a property: %s", schema)
			}
			if !strings.Contains(schema, tc.kept) {
				t.Errorf("a parameter beside the slot was lost: %s", schema)
			}
			if !hasLine(res.Warnings, tc.warnLike) {
				t.Errorf("no warning like %q in %v", tc.warnLike, res.Warnings)
			}
			if _, err := Decode(res.Operations, res.AuthKind, res.AuthName); err != nil {
				t.Errorf("the ingested set does not decode under its own descriptor: %v", err)
			}
		})
	}

	// The same name on a keyless API is an ordinary header.
	res := mustIngest(t, spec(`{"/x":{"get":{"operationId":"x","parameters":[{"name":"X-API-Key","in":"header","schema":{"type":"string"}}],"responses":{}}}}`, ""),
		IngestOptions{NoDerive: true})
	if !strings.Contains(string(res.Ops[0].InputSchema), "header_X-API-Key") {
		t.Errorf("keyless: the header was dropped though nothing is injected there: %s", res.Ops[0].InputSchema)
	}
}
