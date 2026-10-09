package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	gwrest "github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/signer"
)

// `upstream register -transport http` end to end: the -openapi document
// becomes the frozen operation set, the -url (with the document's base path
// folded in) the destination, and the -auth-kind/-auth-name (given or
// derived) the injection descriptor -- all before the database is opened,
// through the adapter's own functions (ADR-0047 §3, ADR-0048 Decisão 6).

// restSpecJSON is the mini-spec of the resthttp ingestion tests: a GET with
// a parameter in each location, a POST with a oneOf body, a servers[] base
// path to fold, and one apiKey scheme to derive from.
const restSpecJSON = `{
  "openapi": "3.0.3",
  "info": {"title": "ioc", "version": "1"},
  "servers": [{"url": "https://elsewhere.example.net/api/v2"}],
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
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/report": {
      "post": {
        "operationId": "report",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"oneOf": [{"$ref": "#/components/schemas/A"}, {"$ref": "#/components/schemas/B"}]}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/upload": {
      "post": {
        "operationId": "upload",
        "requestBody": {"content": {"multipart/form-data": {"schema": {"type": "object"}}}},
        "responses": {"201": {"description": "created"}}
      }
    }
  },
  "components": {
    "schemas": {
      "A": {"type": "object", "additionalProperties": false, "properties": {"ip": {"type": "string"}}},
      "B": {"type": "object", "additionalProperties": false, "properties": {"url": {"type": "string"}}}
    },
    "securitySchemes": {"key": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}
  }
}`

// restSpecYAML is restSpecJSON in YAML, as an operator would write it.
const restSpecYAML = `openapi: 3.0.3
info: {title: ioc, version: "1"}
servers:
  - url: https://elsewhere.example.net/api/v2
paths:
  /check/{ip}:
    parameters:
      - {name: ip, in: path, required: true, schema: {type: string}}
    get:
      operationId: check.ip
      summary: Look an IP up
      parameters:
        - {name: verbose, in: query, schema: {type: boolean}}
        - {name: X-Request-Id, in: header, schema: {type: string}}
      responses:
        "200": {description: ok}
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
  /upload:
    post:
      operationId: upload
      requestBody:
        content:
          multipart/form-data:
            schema: {type: object}
      responses:
        "201": {description: created}
components:
  schemas:
    A: {type: object, additionalProperties: false, properties: {ip: {type: string}}}
    B: {type: object, additionalProperties: false, properties: {url: {type: string}}}
  securitySchemes:
    key: {type: apiKey, in: header, name: X-API-Key}
`

// writeSpec writes a document to a temp file and returns its path.
func writeSpec(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// httpTestConfig is a valid operator configuration (a signer section with a
// trusted key, as a real file has) for the end-to-end register runs.
func httpTestConfig(t *testing.T) string {
	t.Helper()
	return writeOperatorConfig(t, signerSection(t, writeSigningKey(t, 0o600)))
}

// storedEntry reads an entry back through the console's own database path,
// so the test sees what the next command will see.
func storedEntry(t *testing.T, configPath, name string) registry.UpstreamServer {
	t.Helper()
	var got registry.UpstreamServer
	code := opRun(configPath, io.Discard, io.Discard, func(e *opEnv) int {
		entry, err := e.upstreams().Get(e.ctx(), name)
		if err != nil {
			t.Fatalf("Get(%q): %v", name, err)
		}
		got = entry
		return exitOK
	})
	requireExit(t, code, exitOK, "reading the entry back")
	return got
}

// TestCmdUpstreamRegister_HTTPFromFile is the success path, JSON and YAML:
// the stored entry decodes under its descriptor, carries the folded base
// path, and the console says what it generated and what the operator must
// do next for the sensitive tool.
func TestCmdUpstreamRegister_HTTPFromFile(t *testing.T) {
	for _, tc := range []struct{ name, file, doc string }{
		{"json", "openapi.json", restSpecJSON},
		{"yaml", "openapi.yaml", restSpecYAML},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := httpTestConfig(t)
			var out, errBuf bytes.Buffer
			code := cmdUpstream([]string{
				"register", "-config", configPath, "-name", "ioc", "-transport", "http",
				"-url", "https://api.example.com", "-openapi", writeSpec(t, tc.file, tc.doc),
				"-auth-kind", "header", "-auth-name", "X-API-Key", "-env", "IOC_API_KEY",
			}, &out, &errBuf)
			requireExit(t, code, exitOK, "register http")
			if errBuf.Len() != 0 {
				t.Errorf("stderr is not empty:\n%s", errBuf.String())
			}

			entry := storedEntry(t, configPath, "ioc")
			if entry.Transport != registry.TransportHTTP || entry.URL != "https://api.example.com/api/v2" {
				t.Errorf("stored transport/url = %s %q, want http https://api.example.com/api/v2 (base path folded, host from -url)", entry.Transport, entry.URL)
			}
			if entry.AuthKind != registry.AuthHeader || entry.AuthName != "X-API-Key" || strings.Join(entry.EnvVarNames, ",") != "IOC_API_KEY" {
				t.Errorf("stored descriptor = %s %q env %v", entry.AuthKind, entry.AuthName, entry.EnvVarNames)
			}
			// What was stored is what the adapter will dial: Decode, with
			// the same descriptor, and a canonical set (Encode reproduces it).
			ops, err := gwrest.Decode(entry.Operations, string(entry.AuthKind), entry.AuthName)
			if err != nil {
				t.Fatalf("the stored operation set does not decode: %v", err)
			}
			if len(ops) != 2 || ops[0].Name != "check_ip" || ops[1].Name != "report" {
				t.Errorf("stored operations = %+v, want check_ip and report", ops)
			}
			if again, err := gwrest.Encode(ops); err != nil || !bytes.Equal(again, entry.Operations) {
				t.Errorf("the stored set is not canonical: Encode(Decode(set)) differs (%v)", err)
			}
			if err := dialTimeRefusal(entry); err != nil {
				t.Errorf("dialTimeRefusal refuses the entry register accepted: %v", err)
			}

			for _, want := range []string{
				`Registered "ioc"`, "https://api.example.com/api/v2", "header X-API-Key: <secret>", "2 operations, sha256",
				"2 tools generated", "(1 safe, 1 sensitive)", "1 operation skipped", "base path /api/v2 folded",
				"check_ip", "GET", "/check/{ip}", "safe",
				"report", "POST", "/report", "sensitive",
				"POST /upload", "multipart",
				"servers[0].url names https://elsewhere.example.net:443; ignored",
				"tool clear", "ioc TOOL", "tool review", "-server ioc", "non_read", "does not re-ingest", "NOT SIGNED",
			} {
				requireContains(t, out.String(), want, "register http output")
			}
			// The operator chose the descriptor; nothing was derived.
			if strings.Contains(out.String(), "DERIVED") {
				t.Errorf("register claims the descriptor was derived:\n%s", out.String())
			}

			// list shows it like any entry, with the URL as stored.
			out.Reset()
			requireExit(t, cmdUpstream([]string{"list", "-config", configPath}, &out, &errBuf), exitOK, "list")
			requireContains(t, out.String(), "https://api.example.com/api/v2", "list")
			requireContains(t, out.String(), "IOC_API_KEY", "list")
		})
	}
}

// TestCmdUpstreamRegister_HTTPFromURLIsGuarded: a document URL goes through
// the adapter's egress guard, which refuses httptest's loopback listener
// before any request leaves -- no production build has a loopback
// allowance (resthttp/export_test.go is the only one, and it is test-only).
// The successful fetch is therefore proven in the resthttp package
// (TestFetchDocument_*); the console's part is that the guard is the one
// doing the reading, and that a refused URL registers nothing.
func TestCmdUpstreamRegister_HTTPFromURLIsGuarded(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(restSpecJSON))
	}))
	t.Cleanup(srv.Close)

	var out, errBuf bytes.Buffer
	// No -config: the refusal must come before anything opens a database.
	code := cmdUpstream([]string{
		"register", "-name", "ioc", "-transport", "http",
		"-url", "https://api.example.com", "-openapi", srv.URL + "/openapi.json",
	}, &out, &errBuf)
	requireExit(t, code, exitCannotRun, "register from a loopback URL")
	requireContains(t, errBuf.String(), "-openapi:", "refusal names the flag")
	requireContains(t, errBuf.String(), "loopback", "refusal is the egress guard's")
	if hits.Load() != 0 {
		t.Errorf("the document server was reached %d times; a literal loopback host is refused before any dial", hits.Load())
	}
	if strings.Contains(out.String(), "Fetched") {
		t.Errorf("register claims to have fetched the document:\n%s", out.String())
	}

	// A URL that would carry a credential is refused before any I/O, and
	// the refusal does not echo it.
	out.Reset()
	errBuf.Reset()
	code = cmdUpstream([]string{
		"register", "-name", "ioc", "-transport", "http",
		"-url", "https://api.example.com", "-openapi", "https://user:hunter2@docs.example.com/openapi.json",
	}, &out, &errBuf)
	requireExit(t, code, exitCannotRun, "register from a URL with userinfo")
	requireContains(t, errBuf.String(), "userinfo", "refusal names the rule")
	if strings.Contains(errBuf.String()+out.String(), "hunter2") {
		t.Errorf("the refusal echoed the URL's userinfo:\n%s", errBuf.String())
	}
}

// TestCmdUpstreamRegister_HTTPAuthDerivation: with no -auth-kind, the one
// apiKey scheme of the document is derived -- and said so -- which makes
// the entry keyed, so -env is required; "none" refuses the derivation.
func TestCmdUpstreamRegister_HTTPAuthDerivation(t *testing.T) {
	spec := writeSpec(t, "openapi.json", restSpecJSON)
	base := []string{"register", "-name", "ioc", "-transport", "http", "-url", "https://api.example.com/v3", "-openapi", spec}

	t.Run("derived, with the secret named", func(t *testing.T) {
		configPath := httpTestConfig(t)
		var out, errBuf bytes.Buffer
		code := cmdUpstream(append(append([]string{}, base...), "-config", configPath, "-env", "IOC_API_KEY"), &out, &errBuf)
		requireExit(t, code, exitOK, "register with a derived descriptor")
		requireContains(t, out.String(), "DERIVED from the document's securitySchemes", "register output")
		requireContains(t, out.String(), "derived from securitySchemes.key", "register output carries the ingestion's warning")
		requireContains(t, out.String(), "header X-API-Key: <secret>", "register output")

		entry := storedEntry(t, configPath, "ioc")
		if entry.AuthKind != registry.AuthHeader || entry.AuthName != "X-API-Key" {
			t.Errorf("stored descriptor = %s %q, want header X-API-Key", entry.AuthKind, entry.AuthName)
		}
		// -url carried a base path of its own, so the document's was not
		// folded (ADR-0047 §6: the operator's URL is the authority).
		if entry.URL != "https://api.example.com/v3" {
			t.Errorf("stored url = %q, want the -url untouched", entry.URL)
		}
		if strings.Contains(out.String(), "folded into the url") {
			t.Errorf("register claims to have folded a base path into a -url that had one:\n%s", out.String())
		}
		requireContains(t, out.String(), `base path "/api/v2" is not folded in`, "the ingestion's warning reaches the operator")
	})

	t.Run("derived, without the secret, is refused and explained", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		code := cmdUpstream(base, &out, &errBuf)
		requireExit(t, code, exitCannotRun, "register keyed without -env")
		requireContains(t, errBuf.String(), "needs exactly one env var name", "the registry's rule")
		requireContains(t, errBuf.String(), `auth kind "header" name "X-API-Key" was derived`, "where the rule came from")
		requireContains(t, errBuf.String(), "-auth-kind none", "the way out")
	})

	t.Run("-auth-kind none registers keyless", func(t *testing.T) {
		configPath := httpTestConfig(t)
		var out, errBuf bytes.Buffer
		code := cmdUpstream(append(append([]string{}, base...), "-config", configPath, "-auth-kind", "none"), &out, &errBuf)
		requireExit(t, code, exitOK, "register keyless")
		requireContains(t, out.String(), "none (keyless)", "register output")
		requireContains(t, out.String(), "-auth-kind none: the document's security scheme was ignored", "register output")
		entry := storedEntry(t, configPath, "ioc")
		if entry.AuthKind != registry.AuthNone || entry.AuthName != "" || len(entry.EnvVarNames) != 0 {
			t.Errorf("stored descriptor = %s %q env %v, want keyless", entry.AuthKind, entry.AuthName, entry.EnvVarNames)
		}
		if err := dialTimeRefusal(entry); err != nil {
			t.Errorf("the keyless entry does not decode under its own descriptor: %v", err)
		}
	})

	// The common shape: an apiKey scheme AND a header parameter of the same
	// name. Keyless, nothing is injected, so the parameter is legal; the
	// ingestion must not validate the set under the descriptor "none"
	// refused, nor print that a credential is required.
	t.Run("-auth-kind none with a parameter on the scheme's slot", func(t *testing.T) {
		slotSpec := writeSpec(t, "slot.json", `{"openapi":"3.0.3","info":{"title":"t","version":"1"},
			"paths":{"/x":{"get":{"operationId":"x","parameters":[{"name":"X-API-Key","in":"header","schema":{"type":"string"}}],"responses":{}}}},
			"components":{"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-API-Key"}}}}`)
		configPath := httpTestConfig(t)
		var out, errBuf bytes.Buffer
		code := cmdUpstream([]string{"register", "-config", configPath, "-name", "pub", "-transport", "http",
			"-url", "https://api.example.com", "-openapi", slotSpec, "-auth-kind", "none"}, &out, &errBuf)
		requireExit(t, code, exitOK, "register keyless with a parameter on the scheme's slot")
		requireContains(t, out.String(), "-auth-kind none: the document's security scheme was ignored", "register output")
		for _, never := range []string{"-env) is required", "derived from securitySchemes", "DERIVED"} {
			if strings.Contains(out.String(), never) {
				t.Errorf("keyless register output claims %q:\n%s", never, out.String())
			}
		}
		entry := storedEntry(t, configPath, "pub")
		ops, err := gwrest.Decode(entry.Operations, string(entry.AuthKind), entry.AuthName)
		if err != nil || len(ops) != 1 || !strings.Contains(string(ops[0].InputSchema), "header_X-API-Key") {
			t.Errorf("stored set = %+v, %v; want x with its header_X-API-Key parameter", ops, err)
		}
	})
}

// TestCmdUpstreamRegister_HTTPReportEscapesTheDocument: the document chooses
// the text of Skipped lines (a media type key), Warnings (a security
// scheme's name) and refusals; none of it reaches the terminal as a raw
// control byte. An ESC[2J ESC[H after the tool table would clear the screen
// and let the line that follows stand in for the table the operator decides
// sensitivity from.
func TestCmdUpstreamRegister_HTTPReportEscapesTheDocument(t *testing.T) {
	const esc = `\u001b[2J\u001b[H`
	hostile := writeSpec(t, "hostile.json", `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{
		"/x":{"post":{"operationId":"x","requestBody":{"content":{"text/plain`+esc+`HIDDEN":{}}},"responses":{}}},
		"/y":{"get":{"operationId":"y","responses":{}}}},
		"components":{"securitySchemes":{"k`+esc+`LABEL":{"type":"apiKey","in":"header","name":"X-Key"}}}}`)
	configPath := httpTestConfig(t)
	var out, errBuf bytes.Buffer
	code := cmdUpstream([]string{"register", "-config", configPath, "-name", "h", "-transport", "http",
		"-url", "https://api.example.com", "-openapi", hostile, "-env", "H_KEY"}, &out, &errBuf)
	requireExit(t, code, exitOK, "register a document with escape sequences in its text")
	requireContains(t, out.String(), `text/plain\u{001B}[2J`, "the Skipped line, escaped")
	requireContains(t, out.String(), `securitySchemes.k\u{001B}[2J`, "the derivation warning, escaped")
	if strings.ContainsRune(out.String()+errBuf.String(), 0x1b) {
		t.Errorf("a raw ESC byte reached the terminal:\n%q", out.String()+errBuf.String())
	}

	refused := writeSpec(t, "refused.json", `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/y":{"get":{"operationId":"y","responses":{}}}},
		"components":{"securitySchemes":{"k`+esc+`":{"type":"apiKey","in":"header","name":"Bad Name"}}}}`)
	out.Reset()
	errBuf.Reset()
	code = cmdUpstream([]string{"register", "-name", "h", "-transport", "http", "-url", "https://api.example.com", "-openapi", refused, "-env", "H_KEY"}, &out, &errBuf)
	requireExit(t, code, exitCannotRun, "register a document whose derivation is refused")
	requireContains(t, errBuf.String(), "cannot derive", "the refusal")
	requireContains(t, errBuf.String(), `\u{001B}`, "the refusal, escaped")
	if strings.ContainsRune(out.String()+errBuf.String(), 0x1b) {
		t.Errorf("a raw ESC byte reached the terminal:\n%q", out.String()+errBuf.String())
	}
}

// TestCmdUpstreamRegister_HTTPRefusesTheEntryBeforeFetchingTheDocument: the
// registry's document-independent rules run before the one network read,
// so a bad -name or a keyed entry without -env is refused with the
// registry's words -- not with the fetch's (here the egress guard's
// loopback refusal, which would be the first thing reached otherwise) and
// without a "Fetched" line.
func TestCmdUpstreamRegister_HTTPRefusesTheEntryBeforeFetchingTheDocument(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(restSpecJSON))
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"name with the separator", []string{"-name", "a.b"}, "must not contain"},
		{"reserved name", []string{"-name", "gatte"}, "reserved"},
		{"keyed without -env", []string{"-name", "ioc", "-auth-kind", "bearer"}, `auth kind "bearer" needs exactly one env var name`},
		{"keyless with -env", []string{"-name", "ioc", "-auth-kind", "none", "-env", "K"}, "keyless"},
		{"two -env, descriptor still to derive", []string{"-name", "ioc", "-env", "A", "-env", "B"}, "got 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			args := append([]string{"register", "-transport", "http", "-url", "https://api.example.com", "-openapi", srv.URL + "/openapi.json"}, tc.args...)
			requireExit(t, cmdUpstream(args, &out, &errBuf), exitCannotRun, tc.name)
			requireContains(t, errBuf.String(), tc.want, tc.name)
			if strings.Contains(errBuf.String(), "loopback") || strings.Contains(errBuf.String(), "-openapi:") || strings.Contains(out.String(), "Fetched") {
				t.Errorf("%s: the document was read before the entry was refused:\n%s%s", tc.name, out.String(), errBuf.String())
			}
		})
	}
	if hits.Load() != 0 {
		t.Errorf("the document server was reached %d times", hits.Load())
	}
}

// TestCmdUpstreamRegister_HTTPRefusals drives the flag surface the way the
// invalid-entry table does: every refusal lands before a database is
// opened (no -config), names the rule, and registers nothing.
func TestCmdUpstreamRegister_HTTPRefusals(t *testing.T) {
	spec := writeSpec(t, "openapi.json", restSpecJSON)
	hostHeader := writeSpec(t, "host.json", `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{"/x":{"get":{"operationId":"x","parameters":[{"name":"Host","in":"header","schema":{"type":"string"}}],"responses":{}}}}}`)
	swagger := writeSpec(t, "swagger.json", `{"swagger":"2.0","info":{"title":"t","version":"1"},"paths":{}}`)
	garbage := writeSpec(t, "garbage.txt", "this is not a document: [")
	tooBig := writeSpec(t, "big.json", strings.Repeat(" ", gwrest.MaxDocumentBytes+1))

	http := func(extra ...string) []string {
		return append([]string{"register", "-name", "ioc", "-transport", "http"}, extra...)
	}
	tests := []struct {
		name    string
		args    []string
		want    []string
		notWant string
	}{
		{
			name: "-openapi on a stdio entry",
			args: []string{"register", "-name", "ioc", "-transport", "stdio", "-command", "x", "-openapi", spec},
			want: []string{"-openapi applies to -transport http only", "stdio"},
		},
		{
			name: "-auth-kind and -auth-name on an oci entry",
			args: []string{"register", "-name", "ioc", "-transport", "oci", "-image", ociTestImage, "-auth-kind", "header", "-auth-name", "X"},
			want: []string{"-auth-kind, -auth-name apply to -transport http only"},
		},
		{
			// The pre-existing refusals keep their words; the -openapi hint
			// is added to them.
			name: "http without -url nor -openapi",
			args: http(),
			want: []string{"url must not be empty for http transport", "-openapi FILE|URL is required"},
		},
		{
			name: "http with -url but no -openapi",
			args: http("-url", "https://api.example.com"),
			want: []string{"requires a non-empty operation set", "-openapi FILE|URL is required"},
		},
		{
			name: "http with -openapi but no -url",
			args: http("-openapi", spec),
			want: []string{"-url:", "url is empty"},
		},
		{
			name: "-url the adapter refuses (a literal loopback host)",
			args: http("-url", "http://127.0.0.1:8080/", "-openapi", spec),
			want: []string{"-url:", "loopback"},
		},
		{
			name: "unknown -auth-kind",
			args: http("-url", "https://api.example.com", "-openapi", spec, "-auth-kind", "basic", "-env", "K"),
			want: []string{`-auth-kind "basic" is not one of`},
		},
		{
			name: "-auth-name without a kind",
			args: http("-url", "https://api.example.com", "-openapi", spec, "-auth-name", "X-API-Key"),
			want: []string{"-auth-name applies to -auth-kind"},
		},
		{
			name: "-auth-name with bearer",
			args: http("-url", "https://api.example.com", "-openapi", spec, "-auth-kind", "bearer", "-auth-name", "X", "-env", "K"),
			want: []string{"-auth-name applies to -auth-kind"},
		},
		{
			name: "keyed without -env",
			args: http("-url", "https://api.example.com", "-openapi", spec, "-auth-kind", "bearer"),
			want: []string{`auth kind "bearer" needs exactly one env var name`},
		},
		{
			name: "keyed with two -env",
			args: http("-url", "https://api.example.com", "-openapi", spec, "-auth-kind", "bearer", "-env", "A", "-env", "B"),
			want: []string{"needs exactly one env var name", "got 2"},
		},
		{
			name: "document that is neither JSON nor YAML",
			args: http("-url", "https://api.example.com", "-openapi", garbage, "-auth-kind", "none"),
			want: []string{`refusing to register "ioc"`, "invalid openapi document"},
		},
		{
			name: "Swagger 2.0",
			args: http("-url", "https://api.example.com", "-openapi", swagger, "-auth-kind", "none"),
			want: []string{"Swagger 2.0", "convert it first"},
		},
		{
			name: "document over the byte ceiling",
			args: http("-url", "https://api.example.com", "-openapi", tooBig, "-auth-kind", "none"),
			want: []string{"over the", "limit"},
		},
		{
			name: "document file that does not exist",
			args: http("-url", "https://api.example.com", "-openapi", filepath.Join(t.TempDir(), "missing.json"), "-auth-kind", "none"),
			want: []string{"-openapi:", "missing.json"},
		},
		{
			// A control header in the spec is a header injection in the
			// signed set (ADR-0048 Decisão 6); refused naming the operation
			// and the parameter.
			name: "document declaring a Host header parameter",
			args: http("-url", "https://api.example.com", "-openapi", hostHeader, "-auth-kind", "none"),
			want: []string{"GET /x", `"header_Host"`, "control header"},
		},
		// A parameter on the credential's slot is no longer a refusal: it is
		// dropped with a warning (resthttp
		// TestIngest_AParameterOnTheAuthSlotIsDroppedNotServed).
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := cmdUpstream(tc.args, &out, &errBuf)
			requireExit(t, code, exitCannotRun, tc.name)
			for _, want := range tc.want {
				requireContains(t, errBuf.String(), want, tc.name)
			}
			if tc.notWant != "" && strings.Contains(errBuf.String(), tc.notWant) {
				t.Errorf("%s: stderr contains %q\n%s", tc.name, tc.notWant, errBuf.String())
			}
		})
	}
}

// TestRunUpstreamRegister_HTTPSignatureCoversTheOperationSet: the entry
// register writes signs under canonical/v3-http, `sign` shows the
// descriptor and the set's digest it attests to, and a set that differs by
// one byte no longer verifies -- the whole reason the digest is signed
// (ADR-0048 Decisão 2).
func TestRunUpstreamRegister_HTTPSignatureCoversTheOperationSet(t *testing.T) {
	res, err := gwrest.Ingest([]byte(restSpecJSON), gwrest.IngestOptions{AuthKind: gwrest.AuthHeader, AuthName: "X-API-Key", BaseURL: "https://api.example.com"})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	entry := registry.UpstreamServer{
		Name: "ioc", Transport: registry.TransportHTTP, URL: res.BaseURL,
		AuthKind: registry.AuthKind(res.AuthKind), AuthName: res.AuthName,
		Operations: res.Operations, EnvVarNames: []string{"IOC_API_KEY"},
	}

	e := newOpTestEnv(t)
	useSigningKey(t, e)
	requireExit(t, runUpstreamRegister(e.opEnv, entry), exitOK, "register")
	e.out.Reset()
	requireExit(t, runSign(e.opEnv, "ioc"), exitOK, "sign")
	for _, want := range []string{"https://api.example.com/api/v2", "header X-API-Key: <secret>", "2 operations, sha256"} {
		requireContains(t, e.stdoutText(), want, "sign shows what v3-http covers")
	}

	stored, err := e.upstreams().Get(context.Background(), "ioc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if state, err := entrySignatureState(e.opEnv, stored); err != nil || state != sigValid {
		t.Fatalf("signature state = %v, %v; want valid", state, err)
	}

	// The same entry with a different set: a tool repointed at another
	// path, as a direct database write could do it.
	other, err := gwrest.Encode([]gwrest.Operation{{Name: "check_ip", Method: "GET", Path: "/other/{ip}",
		InputSchema: []byte(`{"type":"object","properties":{"path_ip":{"type":"string"}},"required":["path_ip"]}`)}})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	altered := stored
	altered.Operations = other
	if bytes.Equal(signer.Canonical(stored), signer.Canonical(altered)) {
		t.Fatal("the canonical form does not change with the operation set")
	}
	if state, err := entrySignatureState(e.opEnv, altered); err != nil || state != sigInvalid {
		t.Errorf("signature state of the altered set = %v, %v; want invalid", state, err)
	}
	// And with a different descriptor: the injection location is attested.
	moved := stored
	moved.AuthKind, moved.AuthName = registry.AuthQuery, "key"
	if state, err := entrySignatureState(e.opEnv, moved); err != nil || state != sigInvalid {
		t.Errorf("signature state of the moved descriptor = %v, %v; want invalid", state, err)
	}
}
