package resthttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// These tests touch no network. They pin the operation model: what a
// signed operation set may say, what it may not, and that its canonical
// bytes are stable -- because those bytes are what the signer digests
// (ADR-0048 Decisão 2) and what the quarantine fingerprints.

func raw(s string) json.RawMessage { return json.RawMessage(s) }

// good is a set that passes Validate under a header credential named
// X-API-Key: one safe GET with a parameter in every location, one
// sensitive POST with a body.
func good() []Operation {
	return []Operation{
		{
			Name:        "check",
			Description: "Look an IP up",
			Method:      "GET",
			Path:        "/check/{ip}",
			InputSchema: raw(`{"type":"object","properties":{"path_ip":{"type":"string"},"query_maxAgeInDays":{"type":"integer"},"header_Accept":{"type":"string"},"cookie_session":{"type":"string"}},"required":["path_ip"]}`),
		},
		{
			Name:         "report",
			Description:  "File a report <careful>",
			Method:       "POST",
			Path:         "/report",
			InputSchema:  raw(`{"type":"object","properties":{"body":{"type":"object","properties":{"ip":{"type":"string"},"categories":{"type":"array","items":{"type":"integer"}}}}}}`),
			OutputSchema: raw(`{"type":"object","properties":{"id":{"type":"string"}}}`),
		},
	}
}

func mustEncode(t *testing.T, ops []Operation) []byte {
	t.Helper()
	b, err := Encode(ops)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return b
}

func TestDecode_AcceptsAWellFormedSet(t *testing.T) {
	ops, err := Decode(mustEncode(t, good()), AuthHeader, "X-API-Key")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(ops) != 2 || ops[0].Name != "check" || ops[1].Name != "report" {
		t.Fatalf("got %+v", ops)
	}
	if ops[1].OutputSchema == nil || ops[0].OutputSchema != nil {
		t.Errorf("output schema: want only on report; got check=%s report=%s", ops[0].OutputSchema, ops[1].OutputSchema)
	}
	// Schemas come back canonical whatever the stored formatting.
	if want := `{"properties":{"cookie_session":{"type":"string"},"header_Accept":{"type":"string"},"path_ip":{"type":"string"},"query_maxAgeInDays":{"type":"integer"}},"required":["path_ip"],"type":"object"}`; string(ops[0].InputSchema) != want {
		t.Errorf("input schema not canonical:\n got %s\nwant %s", ops[0].InputSchema, want)
	}
}

func TestDecode_ToleratesFormattingButNotUnknownKeys(t *testing.T) {
	pretty := `[
	  {
	    "name": "check",
	    "method": "GET",
	    "path": "/check",
	    "inputSchema": { "type" : "object" }
	  }
	]`
	ops, err := Decode([]byte(pretty), AuthNone, "")
	if err != nil {
		t.Fatalf("pretty-printed set refused: %v", err)
	}
	if string(ops[0].InputSchema) != `{"type":"object"}` {
		t.Errorf("schema not canonicalized: %s", ops[0].InputSchema)
	}

	// A key this version does not know would be dropped on re-encode, and
	// the served set would no longer be the signed set.
	unknown := `[{"name":"check","method":"GET","path":"/check","inputSchema":{"type":"object"},"class":"safe"}]`
	if _, err := Decode([]byte(unknown), AuthNone, ""); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("unknown key accepted: %v", err)
	}
}

func TestDecode_RequiresAscendingOrderByName(t *testing.T) {
	ops := good()
	ops[0], ops[1] = ops[1], ops[0] // report before check
	b, err := json.Marshal(ops)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(b, AuthHeader, "X-API-Key")
	if !errors.Is(err, ErrInvalidOperations) || !strings.Contains(err.Error(), "not ordered") {
		t.Errorf("unordered set: got %v", err)
	}
}

// TestValidate_RefusesEachListedFault is the table ADR-0048 Decisão 6 asks
// for: every way a spec could smuggle a destination, a header or a
// credential slot into signed bytes, refused one by one.
func TestValidate_RefusesEachListedFault(t *testing.T) {
	type tc struct {
		name     string
		mutate   func(ops []Operation)
		authKind string
		authName string
		keyless  bool   // use AuthNone instead of the fixture's header credential
		want     string // substring of the error
	}
	withSchema := func(schema string) func([]Operation) {
		return func(ops []Operation) { ops[0].InputSchema = raw(schema) }
	}
	withPath := func(path string) func([]Operation) {
		return func(ops []Operation) { ops[0].Path = path }
	}
	simple := raw(`{"type":"object"}`)
	cases := []tc{
		// Path: the destination must stay the signed base.
		{name: "path with scheme", mutate: withPath("https://evil.tld/x"), want: "exactly one"},
		{name: "path with authority", mutate: withPath("//evil.tld/x"), want: "//"},
		{name: "path with double slash inside", mutate: withPath("/a//b"), want: "//"},
		{name: "path relative", mutate: withPath("check"), want: "exactly one"},
		{name: "path with ../", mutate: withPath("/a/../b"), want: "dot segment"},
		{name: "path ending in ..", mutate: withPath("/a/.."), want: "dot segment"},
		{name: "path with . segment", mutate: withPath("/a/./b"), want: "dot segment"},
		// Servlet containers strip ";params" before normalising, so "..;"
		// is ".." to Tomcat and Jetty.
		{name: "path with ..; segment", mutate: withPath("/api/..;/admin"), want: "dot segment"},
		{name: "path with ..;x segment", mutate: withPath("/x/..;y/"), want: "dot segment"},
		{name: "path with .; segment", mutate: withPath("/x/.;/y"), want: "dot segment"},
		{name: "path with CRLF", mutate: withPath("/a\r\nHost: evil"), want: "outside the characters"},
		{name: "path with space", mutate: withPath("/a b"), want: "outside the characters"},
		{name: "path with control byte", mutate: withPath("/a\x00b"), want: "outside the characters"},
		{name: "path with query", mutate: withPath("/a?x=1"), want: "query and fragment"},
		{name: "path with fragment", mutate: withPath("/a#frag"), want: "query and fragment"},
		{name: "path with percent escape", mutate: withPath("/a%2Fb"), want: "percent-escape"},
		{name: "path non-ASCII", mutate: withPath("/café"), want: "outside the characters"},
		{name: "path unterminated template", mutate: withPath("/a/{id"), want: "unterminated"},
		{name: "path nested template", mutate: withPath("/a/{{id}}"), want: "nested"},
		{name: "path stray close brace", mutate: withPath("/a/id}"), want: "without a template"},
		{name: "path empty template", mutate: withPath("/a/{}"), want: "template name"},
		{name: "path repeated template", mutate: func(ops []Operation) {
			ops[0].Path = "/a/{id}/{id}"
			ops[0].InputSchema = raw(`{"type":"object","properties":{"path_id":{"type":"string"}}}`)
		}, want: "twice"},
		{name: "path empty", mutate: withPath(""), want: "must not be empty"},
		{name: "path too long", mutate: withPath("/" + strings.Repeat("a", maxPathLen)), want: "limit"},

		// Name and method.
		{name: "duplicate name", mutate: func(ops []Operation) { ops[1].Name = ops[0].Name }, want: "twice"},
		{name: "invalid name (dot)", mutate: func(ops []Operation) { ops[0].Name = "a.b" }, want: "not a legal tool name"},
		{name: "invalid name (empty)", mutate: func(ops []Operation) { ops[0].Name = "" }, want: "not a legal tool name"},
		{name: "invalid name (too long)", mutate: func(ops []Operation) { ops[0].Name = strings.Repeat("a", 65) }, want: "not a legal tool name"},
		{name: "unknown method", mutate: func(ops []Operation) { ops[0].Method = "TRACE" }, want: "method"},
		{name: "lower-case method", mutate: func(ops []Operation) { ops[0].Method = "get" }, want: "method"},
		{name: "empty method", mutate: func(ops []Operation) { ops[0].Method = "" }, want: "method"},

		// Schema shape.
		{name: "schema missing", mutate: withSchema(""), want: "is missing"},
		{name: "schema not JSON", mutate: withSchema("{"), want: "not valid JSON"},
		{name: "schema not an object", mutate: withSchema(`[]`), want: "must be a JSON object"},
		{name: "schema without type=object", mutate: withSchema(`{"properties":{}}`), want: `"type":"object"`},
		{name: "schema with type array", mutate: withSchema(`{"type":"array"}`), want: `"type":"object"`},
		{name: "schema with type list", mutate: withSchema(`{"type":["object","null"]}`), want: `"type":"object"`},
		{name: "schema properties not object", mutate: withSchema(`{"type":"object","properties":[]}`), want: "must be an object"},
		{name: "schema property not a schema", mutate: withSchema(`{"type":"object","properties":{"query_x":true}}`), want: "schema object"},
		{name: "schema required names undeclared", mutate: withSchema(`{"type":"object","required":["query_x"]}`), want: "not a declared property"},
		{name: "schema trailing data", mutate: withSchema(`{"type":"object"} {}`), want: "trailing"},
		{name: "output schema not object", mutate: func(ops []Operation) { ops[0].OutputSchema = raw(`"x"`) }, want: "output schema"},

		// Location vocabulary.
		{name: "key outside prefixes", mutate: withSchema(`{"type":"object","properties":{"ip":{"type":"string"}}}`), want: "location vocabulary"},
		{name: "body_ family is not a location", mutate: withSchema(`{"type":"object","properties":{"body_ip":{"type":"string"}}}`), want: "location vocabulary"},
		{name: "empty path suffix", mutate: withSchema(`{"type":"object","properties":{"path_":{"type":"string"}}}`), want: "empty parameter name"},
		{name: "empty query suffix", mutate: withSchema(`{"type":"object","properties":{"query_":{"type":"string"}}}`), want: "empty parameter name"},
		{name: "query name with space", mutate: withSchema(`{"type":"object","properties":{"query_a b":{"type":"string"}}}`), want: "printable ASCII"},
		{name: "query name with CRLF", mutate: withSchema(`{"type":"object","properties":{"query_a\r\nb":{"type":"string"}}}`), want: "printable ASCII"},
		{name: "body on GET", mutate: withSchema(`{"type":"object","properties":{"body":{"type":"object"}}}`), want: "safe method"},

		// Path template <-> path_* must agree both ways.
		{name: "path_ without template", mutate: func(ops []Operation) {
			ops[0].Path = "/check"
			ops[0].InputSchema = raw(`{"type":"object","properties":{"path_ip":{"type":"string"}}}`)
		}, want: "has no {ip} template"},
		{name: "template without path_", mutate: func(ops []Operation) {
			ops[0].Path = "/check/{ip}"
			ops[0].InputSchema = simple
		}, want: "has no path_ip property"},

		// Header denylist and token grammar.
		{name: "header_host", mutate: withSchema(`{"type":"object","properties":{"header_Host":{"type":"string"}}}`), want: "control header"},
		{name: "header_content-length", mutate: withSchema(`{"type":"object","properties":{"header_content-length":{"type":"string"}}}`), want: "control header"},
		{name: "header_transfer-encoding", mutate: withSchema(`{"type":"object","properties":{"header_Transfer-Encoding":{"type":"string"}}}`), want: "control header"},
		{name: "header_connection", mutate: withSchema(`{"type":"object","properties":{"header_Connection":{"type":"string"}}}`), want: "control header"},
		{name: "header_upgrade", mutate: withSchema(`{"type":"object","properties":{"header_Upgrade":{"type":"string"}}}`), want: "control header"},
		{name: "header_te", mutate: withSchema(`{"type":"object","properties":{"header_TE":{"type":"string"}}}`), want: "control header"},
		{name: "header_trailer", mutate: withSchema(`{"type":"object","properties":{"header_Trailer":{"type":"string"}}}`), want: "control header"},
		{name: "header_keep-alive", mutate: withSchema(`{"type":"object","properties":{"header_Keep-Alive":{"type":"string"}}}`), want: "control header"},
		{name: "header_proxy-authorization", mutate: withSchema(`{"type":"object","properties":{"header_Proxy-Authorization":{"type":"string"}}}`), want: "control header"},
		{name: "header_cookie", mutate: withSchema(`{"type":"object","properties":{"header_Cookie":{"type":"string"}}}`), want: "control header"},
		{name: "header_authorization on a keyless entry", mutate: withSchema(`{"type":"object","properties":{"header_authorization":{"type":"string"}}}`), keyless: true, want: "control header"},
		{name: "header_Authorization on a bearer entry", mutate: withSchema(`{"type":"object","properties":{"header_Authorization":{"type":"string"}}}`), authKind: AuthBearer, want: "control header"},
		{name: "header with CRLF", mutate: withSchema(`{"type":"object","properties":{"header_X\r\nEvil":{"type":"string"}}}`), want: "HTTP token"},
		{name: "header with space", mutate: withSchema(`{"type":"object","properties":{"header_X Evil":{"type":"string"}}}`), want: "HTTP token"},
		{name: "header empty", mutate: withSchema(`{"type":"object","properties":{"header_":{"type":"string"}}}`), want: "HTTP token"},
		{name: "header repeated across case", mutate: withSchema(`{"type":"object","properties":{"header_X-Foo":{"type":"string"},"header_x-foo":{"type":"string"}}}`), want: "repeats the header"},
		// "_" and "-" collapse to the same CGI variable (HTTP_X_FOO), so a
		// control header or a duplicate spelled with "_" is the same header.
		{name: "header_transfer_encoding (underscore)", mutate: withSchema(`{"type":"object","properties":{"header_transfer_encoding":{"type":"string"}}}`), want: "control header"},
		{name: "header_proxy_authorization (underscore)", mutate: withSchema(`{"type":"object","properties":{"header_Proxy_Authorization":{"type":"string"}}}`), want: "control header"},
		{name: "header repeated across underscore", mutate: withSchema(`{"type":"object","properties":{"header_X-Foo":{"type":"string"},"header_x_foo":{"type":"string"}}}`), want: "repeats the header"},

		// The auth slot is reserved case-insensitively, server-wins, and
		// with "_" read as "-" (foldHeader).
		{name: "header_<AuthName> in another case", mutate: withSchema(`{"type":"object","properties":{"header_x-api-key":{"type":"string"}}}`), authKind: AuthHeader, authName: "X-API-Key", want: "credential is injected"},
		{name: "header_<AuthName> exact", mutate: withSchema(`{"type":"object","properties":{"header_X-API-Key":{"type":"string"}}}`), authKind: AuthHeader, authName: "X-API-Key", want: "credential is injected"},
		{name: "header_<AuthName> with underscores", mutate: withSchema(`{"type":"object","properties":{"header_x_api_key":{"type":"string"}}}`), authKind: AuthHeader, authName: "X-API-Key", want: "credential is injected"},
		{name: "header_<AuthName> when the auth name has underscores", mutate: withSchema(`{"type":"object","properties":{"header_X-Api-Key":{"type":"string"}}}`), authKind: AuthHeader, authName: "X_API_KEY", want: "credential is injected"},
		{name: "query_<AuthName> exact", mutate: withSchema(`{"type":"object","properties":{"query_key":{"type":"string"}}}`), authKind: AuthQuery, authName: "key", want: "credential is injected"},
		{name: "query_<AuthName> in another case", mutate: withSchema(`{"type":"object","properties":{"query_KEY":{"type":"string"}}}`), authKind: AuthQuery, authName: "key", want: "credential is injected"},

		// Cookies.
		{name: "cookie with semicolon", mutate: withSchema(`{"type":"object","properties":{"cookie_a;b":{"type":"string"}}}`), want: "HTTP token"},
		{name: "cookie with equals", mutate: withSchema(`{"type":"object","properties":{"cookie_a=b":{"type":"string"}}}`), want: "HTTP token"},
		{name: "cookie empty", mutate: withSchema(`{"type":"object","properties":{"cookie_":{"type":"string"}}}`), want: "HTTP token"},
		{name: "cookie repeated across case", mutate: withSchema(`{"type":"object","properties":{"cookie_S":{"type":"string"},"cookie_s":{"type":"string"}}}`), want: "repeats the cookie"},

		// The descriptor itself, since every slot rule reads it.
		{name: "unknown auth kind", mutate: func([]Operation) {}, authKind: "basic", authName: "", want: "auth kind"},
		{name: "bearer with a name", mutate: func([]Operation) {}, authKind: AuthBearer, authName: "X", want: "must be empty"},
		{name: "header without a name", mutate: func([]Operation) {}, authKind: AuthHeader, authName: "", want: "auth name"},
		{name: "keyless with a name", mutate: func([]Operation) {}, keyless: true, authName: "X", want: "keyless"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ops := good()
			// Default descriptor: the header credential the fixture is
			// written against. Cases that test the slot set their own.
			kind, name := AuthHeader, "X-API-Key"
			if c.keyless || c.authKind != "" {
				kind, name = c.authKind, c.authName
			}
			c.mutate(ops)
			err := Validate(ops, kind, name)
			if err == nil {
				t.Fatalf("accepted; wanted an error containing %q", c.want)
			}
			if !errors.Is(err, ErrInvalidOperations) {
				t.Errorf("error does not wrap ErrInvalidOperations: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err, c.want)
			}
			// Decode must refuse exactly what Validate refuses: the
			// console and the dialer must agree. Unencodable mutations
			// (an empty or invalid schema) cannot reach Decode; skip them.
			if b, encErr := Encode(ops); encErr == nil {
				if _, decErr := Decode(b, kind, name); !errors.Is(decErr, ErrInvalidOperations) {
					t.Errorf("Validate refused but Decode accepted: %v", decErr)
				}
			}
		})
	}
}

func TestValidate_AcceptsWhatTheRulesAllow(t *testing.T) {
	cases := []struct {
		name     string
		ops      []Operation
		authKind string
		authName string
	}{
		{name: "fixture under header auth", ops: good(), authKind: AuthHeader, authName: "X-API-Key"},
		{name: "fixture under bearer", ops: good(), authKind: AuthBearer},
		{name: "fixture under query auth", ops: good(), authKind: AuthQuery, authName: "key"},
		{name: "fixture keyless", ops: good()},
		{name: "no properties at all", ops: []Operation{{Name: "ping", Method: "GET", Path: "/", InputSchema: raw(`{"type":"object"}`)}}},
		{name: "trailing slash and dotted literal", ops: []Operation{{Name: "list", Method: "GET", Path: "/v2/items.json/", InputSchema: raw(`{"type":"object"}`)}}},
		{name: "template with extension", ops: []Operation{{Name: "get", Method: "GET", Path: "/files/{id}.json", InputSchema: raw(`{"type":"object","properties":{"path_id":{"type":"string"}}}`)}}},
		{name: "sub-delims in a literal", ops: []Operation{{Name: "odd", Method: "DELETE", Path: "/a:b@c/(d)*e,f;g=h!$&'+", InputSchema: raw(`{"type":"object"}`)}}},
		{name: "a header that is not reserved under a different kind", ops: []Operation{{Name: "k", Method: "GET", Path: "/k", InputSchema: raw(`{"type":"object","properties":{"header_X-API-Key":{"type":"string"}}}`)}}, authKind: AuthQuery, authName: "X-API-Key"},
		{name: "query name with brackets", ops: []Operation{{Name: "q", Method: "GET", Path: "/q", InputSchema: raw(`{"type":"object","properties":{"query_filter[name]":{"type":"string"}}}`)}}},
		{name: "body on every non-safe method", ops: []Operation{
			{Name: "a", Method: "DELETE", Path: "/a", InputSchema: raw(`{"type":"object","properties":{"body":{"type":"string"}}}`)},
			{Name: "b", Method: "PATCH", Path: "/b", InputSchema: raw(`{"type":"object","properties":{"body":{"type":"string"}}}`)},
			{Name: "c", Method: "POST", Path: "/c", InputSchema: raw(`{"type":"object","properties":{"body":{"type":"string"}}}`)},
			{Name: "d", Method: "PUT", Path: "/d", InputSchema: raw(`{"type":"object","properties":{"body":{"type":"string"}}}`)},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Validate(c.ops, c.authKind, c.authName); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if _, err := Decode(mustEncode(t, c.ops), c.authKind, c.authName); err != nil {
				t.Fatalf("Decode refused what Validate accepted: %v", err)
			}
		})
	}
}

func TestValidate_RefusesAnEmptySet(t *testing.T) {
	if err := Validate(nil, AuthNone, ""); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("empty set: %v", err)
	}
	if _, err := Decode([]byte(`[]`), AuthNone, ""); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("empty array: %v", err)
	}
	if _, err := Decode([]byte(`{}`), AuthNone, ""); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("not an array: %v", err)
	}
}

// TestRoundTrip_EncodeDecodeEncodeIsStable is the property the signature
// rests on: the bytes Encode produces decode to a set that encodes to the
// same bytes, and formatting of the input does not change them.
func TestRoundTrip_EncodeDecodeEncodeIsStable(t *testing.T) {
	// Unsorted input, pretty schemas, keys out of order, HTML characters,
	// a number spelled with an exponent: everything canonicalization has
	// to fold.
	in := []Operation{
		{Name: "zeta", Method: "POST", Path: "/z", Description: "a <b> & c",
			InputSchema: raw("{ \"properties\" : { \"body\" : { \"type\":\"number\", \"maximum\": 1e3, \"minimum\": 0.50 } }, \"type\" : \"object\" }")},
		{Name: "alpha", Method: "GET", Path: "/a/{id}",
			InputSchema:  raw(`{"type":"object","required":["path_id"],"properties":{"query_b":{"type":"string"},"path_id":{"type":"string"}}}`),
			OutputSchema: raw(`{"type":"object", "properties": {"z":{"type":"string"},"a":{"type":"string"}}}`)},
	}
	first, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	ops, err := Decode(first, AuthBearer, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	second, err := Encode(ops)
	if err != nil {
		t.Fatalf("Encode again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("encode->decode->encode is not stable:\n first %s\nsecond %s", first, second)
	}

	want := `[{"inputSchema":{"properties":{"path_id":{"type":"string"},"query_b":{"type":"string"}},"required":["path_id"],"type":"object"},"method":"GET","name":"alpha","outputSchema":{"properties":{"a":{"type":"string"},"z":{"type":"string"}},"type":"object"},"path":"/a/{id}"},{"description":"a <b> & c","inputSchema":{"properties":{"body":{"maximum":1e3,"minimum":0.50,"type":"number"}},"type":"object"},"method":"POST","name":"zeta","path":"/z"}]`
	if string(first) != want {
		t.Errorf("canonical form drifted:\n got %s\nwant %s", first, want)
	}

	// Decoding a differently formatted spelling of the same set yields the
	// same canonical bytes.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, first, "", "  "); err != nil {
		t.Fatal(err)
	}
	ops2, err := Decode(pretty.Bytes(), AuthBearer, "")
	if err != nil {
		t.Fatalf("Decode pretty: %v", err)
	}
	third, err := Encode(ops2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, third) {
		t.Errorf("formatting changed the canonical bytes:\n first %s\n third %s", first, third)
	}
}

func TestEncode_RefusesDuplicateNamesAndBadSchemas(t *testing.T) {
	ops := good()
	ops[1].Name = ops[0].Name
	if _, err := Encode(ops); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("duplicate names: %v", err)
	}
	ops = good()
	ops[0].InputSchema = raw(`{`)
	if _, err := Encode(ops); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("bad schema: %v", err)
	}
	ops = good()
	ops[0].OutputSchema = raw(`nope`)
	if _, err := Encode(ops); !errors.Is(err, ErrInvalidOperations) {
		t.Errorf("bad output schema: %v", err)
	}
	// Encode does not reorder the caller's slice.
	ops = good()
	ops[0], ops[1] = ops[1], ops[0]
	mustEncode(t, ops)
	if ops[0].Name != "report" {
		t.Errorf("Encode reordered the caller's slice")
	}
}

// TestClassOf_IsTheOneSourceOfTheMethodRule pins ADR-0048 Decisão 5's
// derivation and that ToolDef carries it OUTSIDE the fingerprint fields.
func TestClassOf_IsTheOneSourceOfTheMethodRule(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS"} {
		if ClassOf(m) != quarantine.ClassSafe {
			t.Errorf("%s: want safe", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT", "get", "", "PROPFIND"} {
		if ClassOf(m) != quarantine.ClassSensitive {
			t.Errorf("%q: want sensitive (fail closed)", m)
		}
	}

	ops, err := Decode(mustEncode(t, good()), AuthHeader, "X-API-Key")
	if err != nil {
		t.Fatal(err)
	}
	get, post := ops[0].ToolDef(), ops[1].ToolDef()
	if get.SecurityClass != quarantine.ClassSafe || post.SecurityClass != quarantine.ClassSensitive {
		t.Errorf("ToolDef classes: GET=%q POST=%q", get.SecurityClass, post.SecurityClass)
	}
	if get.Name != "check" || get.Description != "Look an IP up" || !bytes.Equal(get.InputSchema, ops[0].InputSchema) || get.OutputSchema != nil {
		t.Errorf("ToolDef fields: %+v", get)
	}
	if !bytes.Equal(post.OutputSchema, ops[1].OutputSchema) {
		t.Errorf("ToolDef output schema: %s", post.OutputSchema)
	}
}

func TestPredicates(t *testing.T) {
	for _, h := range []string{"Host", "host", "HOST", "Proxy-Connection", "proxy-authorization", "TE", "Authorization", "Cookie",
		"Transfer_Encoding", "content_length", "Proxy_Authorization", "keep_alive"} {
		if !IsControlHeader(h) {
			t.Errorf("%q should be a control header", h)
		}
	}
	for _, h := range []string{"X-API-Key", "Accept", "Content-Type", "Proxy", "Cookie2", "X_Forwarded_For"} {
		if IsControlHeader(h) {
			t.Errorf("%q should not be a control header", h)
		}
	}
	for _, tok := range []string{"X-API-Key", "a", "!#$%&'*+-.^_`|~"} {
		if !ValidToken(tok) {
			t.Errorf("%q should be a token", tok)
		}
	}
	for _, tok := range []string{"", "a b", "a:b", "a\r\nb", "ação", "a;b", "a=b", "a\"b"} {
		if ValidToken(tok) {
			t.Errorf("%q should not be a token", tok)
		}
	}
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} {
		if !ValidMethod(m) {
			t.Errorf("%s should be valid", m)
		}
	}
	for _, m := range []string{"TRACE", "CONNECT", "get", "", "PROPFIND"} {
		if ValidMethod(m) {
			t.Errorf("%q should not be valid", m)
		}
	}
	names, err := ParsePath("/a/{x}/b/{y.z}/c")
	if err != nil || len(names) != 2 || names[0] != "x" || names[1] != "y.z" {
		t.Errorf("ParsePath: %v %v", names, err)
	}
}

// TestAuthKindsMatchTheRegistry pins the copied vocabulary to its source
// (internal/registry/registry.go:76-90): the adapter reads the kind as a
// string off gateway.UpstreamSpec, so a respelling on either side would
// silently turn every keyed entry into an "unknown auth kind" refusal.
func TestAuthKindsMatchTheRegistry(t *testing.T) {
	pairs := []struct {
		here  string
		there registry.AuthKind
	}{
		{AuthNone, registry.AuthNone},
		{AuthBearer, registry.AuthBearer},
		{AuthHeader, registry.AuthHeader},
		{AuthQuery, registry.AuthQuery},
	}
	for _, p := range pairs {
		if p.here != string(p.there) {
			t.Errorf("auth kind %q here, %q in the registry", p.here, p.there)
		}
	}
}
