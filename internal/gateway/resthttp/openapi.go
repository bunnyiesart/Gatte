package resthttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mime"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// This file is step 4 of ADR-0048's implementation order: the OpenAPI
// ingestion of ADR-0047 §3, which turns an OpenAPI 3.0.x/3.1.x document into
// the frozen operation set an http entry stores and signs
// (registry.UpstreamServer.Operations). It lives in this package rather than
// in a subpackage so that there is exactly ONE producer of Operation and one
// set of rules about what an operation may say: the parser builds Operation
// values and hands them to Validate/Encode/Decode of operation.go, the same
// functions the dialer runs, and never writes bytes those functions did not
// see. A subpackage would have had to export decodeObject, canonicalize and
// reservedSlots for the parser's benefit and would have nothing to offer in
// return, since nothing but this ingestion will ever parse OpenAPI.
//
// The document is third-party text at every edge (ADR-0048 Decisão 6,
// Consequências). Nothing read from it becomes a destination, a header name
// or a tool name without passing through ParsePath, Validate (token grammar,
// control-header denylist, reserved auth slot) and gateway.ValidToolName --
// which is why every refusal below either comes from those functions or
// precedes them. The parser is deliberately minimal and fail-closed: it reads
// what it can translate and refuses, by name, what it cannot; it does not try
// to be a complete OpenAPI implementation, and go.mod gains no OpenAPI
// library for it (AGENTS.md: the four backends need one gateway, not a
// framework).
//
// Decisions this file takes that ADR-0047 §3 / ADR-0048 Decisão 4 and 6 left
// to the implementation, each marked "Decision:" where it is applied:
//
//   - servers[]: the operator's -url is the authority for scheme, host and
//     port; only the PATH of servers[0].url is read, and it is folded into
//     the registered URL only when that URL carries no base path of its own.
//     A different host in servers[] is ignored with a warning; a server
//     variable ({region}) is refused rather than defaulted; servers beyond
//     the first, and path- or operation-level servers, are ignored with a
//     warning.
//   - requestBody and parameter `content`: application/json or any +json
//     media type only. An operation whose body (or whose parameter content)
//     has no JSON media type is SKIPPED and reported, not fatal: a spec with
//     one multipart upload among fifty JSON operations is the common case,
//     and the operator sees the skip in the register output. A GET, HEAD
//     or OPTIONS with a requestBody is skipped the same way (the adapter
//     sends no body on a safe method).
//   - paths: x-* keys of the Paths Object are vendor extensions, reported as
//     warnings; TRACE and CONNECT are skipped.
//   - $ref: local JSON pointers (#/...) only; a remote or URL reference is
//     refused. Siblings of a $ref are dropped (OpenAPI 3.0 semantics). A
//     cycle, or a chain deeper than maxRefDepth, is refused in a body or
//     parameter schema and merely drops the OutputSchema (with a warning)
//     in a response schema, because the output schema is optional and a
//     recursive response type is ordinary.
//   - nullable (3.0): translated to a "null" alternative in "type", so the
//     3.0 and 3.1 spellings of the same schema produce the same bytes.
//     Boolean exclusiveMinimum/Maximum (3.0) are translated to the numeric
//     form likewise.
//   - allOf: merged into one object -- properties and required unioned; a
//     property declared twice with different schemas, or two different
//     types, is refused; documentation keywords keep the first value.
//     oneOf/anyOf: preserved under the "body" property with the
//     additionalProperties:false of the lifted branches removed, exactly as
//     ADR-0048 Decisão 4 says.
//   - Unknown keywords, x-* extensions, discriminator (its mapping names
//     components that no longer exist once $ref is resolved), xml,
//     externalDocs and if/then/else are dropped; "not" is kept, since it is
//     plain JSON Schema and opaque to the gateway.
//   - Header parameters named Accept, Content-Type or Authorization are
//     ignored with a warning, as the OpenAPI 3 Parameter Object rule says
//     they SHALL be; every other header name goes through Validate, so a
//     header_Host or a header_<AuthName> in the spec fails the register
//     naming the operation and the parameter (server-wins).
//   - OutputSchema is emitted only when EVERY 2xx response declares only
//     JSON media types whose schemas all translate to the same object
//     schema. The gateway validates structuredContent against it
//     (ADR-0014) and the adapter fills structuredContent only for a 2xx
//     JSON body, so a looser rule would turn a legitimate 204 or text/csv
//     answer into a validation failure. Never for HEAD or OPTIONS (no body
//     to read). An output schema the gateway would refuse at connect
//     (gateway.CheckOutputSchema: jsonschema-go cannot compile it) is
//     dropped with a warning.
//   - routesFor's per-tool refusals (ADR-0047 §3 asks that each be raised
//     to the register or left at connect explicitly): name grammar,
//     definition size and the input-schema check are raised (the same
//     predicates); the output-schema compile is raised as a drop (above).
//     Input schemas are not compiled, because nothing in the gateway
//     compiles them.
//   - Auth: the operator's -auth-kind/-auth-name decide the injection. With
//     no -auth-kind given, the descriptor is DERIVED only when the spec
//     declares exactly one security scheme and it is an apiKey in header or
//     query, or an http bearer scheme; the derivation is reported.
//     Anything else registers keyless with a warning. -auth-kind none
//     (NoDerive) derives nothing and validates the set keyless. A header
//     slot that is a control header (Connection, Host, Proxy-*, ... but not
//     Authorization) is refused, derived or given.
//   - YAML is read by tag, not by Go type (yamlConverter): numerals and
//     timestamps as written, unquoted decimal keys as their digits, aliases
//     expanded under a node budget.
//   - Text from the document that reaches the operator (Skipped, Warnings,
//     errors) is escaped with internal/visible where it is not already %q.
//
// What is refused outright (an error, nothing produced): a document over
// maxDocumentBytes or nested deeper than maxDocumentDepth; Swagger 2.0 and
// unknown versions; YAML with keys that are neither strings nor decimal
// integers, duplicate keys, infinities, unknown tags or aliases expanding
// past maxYAMLAliasNodes; servers[0].url with a variable, query or
// fragment; a path template ParsePath refuses; a path-item $ref; a
// parameter without name/in/schema; a tool name that cannot be made unique
// and legal; an operation whose ToolDef exceeds
// gateway.MaxToolDefinitionBytes (refused while its schemas expand, by the
// byte charge, not after); schema expansion past maxSchemaNodes; more than
// maxOperations operations or more than maxOperationsBytes of encoded set;
// and everything Validate refuses.

// ErrInvalidDocument is returned, wrapped with what was wrong, for a
// document this ingestion cannot read: wrong format, unsupported version,
// a $ref it cannot resolve, a shape the specification does not allow. An
// operation set that parsed but is not servable wraps ErrInvalidOperations
// instead, as Validate does, so the console can tell "the spec is broken"
// from "the spec describes something the gateway will not do".
var ErrInvalidDocument = errors.New("resthttp: invalid openapi document")

// errUnsupportedMedia marks an operation whose body or parameter content has
// no JSON media type. It never leaves Ingest: the operation loop turns it
// into a Skipped entry (Decision above).
var errUnsupportedMedia = errors.New("no application/json media type")

// errSafeMethodBody marks a GET, HEAD or OPTIONS that declares a
// requestBody; like errUnsupportedMedia it becomes a Skipped entry.
var errSafeMethodBody = errors.New("requestBody on a safe method is not sent by this adapter (RFC 9110 §9.3.1: content in a GET request has no generally defined semantics)")

// isSkip reports whether an operation's error is one the operation loop
// reports as Skipped rather than failing the document with.
func isSkip(err error) bool {
	return errors.Is(err, errUnsupportedMedia) || errors.Is(err, errSafeMethodBody)
}

// Ceilings. Each exists so that a hostile or merely enormous document fails
// with a message instead of with the process's memory.
const (
	// maxDocumentBytes bounds the spec before it is parsed. 4 MiB is past
	// any real API's document (the largest public ones are ~2 MiB).
	maxDocumentBytes = 4 << 20
	// maxDocumentDepth bounds nesting of the parsed document. A schema
	// forty levels deep is already unreadable; sixty-four leaves room.
	maxDocumentDepth = 64
	// maxRefDepth bounds a chain of $ref hops (A -> B -> C ...) inside one
	// schema expansion; a cycle is refused before this is reached.
	maxRefDepth = 32
	// maxSchemaNodes bounds the total number of schema nodes one Ingest
	// expands. $ref resolution copies the target into every place that
	// references it, so a document that is small on disk can expand
	// geometrically (ten properties each referencing a schema of ten
	// properties each referencing ...); this is the budget that stops it.
	maxSchemaNodes = 250_000
	// maxOperations bounds the tools one entry generates. 512 is far past
	// the four backends' 65 tools together, and each one is a quarantine
	// row the operator reviews by hand.
	maxOperations = 512
	// maxOperationsBytes bounds the encoded set the registry stores and the
	// signer digests.
	maxOperationsBytes = 4 << 20
	// maxDescriptionBytes bounds one tool description. It reaches the model
	// as context on every tools/list; a page is plenty.
	maxDescriptionBytes = 1024
	// nameHashLen is how many hex digits of SHA-256(method+path) are
	// appended to disambiguate a tool name (ADR-0047 §3, "hash curto").
	nameHashLen = 6
)

// IngestOptions is what the operator decided at register time and the
// document may not override.
type IngestOptions struct {
	// AuthKind and AuthName are the -auth-kind/-auth-name flags: "" (keyless
	// or to be derived), AuthBearer, AuthHeader or AuthQuery, and the header
	// or query parameter name for the last two.
	AuthKind string
	AuthName string
	// BaseURL is the -url flag: the scheme, host, port and optional base
	// path the entry is pinned to. It may be empty, in which case the
	// result's BaseURL is empty too and BasePath says what servers[0]
	// declared; the console always passes it.
	BaseURL string
	// NoDerive is -auth-kind none: keyless, and the document's
	// securitySchemes may not make it otherwise. With AuthKind "" and
	// NoDerive false the descriptor may be derived; NoDerive with a
	// non-empty AuthKind is a contradiction and refused. It matters beyond
	// the descriptor: the set is validated under the effective descriptor,
	// so a derived one would reserve its slot and refuse a parameter there
	// that a keyless entry may carry.
	NoDerive bool
}

// IngestResult is what the register writes and prints.
type IngestResult struct {
	// Operations is the canonical encoding of Ops (Encode), already run
	// through Decode under the effective auth descriptor: the bytes the
	// registry stores and the signer digests.
	Operations []byte
	// Ops is the decoded set, sorted by Name, schemas canonical.
	Ops []Operation
	// BaseURL is the URL to register: opts.BaseURL with BasePath folded in,
	// or opts.BaseURL unchanged when nothing was folded. Empty when
	// opts.BaseURL was.
	BaseURL string
	// BasePath is the base path folded into BaseURL from servers[0].url
	// ("" when servers[] declared none, or when opts.BaseURL already
	// carried one and the spec's was therefore ignored).
	BasePath string
	// AuthKind and AuthName are the effective descriptor the set was
	// validated against: the options' when given, derived from the spec's
	// securitySchemes when AuthDerived is true, keyless otherwise.
	AuthKind    string
	AuthName    string
	AuthDerived bool
	// Skipped lists operations the document declares and the set does not
	// carry, one line each with the reason.
	Skipped []string
	// Warnings lists what was ignored or decided on the operator's behalf,
	// one line each; the console prints them.
	Warnings []string
}

// Ingest translates an OpenAPI 3.0.x/3.1.x document (JSON or YAML) into a
// validated, canonically encoded operation set under the auth descriptor
// opts gives or the spec lets it derive.
//
// Pre-condition: doc is the whole document; opts.AuthKind is "" or one of
// AuthBearer/AuthHeader/AuthQuery. Post-condition: on nil error
// Decode(res.Operations, res.AuthKind, res.AuthName) succeeds and returns
// res.Ops; the same doc and opts produce the same res.Operations byte for
// byte; res.BaseURL, when non-empty, is accepted by parseBase; no
// credential value was ever available to this function, so none can be in
// the error or the result. A non-nil error wraps ErrInvalidDocument (the
// document), ErrInvalidOperations (what it describes) or ErrInvalidURL
// (opts.BaseURL, or the document's base path folded into it -- the console
// runs ValidateBaseURL first, so there only the fold can produce it).
//
// Cost: the document is bounded (maxDocumentBytes, maxDocumentDepth,
// maxYAMLAliasNodes) before it is read, and the expansion is bounded while
// it runs -- in nodes (maxSchemaNodes) and in bytes per operation and per
// set (ingestion.charge) -- so a hostile document is refused at the
// ceiling it reaches first, not after the memory its expansion would take.
func Ingest(doc []byte, opts IngestOptions) (IngestResult, error) {
	if len(doc) > maxDocumentBytes {
		return IngestResult{}, fmt.Errorf("%w: document is %d bytes, over the %d-byte limit", ErrInvalidDocument, len(doc), maxDocumentBytes)
	}
	root, err := parseDocument(doc)
	if err != nil {
		return IngestResult{}, err
	}
	if err := checkVersion(root); err != nil {
		return IngestResult{}, err
	}

	in := &ingestion{root: root}
	res := IngestResult{}

	res.AuthKind, res.AuthName, res.AuthDerived, err = in.auth(opts)
	if err != nil {
		return IngestResult{}, err
	}
	if in.authHeader, in.authQuery, err = reservedSlots(res.AuthKind, res.AuthName); err != nil {
		return IngestResult{}, err
	}
	res.BaseURL, res.BasePath, err = in.servers(opts.BaseURL)
	if err != nil {
		return IngestResult{}, err
	}
	ops, err := in.operations()
	if err != nil {
		return IngestResult{}, err
	}
	// Each operation is validated on its own first, so the refusal names
	// the operation as the spec spells it (method and path), not only the
	// derived tool name; then the set as a whole, through the same Encode
	// and Decode the registry and the dialer use, which pins the canonical
	// form and checks uniqueness.
	for _, d := range ops {
		if err := Validate([]Operation{d.op}, res.AuthKind, res.AuthName); err != nil {
			return IngestResult{}, fmt.Errorf("%w: %s %s (tool %q): %s", ErrInvalidOperations, d.method, d.path, d.op.Name,
				strings.TrimPrefix(detail(err), fmt.Sprintf("operation %q: ", d.op.Name)))
		}
		if n := gateway.DefinitionSize(d.op.ToolDef()); n > gateway.MaxToolDefinitionBytes {
			return IngestResult{}, fmt.Errorf("%w: %s %s (tool %q): its definition is %d bytes, over the %d-byte limit the gateway serves", ErrInvalidOperations, d.method, d.path, d.op.Name, n, gateway.MaxToolDefinitionBytes)
		}
		// routesFor's input-schema refusal, raised to the register by the
		// same function (operation's output-schema Decision has the why).
		if err := gateway.CheckInputSchema(d.op.InputSchema); err != nil {
			return IngestResult{}, fmt.Errorf("%w: %s %s (tool %q): %v", ErrInvalidOperations, d.method, d.path, d.op.Name, err)
		}
	}
	plain := make([]Operation, 0, len(ops))
	for _, d := range ops {
		plain = append(plain, d.op)
	}
	encoded, err := Encode(plain)
	if err != nil {
		return IngestResult{}, err
	}
	if len(encoded) > maxOperationsBytes {
		return IngestResult{}, fmt.Errorf("%w: the operation set encodes to %d bytes, over the %d-byte limit", ErrInvalidOperations, len(encoded), maxOperationsBytes)
	}
	decoded, err := Decode(encoded, res.AuthKind, res.AuthName)
	if err != nil {
		return IngestResult{}, err
	}
	res.Operations = encoded
	res.Ops = decoded
	res.Skipped = in.skipped
	res.Warnings = in.warnings
	return res, nil
}

// ingestion is the state of one Ingest: the parsed document, the budgets,
// and what it has to report.
type ingestion struct {
	root     map[string]any
	nodes    int
	skipped  []string
	warnings []string

	// The byte budget (charge). opBytes is what the operation being built
	// will serialize to, counted while its schemas are expanded; totalBytes
	// is the sum over the operations already built. sizes memoizes, per
	// source schema object (by identity), the bytes its own keywords add,
	// so a component referenced from ten thousand places is measured once
	// and charged ten thousand times. overBudget records which ceiling
	// stopped the expansion ("" while none has), so the refusal can name
	// the operation however deep in a schema the charge was refused.
	opBytes    int
	totalBytes int
	sizes      map[uintptr]int
	overBudget string

	// authHeader and authQuery are the injection slot the descriptor
	// reserves (reservedSlots), folded as Validate folds them; "" when the
	// API is keyless or the slot is of the other kind. A parameter the
	// document declares on that slot is dropped with a warning in
	// operation, not refused -- see there.
	authHeader string
	authQuery  string
}

const (
	budgetOperation = "operation"
	budgetSet       = "set"
)

// charge adds n bytes to the operation being built and refuses once the
// operation's definition can no longer fit gateway.MaxToolDefinitionBytes,
// or the set maxOperationsBytes.
//
// Why bytes and not only nodes (maxSchemaNodes): keyword values are copied
// into the output by reference, so expanding a $ref costs one node however
// large the enum, default or example under it -- and the serialization
// then writes that value once per reference. A 1 MiB document whose one
// component holds a 1 MiB enum, referenced from 300 properties, used to
// serialize to 315 MB before the definition ceiling was checked; the
// charge refuses it at the first reference. The count is the bytes the
// serialization will contain, taken from the source nodes they come from:
// keyword names and values and property names. It leaves out quoting and
// punctuation, so it is a lower bound of the serialized size -- except
// where an allOf repeats a property it merges away, or a parameter is
// translated and then ignored, which is counted although not emitted; a
// definition within that margin of the ceiling can be refused early,
// which is accepted.
//
// Post-condition: on a non-nil error in.overBudget names the ceiling.
func (in *ingestion) charge(n int) error {
	in.opBytes += n
	switch {
	case in.opBytes > gateway.MaxToolDefinitionBytes:
		in.overBudget = budgetOperation
		return fmt.Errorf("schema expansion is past the %d-byte definition limit", gateway.MaxToolDefinitionBytes)
	case in.totalBytes+in.opBytes > maxOperationsBytes:
		in.overBudget = budgetSet
		return fmt.Errorf("schema expansion is past the %d-byte limit of an operation set", maxOperationsBytes)
	}
	return nil
}

// budgetError is the refusal for an operation whose expansion charge
// refused, naming it as the document spells it.
func (in *ingestion) budgetError(where string) error {
	if in.overBudget == budgetSet {
		return fmt.Errorf("%w: %s: the operation set's schemas expand past the %d-byte limit of an encoded set (over the limit before this operation was finished)", ErrInvalidOperations, where, maxOperationsBytes)
	}
	return fmt.Errorf("%w: %s: its definition is over the %d-byte limit the gateway serves (its schemas expand past it; the expansion was stopped there)", ErrInvalidOperations, where, gateway.MaxToolDefinitionBytes)
}

// ownBytes is what schema object s adds to the serialization by itself:
// the names and values of the keywords translateSchema keeps verbatim, and
// the names of its properties (the subschemas are charged when they are
// visited). Memoized by identity of s, which the document tree keeps
// alive and unchanged for the whole Ingest.
func (in *ingestion) ownBytes(s map[string]any) int {
	id := reflect.ValueOf(s).Pointer()
	if n, ok := in.sizes[id]; ok {
		return n
	}
	n := 0
	for key, val := range s {
		switch {
		case key == "properties" || key == "patternProperties":
			props, _ := val.(map[string]any)
			for name := range props {
				n += len(key) + len(name)
			}
		case keptKeywords[key] || key == "nullable" || key == "exclusiveMinimum" || key == "exclusiveMaximum":
			if b, err := marshalCanonical(val); err == nil {
				n += len(key) + len(b)
			}
		}
	}
	if in.sizes == nil {
		in.sizes = map[uintptr]int{}
	}
	in.sizes[id] = n
	return n
}

func (in *ingestion) warn(format string, args ...any) {
	in.warnings = append(in.warnings, fmt.Sprintf(format, args...))
}

func (in *ingestion) skip(method, path, reason string) {
	in.skipped = append(in.skipped, fmt.Sprintf("%s %s: %s", method, path, reason))
}

// ---- document ------------------------------------------------------------

// parseDocument reads doc as JSON when its first non-blank byte is "{" and
// as YAML otherwise (a YAML flow mapping that starts with "{" is read as
// JSON; the two agree on everything a spec uses). Numbers are kept as
// json.Number on both paths, so a value re-encodes as written: on the JSON
// path always, on the YAML path whenever the numeral is a JSON number
// (yamlConverter has the rest). The result is a tree of map[string]any,
// []any, string, json.Number, bool and nil, bounded in depth.
func parseDocument(doc []byte) (map[string]any, error) {
	doc = bytes.TrimPrefix(doc, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimLeft(doc, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: document is empty", ErrInvalidDocument)
	}
	var v any
	if trimmed[0] == '{' {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: parsed as JSON (it begins with \"{\"): %v", ErrInvalidDocument, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("%w: trailing data after the JSON document", ErrInvalidDocument)
		}
	} else {
		// Nesting: yaml.v3 (v3.0.1, go.mod) refuses more than 10000 levels
		// of flow or block nesting itself ("exceeded max depth of 10000",
		// scannerc.go max_flow_level/max_indents), so a 4 MiB line of
		// "[[[[" is an error in milliseconds, not a stack overflow; the
		// conversion below and checkDepth then hold the document to
		// maxDocumentDepth. A pre-scan used to stand here claiming to be
		// that guard; it was neither needed nor sound (a stray quote hid
		// every bracket after it), and was removed.
		var n yaml.Node
		if err := yaml.Unmarshal(doc, &n); err != nil {
			return nil, fmt.Errorf("%w: parsed as YAML: %v", ErrInvalidDocument, err)
		}
		var err error
		c := &yamlConverter{}
		if v, err = c.convert(&n, 0, false); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
		}
	}
	if err := checkDepth(v, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	root, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: the top level must be an object", ErrInvalidDocument)
	}
	return root, nil
}

// maxYAMLAliasNodes bounds how many nodes YAML aliases may add to the tree
// when they are expanded. yaml.v3 applies its own alias-ratio limit only
// when it decodes into Go values; decoding into yaml.Node (which the
// conversion below needs, to read tags) copies no alias, so the expansion
// happens here and is bounded here -- the billion-laughs document is small
// on disk and refused by this count. A real spec that reuses an anchored
// parameter a few hundred times adds a few thousand nodes.
const maxYAMLAliasNodes = 1 << 18

// jsonNumberText is RFC 8259's number grammar: the YAML numerals that match
// it are kept as written, so YAML and JSON spellings of one value produce
// the same canonical bytes.
var jsonNumberText = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)

// yamlConverter turns the yaml.v3 node tree into the JSON tree parseDocument
// promises, by TAG rather than by the Go type yaml.v3 would pick for a
// value. Decoding into `any` rewrote what the document says: an unquoted
// 2024-01-01 became time.Time and then "2024-01-01T00:00:00Z", 1.0 became
// float64 and then "1", and an integer past 2^64 lost precision -- inside
// enum, default and example values the signed set then said something the
// document did not.
//
// Decisions, each applied below:
//   - !!int and !!float: the numeral as written when it is a JSON number
//     (1.0 stays 1.0, a 30-digit integer stays exact); any other YAML
//     spelling (0x1F, +5, 1_000, .5) is converted to its value; .inf and
//     .nan are refused (JSON has no spelling for them).
//   - !!timestamp: the text as written, a string -- what the API documents
//     is the string form, and format: date / date-time is how a schema says
//     it is a date.
//   - !!str, !!bool, !!null: their value. Any other tag (!!binary, !!set,
//     a custom !tag) is refused rather than guessed.
//   - Mapping keys: strings; an unquoted decimal integer key (the "200:" of
//     a hand-written responses map, which OpenAPI says to quote but every
//     tool accepts) is read as its digits, which is a bijection; any other
//     non-string key is refused with where it is and how to fix it. A key
//     defined twice is refused (encoding to `any` refused it too).
//   - Merge keys (<<): applied as YAML 1.1 and yaml.v3 define them --
//     explicit keys win, earlier sources over later ones.
//   - Aliases are expanded (copied), never shared, so nothing downstream can
//     be made to walk a small DAG as an exponential tree; the copies are
//     what maxYAMLAliasNodes counts.
type yamlConverter struct {
	aliasNodes int
}

// yamlError is a conversion refusal with its location: a JSON pointer
// assembled on the way back up (a successful conversion builds no paths)
// and the source line of the offending node.
type yamlError struct {
	path []string // innermost segment first
	line int
	msg  string
}

func (e *yamlError) Error() string {
	var b strings.Builder
	for i := len(e.path) - 1; i >= 0; i-- {
		b.WriteByte('/')
		b.WriteString(strings.ReplaceAll(strings.ReplaceAll(e.path[i], "~", "~0"), "/", "~1"))
	}
	ptr := b.String()
	if ptr == "" {
		ptr = "/"
	}
	return fmt.Sprintf("at %s (line %d): %s", visible.Escape(clip(ptr)), e.line, e.msg)
}

// within adds one path segment to a conversion refusal on its way up.
func within(err error, segment string) error {
	if ye, ok := err.(*yamlError); ok {
		ye.path = append(ye.path, segment)
	}
	return err
}

// deAlias follows an alias node to the node it names (bounded: yaml.v3
// refuses an alias to an anchor not yet defined, so a chain is finite).
func deAlias(n *yaml.Node) *yaml.Node {
	for i := 0; n != nil && n.Kind == yaml.AliasNode && i < maxRefDepth; i++ {
		n = n.Alias
	}
	return n
}

// convert is one node. depth is the nesting depth of n in the converted
// tree; underAlias is true inside an expanded alias, where every node
// produced is charged to maxYAMLAliasNodes.
func (c *yamlConverter) convert(n *yaml.Node, depth int, underAlias bool) (any, error) {
	if depth > maxDocumentDepth {
		return nil, &yamlError{line: n.Line, msg: fmt.Sprintf("document nests more than %d levels deep", maxDocumentDepth)}
	}
	if underAlias {
		c.aliasNodes++
		if c.aliasNodes > maxYAMLAliasNodes {
			return nil, &yamlError{line: n.Line, msg: fmt.Sprintf("document contains excessive aliasing: its aliases expand past %d nodes", maxYAMLAliasNodes)}
		}
	}
	switch n.Kind {
	case 0:
		return nil, nil // an empty document (comments only); "top level must be an object" follows
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return c.convert(n.Content[0], depth, underAlias)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, &yamlError{line: n.Line, msg: "alias names no anchor"}
		}
		return c.convert(n.Alias, depth, true)
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for i, item := range n.Content {
			v, err := c.convert(item, depth+1, underAlias)
			if err != nil {
				return nil, within(err, strconv.Itoa(i))
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		return c.mapping(n, depth, underAlias)
	case yaml.ScalarNode:
		return yamlScalar(n)
	}
	return nil, &yamlError{line: n.Line, msg: fmt.Sprintf("YAML node kind %d has no JSON form", n.Kind)}
}

func (c *yamlConverter) mapping(n *yaml.Node, depth int, underAlias bool) (any, error) {
	out := make(map[string]any, len(n.Content)/2)
	var merges []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		if kn.Kind == yaml.ScalarNode && kn.ShortTag() == "!!merge" {
			merges = append(merges, vn)
			continue
		}
		key, err := yamlKey(kn)
		if err != nil {
			return nil, err
		}
		if _, dup := out[key]; dup {
			return nil, &yamlError{line: kn.Line, msg: fmt.Sprintf("mapping key %s is defined twice", strconv.Quote(clip(key)))}
		}
		v, err := c.convert(vn, depth+1, underAlias)
		if err != nil {
			return nil, within(err, key)
		}
		out[key] = v
	}
	for _, m := range merges {
		sources := []*yaml.Node{m}
		if resolved := deAlias(m); resolved != nil && resolved.Kind == yaml.SequenceNode {
			sources = resolved.Content
		}
		for _, src := range sources {
			mv, err := c.convert(src, depth, underAlias)
			if err != nil {
				return nil, within(err, "<<")
			}
			mm, ok := mv.(map[string]any)
			if !ok {
				return nil, &yamlError{line: src.Line, msg: "a merge key (<<) must name a mapping or a sequence of mappings"}
			}
			for k, v := range mm {
				if _, has := out[k]; !has {
					out[k] = v
				}
			}
		}
	}
	return out, nil
}

// yamlKey is the mapping-key decision in yamlConverter's comment.
func yamlKey(kn *yaml.Node) (string, error) {
	k := deAlias(kn)
	if k == nil || k.Kind != yaml.ScalarNode {
		return "", &yamlError{line: kn.Line, msg: "mapping key is a YAML collection, which JSON has no spelling for"}
	}
	switch tag := k.ShortTag(); tag {
	case "!!str":
		return k.Value, nil
	case "!!int":
		if decimalDigits(k.Value) {
			return k.Value, nil
		}
	}
	return "", &yamlError{line: kn.Line, msg: fmt.Sprintf("mapping key %s is a YAML %s, not a string; quote it (OpenAPI requires string keys)", strconv.Quote(clip(k.Value)), visible.Escape(clip(k.ShortTag())))}
}

func decimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// yamlScalar is the scalar decision in yamlConverter's comment.
func yamlScalar(n *yaml.Node) (any, error) {
	refuse := func(format string, args ...any) (any, error) {
		return nil, &yamlError{line: n.Line, msg: fmt.Sprintf(format, args...)}
	}
	switch tag := n.ShortTag(); tag {
	case "!!str":
		return n.Value, nil
	case "!!null":
		return nil, nil
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return refuse("boolean %s: %v", strconv.Quote(clip(n.Value)), err)
		}
		return b, nil
	case "!!timestamp":
		return n.Value, nil
	case "!!int", "!!float":
		if jsonNumberText.MatchString(n.Value) {
			return json.Number(n.Value), nil
		}
		if tag == "!!int" {
			var i int64
			if err := n.Decode(&i); err == nil {
				return json.Number(strconv.FormatInt(i, 10)), nil
			}
			var u uint64
			if err := n.Decode(&u); err == nil {
				return json.Number(strconv.FormatUint(u, 10)), nil
			}
			return refuse("integer %s is not representable in JSON as written", strconv.Quote(clip(n.Value)))
		}
		var f float64
		if err := n.Decode(&f); err != nil {
			return refuse("number %s: %v", strconv.Quote(clip(n.Value)), err)
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return refuse("a YAML infinity or NaN (%s) has no JSON form", strconv.Quote(clip(n.Value)))
		}
		return json.Number(strconv.FormatFloat(f, 'g', -1, 64)), nil
	default:
		return refuse("a YAML %s value has no JSON form", strconv.Quote(clip(tag)))
	}
}

// checkDepth refuses a tree nested deeper than maxDocumentDepth.
func checkDepth(v any, depth int) error {
	if depth > maxDocumentDepth {
		return fmt.Errorf("document nests more than %d levels deep", maxDocumentDepth)
	}
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if err := checkDepth(item, depth+1); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, item := range x {
			if err := checkDepth(item, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkVersion accepts "openapi": "3.0.x" or "3.1.x" and names, for the
// two likely mistakes, what the operator can do about them.
func checkVersion(root map[string]any) error {
	if _, ok := root["swagger"]; ok {
		return fmt.Errorf("%w: this is a Swagger 2.0 document (\"swagger\" key); only OpenAPI 3.0.x and 3.1.x are read -- convert it first", ErrInvalidDocument)
	}
	v, ok := root["openapi"].(string)
	if !ok {
		if n, isNumber := root["openapi"].(json.Number); isNumber {
			// "openapi: 3.0" unquoted in YAML is a number, not a version.
			return fmt.Errorf("%w: \"openapi\" is the number %s, not a version string; quote it (\"3.0.3\")", ErrInvalidDocument, clip(string(n)))
		}
		return fmt.Errorf("%w: no \"openapi\" version string at the top level", ErrInvalidDocument)
	}
	if !strings.HasPrefix(v, "3.0.") && !strings.HasPrefix(v, "3.1.") {
		return fmt.Errorf("%w: openapi version %q is not 3.0.x or 3.1.x", ErrInvalidDocument, clip(v))
	}
	return nil
}

// clip bounds a string from the document for an error message.
func clip(s string) string {
	const n = 80
	if len(s) <= n {
		return s
	}
	for i := n; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i] + "..."
		}
	}
	return "..."
}

// ---- $ref -----------------------------------------------------------------

// resolvePointer returns the node a local reference ("#/components/schemas/X")
// names. Remote references are refused: the only document this ingestion
// trusts to read is the one the operator pointed at, and a reference that
// fetches another is a fetch the operator did not ask for.
func (in *ingestion) resolvePointer(ref string) (any, error) {
	if ref == "#" {
		return in.root, nil
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("$ref %q is not a local reference (#/...); remote references are not followed", clip(ref))
	}
	var cur any = in.root
	for _, part := range strings.Split(ref[2:], "/") {
		if p, err := url.PathUnescape(part); err == nil {
			part = p
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[part]
			if !ok {
				return nil, fmt.Errorf("$ref %q does not resolve (no %q)", clip(ref), clip(part))
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(node) {
				return nil, fmt.Errorf("$ref %q does not resolve (index %q)", clip(ref), clip(part))
			}
			cur = node[i]
		default:
			return nil, fmt.Errorf("$ref %q does not resolve (%q is not a container)", clip(ref), clip(part))
		}
	}
	return cur, nil
}

// deref follows the $ref of an object node (a parameter, requestBody or
// response -- not a schema, which translateSchema handles with its own
// stack) until it reaches an object without one, refusing a cycle and a
// chain past maxRefDepth.
func (in *ingestion) deref(v any, what string) (map[string]any, error) {
	seen := map[string]bool{}
	for hops := 0; ; hops++ {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", what)
		}
		raw, has := obj["$ref"]
		if !has {
			return obj, nil
		}
		ref, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%s: $ref must be a string", what)
		}
		if seen[ref] {
			return nil, fmt.Errorf("%s: $ref %q is cyclic", what, clip(ref))
		}
		if hops >= maxRefDepth {
			return nil, fmt.Errorf("%s: $ref chain deeper than %d", what, maxRefDepth)
		}
		seen[ref] = true
		target, err := in.resolvePointer(ref)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", what, err)
		}
		v = target
	}
}

// ---- schemas ----------------------------------------------------------------

// keptKeywords are the schema keywords copied as they are: value keywords
// and constraints that JSON Schema defines and the gateway treats as
// opaque. Keywords that hold subschemas (properties, items, oneOf, ...) are
// handled by name in translateSchema; everything else -- x-* extensions,
// discriminator, xml, externalDocs, if/then/else, $-keywords -- is dropped.
var keptKeywords = map[string]bool{
	"type": true, "enum": true, "const": true, "format": true, "default": true,
	"title": true, "description": true, "example": true, "examples": true,
	"deprecated": true, "readOnly": true, "writeOnly": true,
	"minimum": true, "maximum": true, "multipleOf": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minItems": true, "maxItems": true, "uniqueItems": true,
	"minProperties": true, "maxProperties": true, "required": true,
	"dependentRequired": true,
}

// translateSchema turns one OpenAPI schema (3.0 or 3.1 flavour) into the
// JSON Schema object the operation carries: $ref resolved against the
// document (stack is the chain of references being expanded, for cycle
// detection), allOf merged, nullable and boolean exclusive bounds
// translated, unknown keywords dropped. A boolean schema (3.1) becomes {}
// or {"not":{}}.
//
// Post-condition: the returned map holds only values marshalCanonical can
// encode, and in.nodes grew by the number of schema nodes visited.
func (in *ingestion) translateSchema(v any, stack []string) (map[string]any, error) {
	in.nodes++
	if in.nodes > maxSchemaNodes {
		return nil, fmt.Errorf("schema expansion exceeds %d nodes (a $ref referenced from many places expands into each)", maxSchemaNodes)
	}
	var s map[string]any
	switch x := v.(type) {
	case bool:
		if x {
			return map[string]any{}, nil
		}
		return map[string]any{"not": map[string]any{}}, nil
	case map[string]any:
		s = x
	default:
		return nil, errors.New("schema must be an object")
	}
	if _, isRef := s["$ref"]; !isRef {
		if err := in.charge(in.ownBytes(s)); err != nil {
			return nil, err
		}
	}

	if raw, has := s["$ref"]; has {
		ref, ok := raw.(string)
		if !ok {
			return nil, errors.New("$ref must be a string")
		}
		for _, r := range stack {
			if r == ref {
				return nil, fmt.Errorf("$ref %q is cyclic (%s)", clip(ref), strings.Join(append(stack, ref), " -> "))
			}
		}
		if len(stack) >= maxRefDepth {
			return nil, fmt.Errorf("$ref chain deeper than %d at %q", maxRefDepth, clip(ref))
		}
		target, err := in.resolvePointer(ref)
		if err != nil {
			return nil, err
		}
		// Decision: siblings of $ref are dropped (OpenAPI 3.0 semantics).
		return in.translateSchema(target, append(stack, ref))
	}

	out := map[string]any{}
	var allOf []any
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := s[key]
		var err error
		switch key {
		case "properties", "patternProperties":
			props, ok := val.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%q must be an object", key)
			}
			translated := make(map[string]any, len(props))
			for name, p := range props {
				if translated[name], err = in.translateSchema(p, stack); err != nil {
					return nil, fmt.Errorf("%s %q: %v", key, clip(name), err)
				}
			}
			out[key] = translated
		case "items", "not":
			if _, isList := val.([]any); isList {
				return nil, fmt.Errorf("%q as an array is not supported (use prefixItems)", key)
			}
			if out[key], err = in.translateSchema(val, stack); err != nil {
				return nil, fmt.Errorf("%s: %v", key, err)
			}
		case "additionalProperties":
			if b, isBool := val.(bool); isBool {
				out[key] = b
				continue
			}
			if out[key], err = in.translateSchema(val, stack); err != nil {
				return nil, fmt.Errorf("%s: %v", key, err)
			}
		case "oneOf", "anyOf", "prefixItems":
			list, ok := val.([]any)
			if !ok {
				return nil, fmt.Errorf("%q must be an array", key)
			}
			branches := make([]any, 0, len(list))
			for i, b := range list {
				t, err := in.translateSchema(b, stack)
				if err != nil {
					return nil, fmt.Errorf("%s[%d]: %v", key, i, err)
				}
				branches = append(branches, t)
			}
			out[key] = branches
		case "allOf":
			list, ok := val.([]any)
			if !ok {
				return nil, errors.New("\"allOf\" must be an array")
			}
			allOf = list
		case "type":
			switch val.(type) {
			case string, []any:
				out[key] = val
			default:
				return nil, errors.New("\"type\" must be a string or an array")
			}
		case "required":
			list, ok := val.([]any)
			if !ok {
				return nil, errors.New("\"required\" must be an array")
			}
			for _, item := range list {
				if _, ok := item.(string); !ok {
					return nil, errors.New("\"required\" must hold property names")
				}
			}
			out[key] = val
		case "nullable", "exclusiveMinimum", "exclusiveMaximum":
			out[key] = val
		default:
			if keptKeywords[key] {
				out[key] = val
			}
			// Decision: anything else is dropped.
		}
	}

	for i, b := range allOf {
		t, err := in.translateSchema(b, stack)
		if err != nil {
			return nil, fmt.Errorf("allOf[%d]: %v", i, err)
		}
		if err := mergeInto(out, t); err != nil {
			return nil, fmt.Errorf("allOf[%d]: %v", i, err)
		}
	}

	// Decision: 3.0 nullable becomes a "null" alternative in type.
	if n, has := out["nullable"]; has {
		delete(out, "nullable")
		if b, _ := n.(bool); b {
			switch t := out["type"].(type) {
			case string:
				out["type"] = []any{t, "null"}
			case []any:
				hasNull := false
				for _, item := range t {
					if item == "null" {
						hasNull = true
					}
				}
				if !hasNull {
					out["type"] = append(append([]any{}, t...), "null")
				}
			}
		}
	}
	// Decision: 3.0 boolean exclusive bounds become the numeric form.
	for _, pair := range [2][2]string{{"exclusiveMinimum", "minimum"}, {"exclusiveMaximum", "maximum"}} {
		if b, isBool := out[pair[0]].(bool); isBool {
			delete(out, pair[0])
			if bound, has := out[pair[1]]; b && has {
				out[pair[0]] = bound
				delete(out, pair[1])
			}
		}
	}
	return out, nil
}

// mergeInto folds one allOf branch into dst: properties and required are
// unioned, documentation keywords keep dst's value, and any other keyword
// present on both sides with a different value -- type above all -- is a
// conflict this ingestion refuses rather than resolves, because two
// readings of one schema would be two different signed sets.
func mergeInto(dst, src map[string]any) error {
	for key, sv := range src {
		dv, has := dst[key]
		switch {
		case key == "properties" || key == "patternProperties":
			dp, _ := dv.(map[string]any)
			if dp == nil {
				dp = map[string]any{}
			}
			for name, ps := range sv.(map[string]any) {
				if prev, dup := dp[name]; dup {
					if !sameJSON(prev, ps) {
						return fmt.Errorf("property %q is declared twice with different schemas", clip(name))
					}
					continue
				}
				dp[name] = ps
			}
			dst[key] = dp
		case key == "required":
			set := map[string]bool{}
			if dl, _ := dv.([]any); dl != nil {
				for _, item := range dl {
					set[item.(string)] = true
				}
			}
			for _, item := range sv.([]any) {
				set[item.(string)] = true
			}
			names := make([]string, 0, len(set))
			for n := range set {
				names = append(names, n)
			}
			sort.Strings(names)
			merged := make([]any, 0, len(names))
			for _, n := range names {
				merged = append(merged, n)
			}
			dst[key] = merged
		case key == "description" || key == "title" || key == "example" || key == "examples" || key == "deprecated" || key == "default":
			if !has {
				dst[key] = sv
			}
		default:
			if has && !sameJSON(dv, sv) {
				if key == "type" {
					return fmt.Errorf("conflicting types %s and %s", jsonText(dv), jsonText(sv))
				}
				return fmt.Errorf("conflicting %q", key)
			}
			dst[key] = sv
		}
	}
	return nil
}

func sameJSON(a, b any) bool { return jsonText(a) == jsonText(b) }

func jsonText(v any) string {
	b, err := marshalCanonical(v)
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

// ---- auth -------------------------------------------------------------------

// auth returns the effective descriptor (Decision: "Auth" in the file
// comment). The spec never overrides a kind the operator gave; it can only
// fill one the operator left blank, and only when there is exactly one
// scheme this adapter can inject.
func (in *ingestion) auth(opts IngestOptions) (kind, name string, derived bool, err error) {
	type scheme struct {
		kind, name, label string
	}
	var declared []scheme
	components, _ := in.root["components"].(map[string]any)
	schemes, _ := components["securitySchemes"].(map[string]any)
	names := make([]string, 0, len(schemes))
	for n := range schemes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		sc, _ := schemes[n].(map[string]any)
		typ, _ := sc["type"].(string)
		where, _ := sc["in"].(string)
		pname, _ := sc["name"].(string)
		httpScheme, _ := sc["scheme"].(string)
		// Every fragment of the label is the document's text and reaches
		// the operator's terminal (warnings, the derivation refusal), so it
		// is escaped as the rest of the console escapes what a third party
		// chose (internal/visible): an ESC in a scheme's name must not be
		// able to repaint the tool table printed above the warnings.
		s := scheme{label: fmt.Sprintf("securitySchemes.%s (%s", visible.Escape(clip(n)), visible.Escape(clip(typ)))}
		switch {
		case typ == "apiKey" && where == "header":
			s.kind, s.name, s.label = AuthHeader, pname, s.label+" in header "+visible.Escape(clip(pname))+")"
		case typ == "apiKey" && where == "query":
			s.kind, s.name, s.label = AuthQuery, pname, s.label+" in query "+visible.Escape(clip(pname))+")"
		case typ == "http" && strings.EqualFold(httpScheme, "bearer"):
			s.kind, s.label = AuthBearer, s.label+" bearer)"
		default:
			s.label += ", not injectable by this adapter)"
		}
		declared = append(declared, s)
	}

	if opts.NoDerive {
		if opts.AuthKind != "" || opts.AuthName != "" {
			return "", "", false, fmt.Errorf("%w: keyless (no derivation) was asked for together with auth kind %q name %q", ErrInvalidOperations, opts.AuthKind, opts.AuthName)
		}
		for _, s := range declared {
			if s.kind != "" {
				in.warn("-auth-kind none: the document's security scheme was ignored and the entry is keyless (%s)", s.label)
			}
		}
		return AuthNone, "", false, nil
	}
	if opts.AuthKind != "" {
		if _, _, err := reservedSlots(opts.AuthKind, opts.AuthName); err != nil {
			return "", "", false, err
		}
		for _, s := range declared {
			if s.kind != "" && (s.kind != opts.AuthKind || !strings.EqualFold(s.name, opts.AuthName)) {
				in.warn("the spec declares %s; the operator's -auth-kind %s%s wins", s.label, opts.AuthKind, nameSuffix(opts.AuthName))
			}
		}
		return opts.AuthKind, opts.AuthName, false, nil
	}
	if opts.AuthName != "" {
		return "", "", false, fmt.Errorf("%w: auth name %q given without an auth kind", ErrInvalidOperations, opts.AuthName)
	}
	switch {
	case len(declared) == 0:
		return AuthNone, "", false, nil
	case len(declared) > 1:
		in.warn("the spec declares %d security schemes and no -auth-kind was given; registering keyless (pass -auth-kind to inject a credential)", len(declared))
		return AuthNone, "", false, nil
	case declared[0].kind == "":
		in.warn("the spec declares %s and no -auth-kind was given; registering keyless", declared[0].label)
		return AuthNone, "", false, nil
	}
	s := declared[0]
	if _, _, err := reservedSlots(s.kind, s.name); err != nil {
		return "", "", false, fmt.Errorf("%w: cannot derive the auth descriptor from %s: %v", ErrInvalidDocument, s.label, detail(err))
	}
	in.warn("auth descriptor derived from %s: kind %s%s; a credential (-env) is required", s.label, s.kind, nameSuffix(visible.Escape(s.name)))
	return s.kind, s.name, true, nil
}

func nameSuffix(name string) string {
	if name == "" {
		return ""
	}
	return " name " + name
}

// ---- servers -----------------------------------------------------------------

// servers applies the servers[] decision: returns the URL to register
// (operatorURL with the spec's base path folded in when operatorURL has
// none) and the folded base path.
func (in *ingestion) servers(operatorURL string) (baseURL, basePath string, err error) {
	var op base
	haveOperator := strings.TrimSpace(operatorURL) != ""
	if haveOperator {
		if op, err = parseBase(operatorURL); err != nil {
			return "", "", err
		}
	}

	list, _ := in.root["servers"].([]any)
	if len(list) == 0 {
		return operatorURL, "", nil
	}
	if len(list) > 1 {
		in.warn("servers[] lists %d entries; only servers[0] is read, for its base path", len(list))
	}
	s0, _ := list[0].(map[string]any)
	raw, _ := s0["url"].(string)
	if raw == "" {
		return "", "", fmt.Errorf("%w: servers[0].url is missing or not a string", ErrInvalidDocument)
	}
	if strings.ContainsAny(raw, "{}") {
		// Decision: refuse rather than substitute defaults -- a default the
		// operator did not type is a destination the operator did not sign.
		return "", "", fmt.Errorf("%w: servers[0].url %q carries a server variable; register the resolved URL with -url instead", ErrInvalidDocument, clip(raw))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", fmt.Errorf("%w: servers[0].url: %v", ErrInvalidDocument, err)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", fmt.Errorf("%w: servers[0].url %q carries a query, fragment or opaque part", ErrInvalidDocument, clip(raw))
	}
	if u.Scheme != "" || u.Host != "" {
		specOrigin := originOf(u)
		switch {
		case !haveOperator:
			in.warn("servers[0].url names %s; ignored: the host is always the registered -url (ADR-0048 Decisão 6)", visible.Escape(clip(specOrigin)))
		case specOrigin != op.origin:
			in.warn("servers[0].url names %s; ignored: the registered URL %s is the destination (ADR-0048 Decisão 6)", visible.Escape(clip(specOrigin)), op.origin)
		}
	}
	path := u.EscapedPath()
	if path == "" || path == "/" {
		return operatorURL, "", nil
	}
	templates, err := ParsePath(path)
	if err != nil {
		return "", "", fmt.Errorf("%w: servers[0].url base path: %s", ErrInvalidDocument, detail(err))
	}
	if len(templates) != 0 {
		return "", "", fmt.Errorf("%w: servers[0].url base path %q carries a template", ErrInvalidDocument, clip(path))
	}
	path = strings.TrimSuffix(path, "/")

	if !haveOperator {
		return "", path, nil
	}
	if op.path != "" {
		if op.path != path {
			in.warn("the registered URL already carries base path %q; the spec's servers[0] base path %q is not folded in", op.path, path)
		}
		return operatorURL, "", nil
	}
	folded := strings.TrimSuffix(operatorURL, "/") + path
	if _, err := parseBase(folded); err != nil {
		return "", "", fmt.Errorf("folding servers[0] base path %q into -url: %w", path, err)
	}
	return folded, path, nil
}

// ---- operations -------------------------------------------------------------

// draft is one operation on its way to the set, with where it came from
// for the messages.
type draft struct {
	method, path, opID string
	op                 Operation
}

// methodOrder is the order operations of one path are visited, so that the
// output -- names included -- does not depend on map iteration.
var methodOrder = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace", "connect", "query"}

// operations walks paths and builds one draft per (path, method) the
// adapter serves, then names them (assignNames).
func (in *ingestion) operations() ([]draft, error) {
	paths, ok := in.root["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, fmt.Errorf("%w: no \"paths\" object (a document with only webhooks or components has no operations to serve)", ErrInvalidDocument)
	}
	pathKeys := make([]string, 0, len(paths))
	for p := range paths {
		pathKeys = append(pathKeys, p)
	}
	sort.Strings(pathKeys)

	var drafts []draft
	for _, path := range pathKeys {
		if strings.HasPrefix(path, "x-") {
			// Not a path (a path begins with "/"): a vendor extension of the
			// Paths Object. Reported, as ADR-0047 §3's step asks of what the
			// ingestion leaves out, but as a warning: it never was an
			// operation.
			in.warn("paths[%q]: vendor extension ignored", clip(path))
			continue
		}
		item, ok := paths[path].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: paths[%q] must be an object", ErrInvalidDocument, clip(path))
		}
		if _, has := item["$ref"]; has {
			return nil, fmt.Errorf("%w: paths[%q]: a path item $ref is not supported", ErrInvalidDocument, clip(path))
		}
		if _, has := item["servers"]; has {
			in.warn("paths[%q].servers ignored: the host is always the registered -url", clip(path))
		}
		// The template is checked before anything else of the path item is
		// read: a path that ParsePath refuses is a destination the spec
		// tried to smuggle (ADR-0048 Decisão 6), whatever its operations say.
		if _, err := ParsePath(path); err != nil {
			return nil, fmt.Errorf("%w: paths[%q]: %s", ErrInvalidOperations, clip(path), detail(err))
		}
		// Path-level parameters are translated once and inherited by every
		// operation of the path, so their bytes are charged to each of them:
		// the charge starts every operation from what they cost.
		in.opBytes = 0
		pathParams, pathErr := in.parameters(item["parameters"])
		if pathErr != nil && in.overBudget != "" {
			return nil, in.budgetError(fmt.Sprintf("paths[%q].parameters", clip(path)))
		}
		if pathErr != nil && !errors.Is(pathErr, errUnsupportedMedia) {
			return nil, fmt.Errorf("%w: paths[%q].parameters: %v", ErrInvalidDocument, clip(path), pathErr)
		}
		pathBytes := in.opBytes
		for _, method := range methodOrder {
			raw, has := item[method]
			if !has {
				continue
			}
			upper := strings.ToUpper(method)
			if !ValidMethod(upper) {
				in.skip(upper, path, "method not served (ValidMethod: TRACE echoes the request, CONNECT opens a tunnel)")
				continue
			}
			if pathErr != nil {
				// A path-level parameter this phase cannot carry is
				// inherited by every operation of the path: all are skipped.
				in.skip(upper, path, "path-level parameters: "+pathErr.Error())
				continue
			}
			if len(drafts) >= maxOperations {
				return nil, fmt.Errorf("%w: more than %d operations", ErrInvalidDocument, maxOperations)
			}
			in.opBytes = pathBytes
			d, err := in.operation(upper, path, raw, pathParams)
			if err != nil {
				if in.overBudget != "" {
					return nil, in.budgetError(upper + " " + path)
				}
				if isSkip(err) {
					in.skip(upper, path, err.Error())
					continue
				}
				return nil, err
			}
			in.totalBytes += in.opBytes
			drafts = append(drafts, d)
		}
	}
	if len(drafts) == 0 {
		return nil, fmt.Errorf("%w: the document declares no operation this adapter can serve (%d skipped)", ErrInvalidOperations, len(in.skipped))
	}
	if err := assignNames(drafts); err != nil {
		return nil, err
	}
	return drafts, nil
}

// operation builds the draft of one (method, path): parameters merged
// (operation-level overriding path-level by (in, name)), body, description
// and output schema; the name is assigned later.
func (in *ingestion) operation(method, path string, raw any, inherited []param) (draft, error) {
	where := method + " " + path
	obj, ok := raw.(map[string]any)
	if !ok {
		return draft{}, fmt.Errorf("%w: %s must be an object", ErrInvalidDocument, where)
	}
	if _, has := obj["servers"]; has {
		in.warn("%s: operation-level servers ignored: the host is always the registered -url", where)
	}
	var opID string
	if v, has := obj["operationId"]; has {
		if opID, ok = v.(string); !ok {
			return draft{}, fmt.Errorf("%w: %s: operationId must be a string", ErrInvalidDocument, where)
		}
	}
	if _, has := obj["requestBody"]; has && ClassOf(method) == quarantine.ClassSafe {
		// Decision: skipped, not fatal. OpenAPI 3.1 allows a body on GET
		// ("not well-defined"), search APIs use it, and this adapter never
		// sends one on a safe method (Validate refuses the body property
		// there): one such operation must not keep the other forty-nine of
		// a document out, any more than a multipart upload does.
		return draft{}, errSafeMethodBody
	}
	own, err := in.parameters(obj["parameters"])
	if err != nil {
		if errors.Is(err, errUnsupportedMedia) {
			return draft{}, fmt.Errorf("parameters: %w", err)
		}
		return draft{}, fmt.Errorf("%w: %s: parameters: %v", ErrInvalidDocument, where, err)
	}
	params := mergeParams(inherited, own)

	props := map[string]any{}
	required := map[string]bool{}
	for _, p := range params {
		var prefix string
		switch p.in {
		case "path":
			prefix = PrefixPath
			p.required = true // OpenAPI requires it; a template with no value has no URL.
		case "query":
			prefix = PrefixQuery
			if in.authQuery != "" && strings.ToLower(p.name) == in.authQuery {
				in.warn("%s: query parameter %q dropped: the gateway injects the credential there itself", where, p.name)
				continue
			}
		case "header":
			prefix = PrefixHeader
			// Decision (09 Oct 2026, found against the public Petstore
			// document): a parameter on the credential's own slot is
			// DROPPED with a warning, not refused. Documents declare the
			// key header on the operations that need it (Petstore's
			// DELETE /pet/{petId} declares api_key), and the outcome is the
			// one the refusal protected: the analyst's model cannot set the
			// slot, and the server-side value is the one sent (ADR-0047 §3,
			// "servidor-vence"). Refusing it kept a whole real API out over
			// one redundant declaration. Validate still refuses the
			// property in a set that reaches it by any other road.
			if in.authHeader != "" && foldHeader(p.name) == in.authHeader {
				in.warn("%s: header parameter %q dropped: the gateway injects the credential there itself", where, p.name)
				continue
			}
			switch strings.ToLower(p.name) {
			case "accept", "content-type", "authorization":
				// OpenAPI 3 Parameter Object: "If in is "header" and the
				// name field is "Accept", "Content-Type" or "Authorization",
				// the parameter definition SHALL be ignored."
				in.warn("%s: header parameter %q ignored, as the OpenAPI Parameter Object rule says", where, p.name)
				continue
			}
		case "cookie":
			prefix = PrefixCookie
		}
		key := prefix + p.name
		if err := in.charge(len(key)); err != nil {
			return draft{}, err
		}
		if _, dup := props[key]; dup {
			return draft{}, fmt.Errorf("%w: %s: parameter %q in %s is declared twice", ErrInvalidDocument, where, clip(p.name), p.in)
		}
		props[key] = p.schema
		if p.required {
			required[key] = true
		}
	}

	if rb, has := obj["requestBody"]; has {
		schema, bodyRequired, err := in.requestBody(rb)
		if err != nil {
			if errors.Is(err, errUnsupportedMedia) {
				return draft{}, fmt.Errorf("requestBody: %w", err)
			}
			return draft{}, fmt.Errorf("%w: %s: requestBody: %v", ErrInvalidDocument, where, err)
		}
		props[BodyProperty] = schema
		if bodyRequired {
			required[BodyProperty] = true
		}
	}

	input := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) != 0 {
		names := make([]string, 0, len(required))
		for n := range required {
			names = append(names, n)
		}
		sort.Strings(names)
		list := make([]any, 0, len(names))
		for _, n := range names {
			list = append(list, n)
		}
		input["required"] = list
	}
	inputBytes, err := marshalCanonical(input)
	if err != nil {
		return draft{}, fmt.Errorf("%w: %s: input schema: %v", ErrInvalidDocument, where, err)
	}

	var output json.RawMessage
	if method == "HEAD" || method == "OPTIONS" {
		// Decision: no OutputSchema for HEAD or OPTIONS, whatever the
		// responses declare. A HEAD answer never has a body (RFC 9110
		// §9.3.2) and an OPTIONS answer rarely does; the adapter fills
		// structuredContent only from a 2xx JSON body (resthttp.go
		// serialize), and the gateway refuses a result without one when the
		// tool declares an output schema (response.go
		// validateStructuredContent) -- so a generated spec that copies the
		// GET's responses onto the HEAD would yield a tool that can never
		// answer.
		declared, err := in.declaresContent(obj["responses"])
		if err != nil {
			return draft{}, fmt.Errorf("%w: %s: responses: %v", ErrInvalidDocument, where, err)
		}
		if declared {
			in.warn("%s: response content ignored, no output schema: a %s response carries no body the adapter can read", where, method)
		}
	} else {
		preOutput := in.opBytes
		output, err = in.outputSchema(obj["responses"], where)
		if err != nil {
			return draft{}, fmt.Errorf("%w: %s: responses: %v", ErrInvalidDocument, where, err)
		}
		defer func() {
			if output == nil {
				in.opBytes = preOutput // a dropped output schema is not serialized
			}
		}()
	}
	if len(output) != 0 {
		// Decision (ADR-0047 §3 asks that routesFor's per-tool refusals be
		// raised to the register or left there explicitly): an output
		// schema routesFor would refuse at connect -- one jsonschema-go
		// cannot compile, such as a "pattern" with a lookahead RE2 does not
		// have -- is DROPPED here with a warning, by the same function
		// (gateway.CheckOutputSchema), exactly as a recursive response type
		// is: the output schema is optional, and without it the tool still
		// serves. Input schemas are held to routesFor's input check in
		// Ingest (gateway.CheckInputSchema) and are not compiled: nothing in
		// the gateway compiles an input schema (arguments are the backend's
		// to validate), so an input "pattern" in a syntax RE2 lacks is kept
		// as the document wrote it.
		if err := gateway.CheckOutputSchema(output); err != nil {
			in.warn("%s: output schema will not compile, dropped: %s", where, clip(err.Error()))
			output = nil
		}
	}

	op := Operation{
		Description:  describe(obj, method, path),
		Method:       method,
		Path:         path,
		InputSchema:  inputBytes,
		OutputSchema: output,
	}
	// Measured here, with the name not yet assigned (assignNames runs over
	// the whole set), so the refusal comes at the first oversized operation
	// rather than after every other one was built; the size without a name
	// is a lower bound, and Ingest measures again with it.
	if n := gateway.DefinitionSize(op.ToolDef()); n > gateway.MaxToolDefinitionBytes {
		return draft{}, fmt.Errorf("%w: %s: its definition is %d bytes, over the %d-byte limit the gateway serves", ErrInvalidOperations, where, n, gateway.MaxToolDefinitionBytes)
	}
	return draft{method: method, path: path, opID: opID, op: op}, nil
}

// declaresContent reports whether any 2xx response of a responses object
// declares content (the HEAD/OPTIONS decision in operation).
func (in *ingestion) declaresContent(raw any) (bool, error) {
	responses, ok := raw.(map[string]any)
	if raw != nil && !ok {
		return false, errors.New("must be an object")
	}
	for code, r := range responses {
		if !is2xx(code) {
			continue
		}
		resp, err := in.deref(r, "responses["+code+"]")
		if err != nil {
			return false, err
		}
		if content, _ := resp["content"].(map[string]any); len(content) != 0 {
			return true, nil
		}
	}
	return false, nil
}

// param is one parameter as read from the document, schema translated.
type param struct {
	name, in   string
	required   bool
	schema     map[string]any
	deprecated bool
}

// parameters reads a parameters list (path- or operation-level), resolving
// $ref to components/parameters. An entry with `content` instead of
// `schema` takes the JSON media type's schema or marks the operation
// unsupported (errUnsupportedMedia).
func (in *ingestion) parameters(raw any) ([]param, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("must be an array")
	}
	out := make([]param, 0, len(list))
	for i, item := range list {
		obj, err := in.deref(item, fmt.Sprintf("parameters[%d]", i))
		if err != nil {
			return nil, err
		}
		p := param{}
		if p.name, ok = obj["name"].(string); !ok || p.name == "" {
			return nil, fmt.Errorf("parameters[%d]: \"name\" must be a non-empty string", i)
		}
		if p.in, ok = obj["in"].(string); !ok {
			return nil, fmt.Errorf("parameters[%d] (%q): \"in\" is missing", i, clip(p.name))
		}
		switch p.in {
		case "path", "query", "header", "cookie":
		default:
			return nil, fmt.Errorf("parameters[%d] (%q): \"in\" %q is not path, query, header or cookie", i, clip(p.name), clip(p.in))
		}
		p.required, _ = obj["required"].(bool)
		p.deprecated, _ = obj["deprecated"].(bool)

		var schemaNode any
		switch {
		case obj["schema"] != nil:
			schemaNode = obj["schema"]
		case obj["content"] != nil:
			media, mt, err := pickJSONMedia(obj["content"])
			if err != nil {
				return nil, fmt.Errorf("parameters[%d] (%q): content: %w", i, clip(p.name), err)
			}
			if media["schema"] == nil {
				return nil, fmt.Errorf("parameters[%d] (%q): content[%q] has no schema", i, clip(p.name), mt)
			}
			schemaNode = media["schema"]
		default:
			return nil, fmt.Errorf("parameters[%d] (%q): neither \"schema\" nor \"content\"", i, clip(p.name))
		}
		if p.schema, err = in.translateSchema(schemaNode, nil); err != nil {
			return nil, fmt.Errorf("parameters[%d] (%q): schema: %v", i, clip(p.name), err)
		}
		if d, ok := obj["description"].(string); ok && d != "" {
			if _, has := p.schema["description"]; !has {
				if err := in.charge(len(d)); err != nil {
					return nil, err
				}
				p.schema["description"] = d
			}
		}
		if p.deprecated {
			p.schema["deprecated"] = true
		}
		out = append(out, p)
	}
	return out, nil
}

// mergeParams applies the OpenAPI override rule: an operation-level
// parameter replaces a path-level one with the same (in, name); the rest
// are inherited. Order: inherited first, then own, both as declared.
func mergeParams(inherited, own []param) []param {
	override := map[[2]string]bool{}
	for _, p := range own {
		override[[2]string{p.in, p.name}] = true
	}
	out := make([]param, 0, len(inherited)+len(own))
	for _, p := range inherited {
		if !override[[2]string{p.in, p.name}] {
			out = append(out, p)
		}
	}
	return append(out, own...)
}

// pickJSONMedia returns the media type object of a `content` map to use:
// application/json when present, else the first (by sorted key) +json
// type; errUnsupportedMedia when there is none.
func pickJSONMedia(raw any) (media map[string]any, mediaType string, err error) {
	content, ok := raw.(map[string]any)
	if !ok {
		return nil, "", errors.New("\"content\" must be an object")
	}
	keys := make([]string, 0, len(content))
	for k := range content {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	chosen := ""
	for _, k := range keys {
		mt, _, perr := mime.ParseMediaType(k)
		if perr != nil {
			continue
		}
		if strings.ToLower(mt) == "application/json" {
			chosen = k
			break
		}
		if chosen == "" && isJSONMediaType(k) {
			chosen = k
		}
	}
	if chosen == "" {
		// The media type keys are the document's text and end up in the
		// Skipped lines the console prints: escaped (see auth).
		return nil, "", fmt.Errorf("%w (declared: %s); only JSON bodies are served in this phase", errUnsupportedMedia, visible.Escape(clip(strings.Join(keys, ", "))))
	}
	media, ok = content[chosen].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("content[%q] must be an object", clip(chosen))
	}
	return media, chosen, nil
}

// requestBody reads the body description: the JSON media type's schema,
// translated, with the lifted alternation's additionalProperties:false
// neutralized (ADR-0048 Decisão 4), and whether the body is required. A
// media type without a schema is "any JSON" ({}).
func (in *ingestion) requestBody(raw any) (map[string]any, bool, error) {
	obj, err := in.deref(raw, "requestBody")
	if err != nil {
		return nil, false, err
	}
	media, _, err := pickJSONMedia(obj["content"])
	if err != nil {
		return nil, false, err
	}
	required, _ := obj["required"].(bool)
	schema := map[string]any{}
	if media["schema"] != nil {
		if schema, err = in.translateSchema(media["schema"], nil); err != nil {
			return nil, false, fmt.Errorf("schema: %v", err)
		}
	}
	for _, key := range []string{"oneOf", "anyOf"} {
		branches, _ := schema[key].([]any)
		for _, b := range branches {
			if bm, ok := b.(map[string]any); ok {
				if closed, isBool := bm["additionalProperties"].(bool); isBool && !closed {
					delete(bm, "additionalProperties")
				}
			}
		}
	}
	if d, ok := obj["description"].(string); ok && d != "" {
		if _, has := schema["description"]; !has {
			if err := in.charge(len(d)); err != nil {
				return nil, false, err
			}
			schema["description"] = d
		}
	}
	return schema, required, nil
}

// outputSchema applies the OutputSchema decision: the canonical bytes of
// the one object schema every 2xx response declares under JSON-only media
// types, or nil. A schema this ingestion cannot translate (a recursive
// response type, say) drops the output schema with a warning rather than
// failing the register, since the output schema is optional.
//
// Charging: every candidate schema is translated from the same starting
// charge (the input's), and only the one emitted stays charged -- two 2xx
// responses that $ref the same object are one output schema, not two.
func (in *ingestion) outputSchema(raw any, where string) (out json.RawMessage, err error) {
	if raw == nil {
		return nil, nil
	}
	base, agreedCost := in.opBytes, 0
	defer func() {
		if in.overBudget != "" {
			return
		}
		in.opBytes = base
		if out != nil {
			in.opBytes += agreedCost
		}
	}()
	responses, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("must be an object")
	}
	codes := make([]string, 0, len(responses))
	for code := range responses {
		if is2xx(code) {
			codes = append(codes, code)
		}
	}
	if len(codes) == 0 {
		return nil, nil
	}
	sort.Strings(codes)
	var agreed []byte
	for _, code := range codes {
		resp, err := in.deref(responses[code], "responses["+code+"]")
		if err != nil {
			return nil, err
		}
		content, ok := resp["content"].(map[string]any)
		if !ok || len(content) == 0 {
			return nil, nil // a 204, or a response without a body
		}
		mediaTypes := make([]string, 0, len(content))
		for mt := range content {
			mediaTypes = append(mediaTypes, mt)
		}
		sort.Strings(mediaTypes)
		for _, mt := range mediaTypes {
			if !isJSONMediaType(mt) {
				return nil, nil
			}
			media, ok := content[mt].(map[string]any)
			if !ok || media["schema"] == nil {
				return nil, nil
			}
			in.opBytes = base
			schema, err := in.translateSchema(media["schema"], nil)
			if err != nil {
				if in.overBudget != "" {
					return nil, err
				}
				in.warn("%s: responses[%s] schema not translated, no output schema: %v", where, code, err)
				return nil, nil
			}
			if t, _ := schema["type"].(string); t != "object" {
				return nil, nil
			}
			b, err := marshalCanonical(schema)
			if err != nil {
				return nil, err
			}
			if agreed != nil && !bytes.Equal(agreed, b) {
				return nil, nil
			}
			agreed, agreedCost = b, in.opBytes-base
		}
	}
	return agreed, nil
}

func is2xx(code string) bool {
	if strings.EqualFold(code, "2XX") {
		return true
	}
	n, err := strconv.Atoi(code)
	return err == nil && len(code) == 3 && n >= 200 && n <= 299
}

// describe is the description rule: summary, else description, else
// "<METHOD> <path>", bounded by maxDescriptionBytes with the cut marked.
func describe(obj map[string]any, method, path string) string {
	s, _ := obj["summary"].(string)
	s = strings.TrimSpace(s)
	if s == "" {
		s, _ = obj["description"].(string)
		s = strings.TrimSpace(s)
	}
	if s == "" {
		s = method + " " + path
	}
	if len(s) > maxDescriptionBytes {
		cut := maxDescriptionBytes
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + " [truncated]"
	}
	return s
}

// ---- names --------------------------------------------------------------------

// sanitizeName maps an operationId (or a "<method>_<path>" fallback) onto
// gateway.ValidToolName's charset: every byte outside [A-Za-z0-9-] becomes
// "_", runs collapse to one, and leading/trailing "_" are trimmed.
func sanitizeName(s string) string {
	var b strings.Builder
	prevUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteByte(c)
			prevUnderscore = false
			continue
		}
		if !prevUnderscore {
			b.WriteByte('_')
		}
		prevUnderscore = true
	}
	return strings.Trim(b.String(), "_")
}

// hashSuffix is "_" + nameHashLen hex digits of SHA-256("<METHOD> <path>"):
// the disambiguator of ADR-0047 §3, a function of what makes the operation
// unique in its document, so the same spec yields the same names.
func hashSuffix(method, path string) string {
	sum := sha256.Sum256([]byte(method + " " + path))
	return "_" + hex.EncodeToString(sum[:])[:nameHashLen]
}

// assignNames gives every draft its tool name (ADR-0047 §3): the sanitized
// operationId, or "<method>_<path>" sanitized when there is none; when the
// result is over gateway.MaxToolNameLen, or two operations share it, the
// hash suffix is appended with the prefix truncated to fit -- to BOTH
// colliding operations, so neither silently wins. A name that is still
// not unique and legal after that fails the register naming the operation.
func assignNames(drafts []draft) error {
	bases := make([]string, len(drafts))
	count := map[string]int{}
	for i, d := range drafts {
		name := sanitizeName(d.opID)
		if name == "" {
			name = sanitizeName(strings.ToLower(d.method) + "_" + d.path)
		}
		bases[i] = name
		count[name]++
	}
	final := map[string]int{}
	for i := range drafts {
		name := bases[i]
		if len(name) > gateway.MaxToolNameLen || count[name] > 1 {
			suffix := hashSuffix(drafts[i].method, drafts[i].path)
			if room := gateway.MaxToolNameLen - len(suffix); len(name) > room {
				name = strings.TrimRight(name[:room], "_")
			}
			name += suffix
		}
		if !gateway.ValidToolName(name) {
			return fmt.Errorf("%w: %s %s: cannot derive a legal tool name (operationId %q)", ErrInvalidOperations, drafts[i].method, drafts[i].path, clip(drafts[i].opID))
		}
		if j, dup := final[name]; dup {
			return fmt.Errorf("%w: %s %s and %s %s both derive the tool name %q; give them distinct operationIds", ErrInvalidOperations,
				drafts[j].method, drafts[j].path, drafts[i].method, drafts[i].path, name)
		}
		final[name] = i
		drafts[i].op.Name = name
	}
	return nil
}
