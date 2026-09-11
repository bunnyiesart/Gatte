package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// This file is design/adr/0014-response-validation-scope.md: what the
// gateway checks about a result on its way back from a backend, and --
// just as deliberately -- what it does not.
//
// Two controls:
//
//  1. A size ceiling, applied to every result. This is the one with an
//     effect today, because no backend in this fleet declares an output
//     schema.
//  2. Validation of StructuredContent against Tool.OutputSchema, when the
//     backend declares one. Nothing is inferred when it does not.
//
// And one absence, which is a decision and not an omission: **the gateway
// does not attempt to detect prompt injection in a result.** No "looks
// like a prompt" heuristic, no phrase list. Schema validation proves
// *shape*, never content: a result can satisfy its schema perfectly and
// carry, in a string field the schema declares as a string, an
// instruction addressed to the model. A structural validator does not
// solve that, and one advertised as solving it would be worse than none,
// because somebody would rely on it. The false-negative rate makes such a
// filter useless as a control and the false-positive rate makes it break
// legitimate analyst work; together they produce a control people switch
// off. The real defence is the result reaching the model marked as
// untrusted data, which is a property of the MCP client and the model,
// not of this gateway.

// Sentinel errors for a result the gateway refuses to pass on.
var (
	// ErrResultTooLarge means a backend answered with more bytes than the
	// configured ceiling allows. See DefaultMaxResultBytes.
	ErrResultTooLarge = errors.New("gateway: result too large")

	// ErrResultSchemaViolation means a tool declared an OutputSchema and
	// its result's StructuredContent does not satisfy it.
	ErrResultSchemaViolation = errors.New("gateway: result does not match the tool's declared output schema")

	// ErrUnusableOutputSchema means an upstream declared an output schema
	// the gateway cannot compile, so it could never be checked against.
	// Refused at discovery, like ErrUnusableSchema. See resolveOutputSchema.
	ErrUnusableOutputSchema = errors.New("gateway: unusable output schema")
)

// Reasons for a result refused after the call completed. Part of the same
// closed set as reasonUpstreamTimeout and friends, and closed for the same
// reason: Reason is operator-facing evidence, not a place for
// upstream-authored text. Both are recorded with audit.OutcomeFailed, as
// the second row of the pair design/adr/0012 describes.
const (
	reasonResultTooLarge        = "result too large"
	reasonResultSchemaViolation = "result violates output schema"
)

// DefaultMaxResultBytes is the ceiling on one tool result when the
// configuration does not set one: one mebibyte.
//
// Both ends of the range this sits in are worth stating, because a number
// with no argument behind it is a number the next person moves at random.
//
// Why not larger: the harm being prevented is not only memory, it is the
// model's context window. A megabyte of JSON is on the order of a quarter
// of a million tokens -- at or past the whole budget of most contexts this
// gateway will ever serve. Past this point a single tool result *is* the
// context, and everything the analyst actually asked about has been pushed
// out of it. A ceiling of ten megabytes would not be a flood control; it
// would be a formality.
//
// Why not smaller: a refusal here is total, by design -- no truncation --
// so a ceiling set below real traffic does not degrade a query, it
// destroys it. A Logsearch or Docsearch page of a few hundred log lines
// runs to tens of kilobytes, sometimes low hundreds; a megabyte leaves
// roughly an order of magnitude of headroom over the largest legitimate
// answer this fleet produces. A control that breaks ordinary work is a
// control that gets raised to infinity by the first person on call.
//
// And why a default at all rather than a required setting: the limit is
// the control that works with no cooperation from any backend, so it has
// to apply to a gateway whose operator never heard of it.
const DefaultMaxResultBytes int64 = 1 << 20

// maxSchemaErrorDetail bounds how much of a validation failure's text is
// carried into the log line.
//
// A jsonschema failure quotes the offending instance, and the instance is
// upstream-authored data that may be most of a megabyte. Note this is a
// truncation of a *log line about a refusal*, which is a different thing
// from truncating a result: nothing here is handed to a model as though it
// were complete. The audit record carries no part of it at all -- Reason
// stays one of the two constants above.
const maxSchemaErrorDetail = 512

// resultSize is the number of bytes of backend-authored payload in one
// result.
//
// # What is measured, and why this and not something else
//
// The serialised content blocks plus the serialised structured content:
// exactly the two fields a backend fills and exactly the two that travel
// on to the client and into the model's context. Structured content is
// counted because SEP-2106 puts it in the same result, reaching the same
// context window; a ceiling that ignored it would be a ceiling a backend
// drives straight through while every counter reads zero.
//
// Both fields are already []byte by the time this runs -- the adapter had
// to serialise them once to produce a gateway.Result at all -- so
// measuring is two calls to len. Nothing is re-marshalled, nothing is
// decoded, and no second copy of the payload is made to weigh it. The
// alternatives all cost a pass over the data or worse: counting characters
// of text would mean decoding every content block, and measuring the
// client-facing wire form would mean marshalling the whole result twice,
// once to measure and once to send.
//
// The count therefore excludes the JSON-RPC envelope around it, which is a
// few dozen bytes and constant, and it counts base64 as the bytes it is --
// which is the right unit here, since base64 is what actually occupies the
// context.
//
// One consequence is worth stating because it is not guessable: a backend
// built with the Go SDK's generic AddTool sends the same payload twice,
// once as a JSON text block and once as structured content, and every lab
// backend in this fleet does exactly that. Such a result spends roughly
// twice its own size against the ceiling. That is the correct arithmetic
// -- both copies are transmitted and both land in the context -- but it
// means the effective allowance for those backends is about half the
// configured number.
//
// # What this does NOT bound, stated because the ADR is easy to over-read
//
// It does not bound the gateway's peak memory during the call. By the time
// this function can see anything, the SDK has already read the whole
// response off the wire and decoded it; refusing here stops the payload
// from being forwarded and retained, but it was allocated once. Bounding
// that would mean a limit inside the transport, which the SDK does not
// expose. What this does bound -- completely -- is what reaches the client
// and the model.
func resultSize(res Result) int64 {
	return int64(len(res.Content)) + int64(len(res.StructuredContent))
}

// checkResult decides whether a completed call's result may be passed on.
//
// The order is deliberate: size first, because it is two integer
// comparisons and because validating a payload the gateway has already
// decided to refuse is work done for an attacker.
//
// A refusal returns an error and no result. There is no truncating path
// and no partial one -- handing a model a document cut off mid-sentence,
// with nothing saying it was cut, is a lie told to the consumer of the
// data (ADR-0014).
func (g *Gateway) checkResult(rt routedTool, res Result) error {
	if size := resultSize(res); size > g.maxResultBytes {
		return fmt.Errorf("%w: %d bytes, limit is %d", ErrResultTooLarge, size, g.maxResultBytes)
	}
	return validateStructuredContent(rt.output, res)
}

// validateStructuredContent holds a result to the output schema its tool
// declared. schema is nil for every tool that declares none, and that is
// the common case -- see ToolDef.OutputSchema.
//
// # When there is no schema there is no check
//
// Not a weakened check, not a guessed one. The gateway does not remember
// the shape of the last response and hold the next one to it: a contract
// inferred from one sample and then enforced is how a system breaks on a
// Tuesday over a field that was always optional. Nothing in this package
// writes to a schema.
//
// # Why a tool-level error is exempt
//
// IsError means the tool ran and refused, and a refusal is not an instance
// of the success shape any output schema describes. Holding it to that
// schema would refuse every legitimate error a schema-declaring backend
// ever returns, which turns "your query was wrong" into "the gateway is
// broken" -- the false positive that gets a control switched off. The size
// ceiling still applies to it, because a refusal can flood a context as
// well as an answer can.
//
// # Why absent structured content fails
//
// A tool that publishes an output contract and then answers with nothing
// structured has not met it (SEP-2106), and reading the absence as
// "nothing to check" would make the control evadable by omission -- a
// swapped backend simply drops the field.
func validateStructuredContent(schema *jsonschema.Resolved, res Result) error {
	if schema == nil || res.IsError {
		return nil
	}
	if len(res.StructuredContent) == 0 {
		return fmt.Errorf("%w: the tool declares an output schema and the result carries no structured content", ErrResultSchemaViolation)
	}

	var instance any
	if err := json.Unmarshal(res.StructuredContent, &instance); err != nil {
		return fmt.Errorf("%w: structured content is not valid JSON", ErrResultSchemaViolation)
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("%w: %s", ErrResultSchemaViolation, clip(err.Error(), maxSchemaErrorDetail))
	}
	return nil
}

// resolveOutputSchema compiles a tool's declared output schema once, at
// discovery, and returns nil for a tool that declares none.
//
// Compiling here rather than per call is not only cheaper. It means the
// call path never has to answer "the contract itself will not parse", and
// a backend that publishes an uncheckable contract is refused loudly at
// Connect and at every Refresh instead of quietly at whatever hour an
// analyst first calls the tool. That is the same rule validateSchema
// applies to the input schema, and the same fail-closed reading: a
// declared contract nothing can check is not a contract.
//
// Remote $ref is refused as a side effect of passing no Loader, and that
// is correct rather than incidental: fetching a schema over the network,
// at a URL an upstream chose, would hand a backend a request the gateway
// makes on its behalf.
func resolveOutputSchema(raw json.RawMessage) (*jsonschema.Resolved, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, fmt.Errorf("%w: not a JSON schema document", ErrUnusableOutputSchema)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrUnusableOutputSchema, clip(err.Error(), maxSchemaErrorDetail))
	}
	return resolved, nil
}

// clip shortens s to at most n bytes and says so when it did, so a reader
// of the log is never left wondering whether a message ended or was cut.
// A rune split by the cut is dropped rather than left as broken UTF-8.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "... (truncated)"
}
