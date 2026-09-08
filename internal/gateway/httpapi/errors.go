package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
)

// This file is the one place an internal error is turned into something a
// client is allowed to see, and it is written so that reviewing "what can
// leak" means reviewing this file.
//
// The errors arriving here are deliberately informative. access.Policy's
// forbidden error interpolates the caller's `sub` claim; the gateway's
// quarantine error names the route and the upstream; a dial failure carries
// whatever the network stack said, which in a SOC is an internal hostname
// and port. Every one of those is right for the audit trail and the
// operator's log, and wrong on the wire.
//
// So nothing derived from an error's *text* ever reaches a client. An error
// is reduced to a class, and a class maps to one constant string. The only
// caller-varying value that ever appears in a response is the tool name the
// caller themselves asked for -- which tells them nothing they did not
// already type.

// The constant messages. There is one per class and it never changes with
// the cause, so two genuinely different internal failures of the same class
// are indistinguishable from outside.
const (
	msgUnauthenticated  = "authentication required"
	msgForbidden        = "forbidden"
	msgInternal         = "internal error"
	msgMethodNotAllowed = "method not allowed"
	// msgUnknownToolNoName is used when there is no caller-supplied name to
	// echo. It is never richer than this.
	msgUnknownToolNoName = "unknown tool"
)

// failureClass is the entire vocabulary this package has for talking to a
// client about a failure.
type failureClass int

const (
	// classInternal is the default, and the default matters: an error this
	// package does not recognise is reported as an internal error, never
	// passed through. Adding a new sentinel upstream cannot open a leak
	// here; at worst it is reported as a 500 until someone classifies it.
	classInternal failureClass = iota
	classUnauthenticated
	classForbidden
	classUnknownTool
	classMethodNotAllowed
)

// String names the class for the operator's log. It is never sent to a
// client.
func (c failureClass) String() string {
	switch c {
	case classUnauthenticated:
		return "unauthenticated"
	case classForbidden:
		return "forbidden"
	case classUnknownTool:
		return "unknown-tool"
	case classMethodNotAllowed:
		return "method-not-allowed"
	default:
		return "internal"
	}
}

// status is the HTTP status this class maps to.
func (c failureClass) status() int {
	switch c {
	case classUnauthenticated:
		return http.StatusUnauthorized
	case classForbidden:
		return http.StatusForbidden
	case classUnknownTool:
		return http.StatusNotFound
	case classMethodNotAllowed:
		return http.StatusMethodNotAllowed
	default:
		return http.StatusInternalServerError
	}
}

// message is the constant body text for this class.
func (c failureClass) message() string {
	switch c {
	case classUnauthenticated:
		return msgUnauthenticated
	case classForbidden:
		return msgForbidden
	case classUnknownTool:
		return msgUnknownToolNoName
	case classMethodNotAllowed:
		return msgMethodNotAllowed
	default:
		return msgInternal
	}
}

// classify reduces any internal error to a class.
//
// The mapping follows internal/access's deliberate 401/403 split
// (CONCEPTS.md section 3.3): "I don't know who you are" and "I know who you
// are and you may not" must not collapse into each other, in either
// direction.
//
// gateway.ErrToolQuarantined is mapped to the same class as
// gateway.ErrUnknownTool. gateway.Dispatch already collapses the two before
// returning -- see its doc comment on why a caller must not be able to tell
// "no such tool" from "that tool exists but is not approved", which would
// be an oracle for reading the SOC's security posture tool by tool. The
// mapping is repeated here so that if some future path ever does return the
// quarantine sentinel outward, it still cannot be distinguished at the
// boundary.
func classify(err error) failureClass {
	switch {
	case err == nil:
		return classInternal
	case errors.Is(err, access.ErrUnauthenticated):
		return classUnauthenticated
	case errors.Is(err, access.ErrForbidden):
		return classForbidden
	case errors.Is(err, gateway.ErrUnknownTool), errors.Is(err, gateway.ErrToolQuarantined):
		return classUnknownTool
	default:
		// Everything else -- ErrQuarantineUnavailable, ErrRegistryUnavailable,
		// ErrClosed, an audit-store failure, a transport error, a Go runtime
		// error -- is an internal error and says exactly that.
		return classInternal
	}
}

// writeGeneric writes the constant response for a class.
//
// It writes plain text rather than JSON on purpose: these responses are
// produced before or outside the JSON-RPC layer, where a client has no
// message ID to correlate a JSON-RPC error against, and a short text body
// with nosniff is what the SDK's own pre-protocol errors look like.
//
// The body is a constant per class, so a test can assert byte equality
// across genuinely different causes.
func writeGeneric(w http.ResponseWriter, class failureClass) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(class.status())
	_, _ = fmt.Fprintln(w, class.message())
}

// jsonRPCError is the client-facing error for a failed tool call.
//
// A tool call fails inside the MCP protocol, so its failure travels as a
// JSON-RPC error object rather than an HTTP status -- the streamable
// transport answers 200 and puts the error in the body. The class still
// governs what is said; only the envelope differs.
//
// The unknown-tool case reproduces the SDK's own wording and code for a
// tool that is not registered, byte for byte. That is deliberate: a tool
// outside the caller's role is never registered on their server, so the SDK
// answers that case itself, and a *different* message from this path would
// let a caller tell "the gateway refused this" from "your server has no
// such tool" -- reintroducing exactly the distinction gateway.Dispatch
// works to erase. The tool name is echoed because the caller supplied it.
func jsonRPCError(class failureClass, tool string) error {
	if class == classUnknownTool {
		message := msgUnknownToolNoName
		if tool != "" {
			message = fmt.Sprintf("unknown tool %q", tool)
		}
		return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: message}
	}

	code := jsonrpc.CodeInternalError
	if class == classUnauthenticated || class == classForbidden {
		// JSON-RPC 2.0 has no authorization code; the spec's registry stops
		// at "invalid request". The code is not the signal here -- the
		// constant message is -- so the nearest standard code is used rather
		// than inventing one in the implementation-defined range.
		code = jsonrpc.CodeInvalidRequest
	}
	return &jsonrpc.Error{Code: int64(code), Message: class.message()}
}
