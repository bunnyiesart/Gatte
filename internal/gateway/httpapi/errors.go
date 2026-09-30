package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	"github.com/bunnyiesart/Gatte/internal/quota"
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
	// msgQuotaExhausted is deliberately the same wording as the audit
	// trail's reasonQuotaExhausted. An analyst reporting what they saw and
	// an operator grepping the trail for it should land on the same word;
	// two spellings of one event is how the two halves of an incident stop
	// being searchable together.
	msgQuotaExhausted = "quota exhausted"
	// msgConcurrencyLimited is the trail's reasonConcurrencyLimited, for
	// the same reason (design/adr/0035).
	msgConcurrencyLimited = "concurrency limited"
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
	// classQuotaExhausted is the caller's own per-analyst limit, spent for
	// this window (design/adr/0030 decision 7).
	//
	// It is a class of its own rather than folded into classForbidden or
	// classInternal, and that is this file's one substantive addition in a
	// while, so the argument is written out. What it discloses is a fact
	// about the caller, to the caller: that THEY have spent THEIR
	// allowance. It says nothing about which tools exist, which are under
	// suspicion, what other analysts have spent, or which account was
	// charged -- the message below is a constant, like every other one
	// here. The account name and the reset instant are in the gateway's
	// own error, which rejectCall writes to the operator's log; the trail
	// carries the analyst, the tool and the reason; and `mcp-gateway quota
	// usage` is where somebody looks up how much is left. None of that is
	// on the wire.
	//
	// Folding it into classForbidden would tell somebody whose role is
	// fine that their role is not, and the difference matters at 03:00:
	// one resolves itself when the window rolls over, the other needs a
	// reviewed change to a file. Folding it into classInternal would tell
	// them the gateway is broken when it is working exactly as configured.
	// This is the same exception access.ErrForbidden already is -- what
	// leaks is the operator's published policy, not the SOC's posture --
	// and note the bound it inherits: the class is distinguishable, the
	// text is not.
	classQuotaExhausted
	// classConcurrencyLimited is the caller's own per-analyst concurrency
	// cap, full at this moment (design/adr/0035). A class of its own on
	// exactly classQuotaExhausted's argument: a fact about the caller,
	// told to the caller, that resolves by itself -- here as soon as one
	// of their own calls ends.
	classConcurrencyLimited
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
	case classQuotaExhausted:
		return "quota-exhausted"
	case classConcurrencyLimited:
		return "concurrency-limited"
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
	case classQuotaExhausted:
		// 429, not 403: a spent allowance is a temporal condition that
		// resolves when the window rolls over, and every client library
		// and proxy in existence already reads 429 that way.
		return http.StatusTooManyRequests
	case classConcurrencyLimited:
		return http.StatusTooManyRequests
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
	case classQuotaExhausted:
		return msgQuotaExhausted
	case classConcurrencyLimited:
		return msgConcurrencyLimited
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
	case errors.Is(err, quota.ErrExhausted):
		return classQuotaExhausted
	case errors.Is(err, gateway.ErrConcurrencyLimited):
		return classConcurrencyLimited
	default:
		// Everything else -- ErrQuarantineUnavailable, ErrRegistryUnavailable,
		// ErrClosed, an audit-store failure, a transport error, a Go runtime
		// error -- is an internal error and says exactly that.
		//
		// quota.ErrUnavailable lands here, deliberately and without a case
		// of its own: a counter that could not be read or written is this
		// gateway's problem, and telling a caller which of its stores is
		// unwell hands them a map of what to break next. The refusal is
		// identical to any other internal failure from outside, and fully
		// distinguishable in the log and the trail, where reasonQuotaUnavailable
		// names it.
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
	if class == classUnauthenticated || class == classForbidden || class == classQuotaExhausted || class == classConcurrencyLimited {
		// JSON-RPC 2.0 has no authorization code; the spec's registry stops
		// at "invalid request". The code is not the signal here -- the
		// constant message is -- so the nearest standard code is used rather
		// than inventing one in the implementation-defined range.
		code = jsonrpc.CodeInvalidRequest
	}
	return &jsonrpc.Error{Code: int64(code), Message: class.message()}
}

// ------------------------------------------------ design/adr/0041: texts
//
// Two classes of answer are built here from the gateway's own STATE, never
// from an error's text: a backend that cannot take a granted, approved call
// (down, reconnecting, in maintenance, found dead during the call), and a
// live backend that failed it. They are the only texts on the wire that
// vary with more than the class, and every value that varies is a field the
// gateway filled from its own memory or from the operator's validated
// maintenance row (ADR-0041 item 3). The operator's message is quoted
// Go-style (strconv.Quote, so accents stay accents) so that no message can
// close the quote and continue as the gateway's words.

// OriginMetaKey is the reserved _meta key every result the gateway builds
// itself carries, with the value "gateway". An upstream result never
// carries it: toCallToolResult forwards no _meta of an upstream at all.
// A structural marker for clients that read _meta; it proves nothing to a
// model, which is why the instructions name gatte.status as the only
// authoritative source (ADR-0041 item 2).
const OriginMetaKey = "io.github.bunnyiesart.gatte/origin"

// msgServiceUnavailable is the one body of every ListTools failure after
// admission (ADR-0041 item 8): the suspension and an unreadable approval
// store answer the same bytes, so the caller learns "temporary" and not
// which part is unwell. The first sentence is the one a client shows.
const msgServiceUnavailable = "Gatte is temporarily unable to serve tools. This is not a problem with your request; retry in a few minutes or tell the user."

// notYourRequest is the sentence every unavailability text carries.
const notYourRequest = "This is not a problem with your request or its arguments: do not change them."

// statusHint closes the unavailability texts.
const statusHint = "Call gatte.status for the current state of your backends."

// stamp renders an instant the way every text here does: RFC 3339, UTC,
// seconds.
func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// quoteMessage is the operator's text inside the gateway's.
func quoteMessage(msg string) string { return strconv.Quote(msg) }

// untilPhrase is how a maintenance's announced end reads.
func untilPhrase(n *gateway.MaintenanceNotice) string {
	switch {
	case n.Until.IsZero():
		return "with no announced end"
	case n.UntilPassed:
		return "expected until " + stamp(n.Until) + " (that time has passed; the maintenance has not been ended yet)"
	default:
		return "expected until " + stamp(n.Until)
	}
}

// unavailableText is the text of an *gateway.UnavailableError.
func unavailableText(e *gateway.UnavailableError) string {
	name := strconv.Quote(e.Backend)
	switch e.State {
	case gateway.StateMaintenance:
		m := e.Maintenance
		if m == nil {
			m = &gateway.MaintenanceNotice{Since: e.Since}
		}
		return fmt.Sprintf("Gatte: the backend %s is in planned maintenance since %s, %s. Operator message: %s. %s Retry after the maintenance, or tell the user. %s",
			name, stamp(m.Since), untilPhrase(m), quoteMessage(m.Message), notYourRequest, statusHint)
	case gateway.StateDown:
		attempt := "no reconnect attempt yet"
		if !e.LastAttempt.IsZero() {
			attempt = "last reconnect attempt " + stamp(e.LastAttempt)
		}
		return fmt.Sprintf("Gatte: the backend %s is unavailable since %s (%s). Gatte is not reconnecting it automatically; an operator has to act. %s Tell the user. %s",
			name, stamp(e.Since), attempt, notYourRequest, statusHint)
	default:
		var parts []string
		if e.LastAttempt.IsZero() {
			parts = append(parts, "no reconnect attempt yet")
		} else {
			parts = append(parts, "last attempt "+stamp(e.LastAttempt))
		}
		if !e.NextAttempt.IsZero() {
			parts = append(parts, "next attempt around "+stamp(e.NextAttempt))
		}
		return fmt.Sprintf("Gatte: the backend %s is unavailable since %s; Gatte is reconnecting it (%s). %s Retry after the next attempt, or tell the user. %s",
			name, stamp(e.Since), strings.Join(parts, ", "), notYourRequest, statusHint)
	}
}

// backendFailedText is the text of an *gateway.BackendFailedError. It says
// where, not why: the backend's error is not forwarded, and it may well be
// `invalid params`, so it does not claim the request is right.
func backendFailedText(e *gateway.BackendFailedError) string {
	return fmt.Sprintf("Gatte: the backend %s failed this call. Gatte does not forward the backend's error, so it cannot say why: it may be the backend or the request. If it repeats with a request you believe is correct, tell the user. In gatte.status, \"up\" only means Gatte is connected to the backend.",
		strconv.Quote(e.Backend))
}

// gatewayNoticeText is the block appended to results while the whole
// gateway is in planned maintenance.
func gatewayNoticeText(n *gateway.MaintenanceNotice) string {
	return fmt.Sprintf("Gatte notice: the Gatte gateway is in planned maintenance since %s, %s. Operator message: %s. Calls are still being served; if one fails as unavailable, call gatte.status.",
		stamp(n.Since), untilPhrase(n), quoteMessage(n.Message))
}

// ------------------------------------------------ design/adr/0042: texts
//
// Four more answers a model can act on, for a granted, approved call the
// gateway refused or gave up on for a reason of its OWN: a result over the
// size ceiling, a call over the time ceiling, the caller's allowance spent,
// the caller's calls in flight at the cap. Every value in them is the
// operator's declared policy (a limit, a window, an account name) or the
// window arithmetic over it (when it resets) -- never a count of anybody's
// use and never a backend's words. Each says what happened, whether the
// request was at fault, and what to do next, in that order, because a
// client may cut the text and the model acts on the first sentence.

// durationPhrase renders a policy duration the way an operator writes it:
// "24h", "90m", "45s", never Go's "24h0m0s".
func durationPhrase(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d >= time.Minute && d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d >= time.Second && d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	default:
		return d.String()
	}
}

// bytesPhrase renders a size ceiling: bytes, and MiB when it is a round
// number of them.
func bytesPhrase(n int64) string {
	const mib = 1 << 20
	if n >= mib && n%mib == 0 {
		return fmt.Sprintf("%d bytes (%d MiB)", n, n/mib)
	}
	return fmt.Sprintf("%d bytes", n)
}

// tooLargeText: the call ran and its result was refused whole (ADR-0014).
func tooLargeText(e *gateway.ResultTooLargeError) string {
	return fmt.Sprintf("Gatte: the result of %s was larger than Gatte's limit of %s for one result, so Gatte did not deliver any of it. The call itself did run at the backend. Narrow the request (fewer results, a shorter time range, fewer fields) and call again; do not repeat it unchanged. If the call changes something at the backend, that change has already happened.",
		strconv.Quote(e.Tool), bytesPhrase(e.Limit))
}

// timeoutText: the gateway's per-call ceiling ran out (ADR-0025).
func timeoutText(e *gateway.CallTimeoutError) string {
	return fmt.Sprintf("Gatte: the backend %s did not answer this call within Gatte's limit of %s for one call, so Gatte stopped waiting. This limit is Gatte's, not an error in your arguments, and the backend may still have run the call. A narrower request (a shorter time range, fewer results) may finish in time: retry once with it, and if that also times out, tell the user.",
		strconv.Quote(e.Backend), durationPhrase(e.Limit))
}

// quotaText: the caller's own allowance on one account is spent (ADR-0030).
func quotaText(e *gateway.QuotaExhaustedError) string {
	b := e.Budget
	return fmt.Sprintf("Gatte: your quota on the %s account is spent: it allows %d call(s) per analyst every %s, and this window resets at %s. Do not retry this tool, or any tool that spends the same account, before then: every such call until the reset is refused the same way and spends nothing. Tell the user when it resets. Tools that do not spend this account keep working.",
		strconv.Quote(b.Provider), b.Limit, durationPhrase(b.Window), stamp(b.ResetsAt))
}

// concurrencyText: the caller's own calls in flight fill the cap (ADR-0035).
func concurrencyText(e *gateway.ConcurrencyLimitedError) string {
	return fmt.Sprintf("Gatte: you already have %d calls in flight through Gatte, counting every session of yours, and %d is the limit per analyst. This call was not run and spent no quota. Wait for one of your calls to finish, then retry this one with the same arguments.",
		e.Limit, e.Limit)
}

// msgAccountRefused is the body of the 403 a blocked subject gets at
// admission (ADR-0031, amended by ADR-0042 item 2). Admission has exactly
// one forbidden cause, so the text tells nothing the status did not; what
// it adds is the one thing the analyst needs: signing in again will not
// help. It deliberately does not say "blocked", nor why.
const msgAccountRefused = "Gatte refuses requests from this account. Signing in again will not change that: ask the SOC operator."

// pulledText is the JSON-RPC error message for a tool this very subject
// was listed and that is no longer served to them (ADR-0042 item 2). The
// same words whatever removed it -- a role change, a rewrite awaiting
// review, a deregistered backend -- so it says "no longer available",
// which the caller already knew the moment the call failed, and never
// which. A name this subject was never listed gets the SDK's own
// `unknown tool`, byte for byte, as before.
func pulledText(tool string) string {
	return fmt.Sprintf("Gatte: the tool %s was in your tool list but is no longer available to you. Do not retry it and do not try other names or spellings for it. Tell the user; if an operator makes it available again, reconnecting the Gatte server lists it again (in Claude Code: /mcp, then reconnect).",
		strconv.Quote(tool))
}

// pulledError is pulledText as the JSON-RPC error, with the SDK's code for
// an unknown tool: the call did not reach any tool.
func pulledError(tool string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: pulledText(tool)}
}

// honestResult is the tool result for a call the gateway answers with a
// backend's state or its own limit, or nil when err is none of those.
func honestResult(err error) *mcp.CallToolResult {
	var (
		ue   *gateway.UnavailableError
		bf   *gateway.BackendFailedError
		tl   *gateway.ResultTooLargeError
		to   *gateway.CallTimeoutError
		qe   *gateway.QuotaExhaustedError
		cl   *gateway.ConcurrencyLimitedError
		text string
		gw   *gateway.MaintenanceNotice
	)
	switch {
	case errors.As(err, &ue):
		text, gw = unavailableText(ue), ue.Gateway
	case errors.As(err, &bf):
		text, gw = backendFailedText(bf), bf.Gateway
	case errors.As(err, &tl):
		text, gw = tooLargeText(tl), tl.Gateway
	case errors.As(err, &to):
		text, gw = timeoutText(to), to.Gateway
	case errors.As(err, &qe):
		text, gw = quotaText(qe), qe.Gateway
	case errors.As(err, &cl):
		text, gw = concurrencyText(cl), cl.Gateway
	default:
		return nil
	}
	res := &mcp.CallToolResult{
		Meta:    mcp.Meta{OriginMetaKey: "gateway"},
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
	}
	appendNotice(res, gw)
	return res
}

// appendNotice adds the gateway's maintenance notice as a last text block.
// Never into structuredContent: an upstream's output schema governs that.
func appendNotice(res *mcp.CallToolResult, n *gateway.MaintenanceNotice) {
	if n == nil {
		return
	}
	res.Content = append(res.Content, &mcp.TextContent{Text: gatewayNoticeText(n)})
}

// writeServiceUnavailable answers a ListTools failure after admission.
func writeServiceUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", "60")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = fmt.Fprintln(w, msgServiceUnavailable)
}

// writeAccountRefused answers a subject admission refused as forbidden --
// which today means blocked -- with 403 and msgAccountRefused, plus the
// operator's configured contact line when there is one. No
// WWW-Authenticate: this is not a request to authenticate (ADR-0031 §3).
func writeAccountRefused(w http.ResponseWriter, contact string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	body := msgAccountRefused
	if contact != "" {
		body += " Contact: " + strconv.Quote(contact) + "."
	}
	_, _ = fmt.Fprintln(w, body)
}
