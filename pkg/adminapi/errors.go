package adminapi

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes (api/admin.openapi.yaml, ErrorCode). The set is OPEN: a
// client handles a code it does not know by the HTTP status.
const (
	CodeBadRequest            = "bad_request"
	CodeInvalidArgument       = "invalid_argument"
	CodeFingerprintRequired   = "fingerprint_required"
	CodeGroupNotMapped        = "group_not_mapped"
	CodePeerUnattributable    = "peer_unattributable"
	CodeForbiddenPeer         = "forbidden_peer"
	CodeBrowserRequestRefused = "browser_request_refused"
	CodeNotFound              = "not_found"
	CodeUnknownRoute          = "unknown_route"
	CodeWrongSocket           = "wrong_socket"
	CodeMethodNotAllowed      = "method_not_allowed"
	CodeFingerprintMismatch   = "fingerprint_mismatch"
	CodeFingerprintMoved      = "fingerprint_moved"
	CodeDefinitionUnavailable = "definition_unavailable"
	CodeChangedNotRevocable   = "changed_not_revocable"
	CodeAccountExists         = "account_exists"
	CodePayloadTooLarge       = "payload_too_large"
	CodeConnectNotConfigured  = "connect_not_configured"
	CodeCorruptState          = "corrupt_state"
	CodeInternal              = "internal"
	CodeConfigUnavailable     = "config_unavailable"
	CodeStoreBusy             = "store_busy"
	CodeAccountNotManaged     = "account_not_managed"
	// Since 1.2.0 (design/adr/0043).
	CodeManifestRequired = "manifest_required"
	CodeManifestMismatch = "manifest_mismatch"
	// Since 1.5.0 (design/adr/0048): clearing a sensitive tool.
	// not_sensitive: the tool is safe, served on approval alone, nothing
	// to clear. not_approved: no approved baseline to clear at (pending or
	// changed). no_non_read_grant: no role marked non_read names the tool
	// in `tools`; `details.callable_by` lists the roles that cover it
	// without reaching it.
	CodeNotSensitive   = "not_sensitive"
	CodeNotApproved    = "not_approved"
	CodeNoNonReadGrant = "no_non_read_grant"
)

// codeStatus is the HTTP status each known code travels with.
var codeStatus = map[string]int{
	CodeBadRequest:            http.StatusBadRequest,
	CodeInvalidArgument:       http.StatusBadRequest,
	CodeFingerprintRequired:   http.StatusBadRequest,
	CodeGroupNotMapped:        http.StatusBadRequest,
	CodePeerUnattributable:    http.StatusForbidden,
	CodeForbiddenPeer:         http.StatusForbidden,
	CodeBrowserRequestRefused: http.StatusForbidden,
	CodeNotFound:              http.StatusNotFound,
	CodeUnknownRoute:          http.StatusNotFound,
	CodeWrongSocket:           http.StatusNotFound,
	CodeMethodNotAllowed:      http.StatusMethodNotAllowed,
	CodeFingerprintMismatch:   http.StatusConflict,
	CodeFingerprintMoved:      http.StatusConflict,
	CodeDefinitionUnavailable: http.StatusConflict,
	CodeChangedNotRevocable:   http.StatusConflict,
	CodeAccountExists:         http.StatusConflict,
	CodePayloadTooLarge:       http.StatusRequestEntityTooLarge,
	CodeConnectNotConfigured:  http.StatusNotFound,
	CodeCorruptState:          http.StatusInternalServerError,
	CodeInternal:              http.StatusInternalServerError,
	CodeConfigUnavailable:     http.StatusServiceUnavailable,
	CodeStoreBusy:             http.StatusServiceUnavailable,
	CodeAccountNotManaged:     http.StatusForbidden,
	CodeManifestRequired:      http.StatusBadRequest,
	CodeManifestMismatch:      http.StatusConflict,
	CodeNotSensitive:          http.StatusConflict,
	CodeNotApproved:           http.StatusConflict,
	CodeNoNonReadGrant:        http.StatusConflict,
}

// StatusOf returns the HTTP status of a known code, 500 otherwise.
func StatusOf(code string) int {
	if s, ok := codeStatus[code]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// Codes returns every error code this package knows.
func Codes() []string {
	out := make([]string, 0, len(codeStatus))
	for c := range codeStatus {
		out = append(out, c)
	}
	return out
}

// Error is a refusal from the backend. Branch on Code; show Message.
type Error struct {
	// Status is the HTTP status it came with.
	Status  int            `json:"-"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Error implements error.
func (e *Error) Error() string {
	return fmt.Sprintf("gatte admin: %s: %s", e.Code, e.Message)
}

// ErrorResponse is the body of every failure.
type ErrorResponse struct {
	Error *Error `json:"error"`
}

// NewError builds an Error with the status of its code.
func NewError(code, format string, args ...any) *Error {
	return &Error{Status: StatusOf(code), Code: code, Message: fmt.Sprintf(format, args...)}
}

// With returns e with one detail added.
func (e *Error) With(key string, value any) *Error {
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	e.Details[key] = value
	return e
}

// IsCode reports whether err is an *Error carrying code.
func IsCode(err error, code string) bool {
	var ae *Error
	return errors.As(err, &ae) && ae.Code == code
}

// ErrImpostor is returned when the process serving a socket is not the one
// the client requires (design/adr/0040 §4).
var ErrImpostor = errors.New("gatte admin: the process serving this socket is not the expected one; refusing to talk to it")
