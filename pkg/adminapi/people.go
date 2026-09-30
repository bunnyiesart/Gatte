package adminapi

import (
	"context"
	"net/http"
	"net/url"
)

// Audit search and people lifecycle (design/adr/0046), since 1.4.0. A front
// calls each only when WhoAmI.Features lists its feature.
const (
	// FeatureAuditFilters: GET /v1/audit takes tool, server and until.
	FeatureAuditFilters = "audit_filters"
	// FeatureBlockUntil: BlockRequest.until, and Block.until and
	// Block.expired in the blocklist; the gateway records an expiry as
	// (access block expired).
	FeatureBlockUntil = "block_until"
	// FeatureAccountDelete: DELETE /v1/accounts/{username} on the accounts
	// socket.
	FeatureAccountDelete = "account_delete"
	// FeatureOffboard: POST /v1/accounts/{username}/offboard on the
	// accounts socket.
	FeatureOffboard = "offboard"
)

// WarnOffboardIncomplete: an offboard did part of its work, which is in
// force, and not the rest; the message says which part is missing.
const WarnOffboardIncomplete = "offboard_incomplete"

// OffboardRequest is the body of POST /v1/accounts/{username}/offboard.
type OffboardRequest struct {
	// Subject is the person's analyst identity, as the trail's
	// analyst_identity carries it (the token's sub): the gateway block.
	// Empty when the person never used the gateway; the answer then says
	// no block was placed.
	Subject string `json:"subject,omitempty"`
	// Reason is free text; the backend prefixes the front tag.
	Reason string `json:"reason,omitempty"`
}

// OffboardResult answers an offboard. Rows are the operator rows written,
// in order: (access block), (account disable), then the summary
// (account offboard). Remaining is what the operator still has to do by
// hand: it is never empty.
type OffboardResult struct {
	ActionResult
	Account   Account       `json:"account"`
	Subject   string        `json:"subject,omitempty"`
	Blocked   bool          `json:"blocked"`
	Disabled  bool          `json:"disabled"`
	Rows      []OperatorRow `json:"rows"`
	Remaining []string      `json:"remaining"`
}

// DeleteAccount removes the account from the identity provider's users
// file. The trail keeps every row it ever wrote.
func (c *Client) DeleteAccount(ctx context.Context, username string) (AccountResult, error) {
	var v AccountResult
	return v, c.do(ctx, http.MethodDelete, "/v1/accounts/"+url.PathEscape(username), nil, nil, &v)
}

// OffboardAccount blocks the person in the gateway and disables their
// account, in one call.
func (c *Client) OffboardAccount(ctx context.Context, username string, r OffboardRequest) (OffboardResult, error) {
	var v OffboardResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts/"+url.PathEscape(username)+"/offboard", nil, r, &v)
}
