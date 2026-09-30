package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// FeatureServeControl: POST /v1/reload, POST /v1/upstreams/redial and GET
// /v1/serve-requests/{id} (design/adr/0044), since 1.3.0.
const FeatureServeControl = "serve_control"

// CodeServeNotRunning: no gateway process (`serve`) could be rung, so the
// request was not filed (503). Since 1.3.0.
const CodeServeNotRunning = "serve_not_running"

// Kinds of a ServeRequest.
const (
	ServeKindReload = "reload"
	ServeKindRedial = "redial"
)

// States of a ServeRequest.
const (
	// ServeStatePending: filed and rung; serve has not answered yet. Read
	// it again with GET /v1/serve-requests/{id}.
	ServeStatePending = "pending"
	ServeStateDone    = "done"
)

// Outcomes of a done ServeRequest.
const (
	ServeOutcomeApplied = "applied"
	ServeOutcomeRefused = "refused"
)

// Refusal codes of a refused ServeRequest. Open set.
const (
	// RefusalInvalidConfig: the file does not load or does not validate;
	// the policy in force is kept.
	RefusalInvalidConfig = "invalid_config"
	// RefusalQuotaMismatch: the new [quota] and the registry disagree, as
	// at boot; the policy in force is kept.
	RefusalQuotaMismatch = "quota_mismatch"
	// RefusalRegistryUnavailable: the registry could not be read, so the
	// new quota could not be checked against it.
	RefusalRegistryUnavailable = "registry_unavailable"
	// RefusalNotServable: the backend named by a redial is not servable.
	RefusalNotServable = "not_servable"
	// RefusalHeldBack: dials are held back (quota and registry disagree);
	// a redial would close the backend and not bring it back.
	RefusalHeldBack = "held_back"
	// RefusalSuperseded: serve restarted before answering; the restart
	// read the whole file and dialled every backend.
	RefusalSuperseded = "superseded_by_restart"
	// RefusalNotRung: the request was filed and serve could not be rung.
	RefusalNotRung = "serve_not_rung"
)

// RedialRequest names the backend to drop and dial again.
type RedialRequest struct {
	Upstream string `json:"upstream"`
}

// RoleChange is what one role reaches before and after a reload, over the
// tools the gateway routes now.
type RoleChange struct {
	Role    string   `json:"role"`
	Added   bool     `json:"added"`
	Removed bool     `json:"removed"`
	Gained  []string `json:"gained"`
	Lost    []string `json:"lost"`
}

// GroupChange is one [group_to_role] key whose role changed; from or to
// is empty for a group added or removed.
type GroupChange struct {
	Group string `json:"group"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
}

// QuotaChange is one account of [quota] added, removed or changed.
type QuotaChange struct {
	Account string `json:"account"`
	Change  string `json:"change"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
}

// ReloadChanges is the diff of a reload: what it applies, and the keys
// that differ from the file serve booted with and are NOT applied until a
// restart.
type ReloadChanges struct {
	Roles            []RoleChange  `json:"roles"`
	Groups           []GroupChange `json:"groups"`
	Quota            []QuotaChange `json:"quota"`
	FreeToolsChanged bool          `json:"free_tools_changed"`
	NotReloaded      []string      `json:"not_reloaded"`
}

// RedialOutcome is what a redial found and left.
type RedialOutcome struct {
	// WasConnected is false for a backend with no live connection: the
	// round dialled it without anything to drop.
	WasConnected bool `json:"was_connected"`
	// Live says whether the backend is live after the round that
	// followed; Cause says why not.
	Live  bool   `json:"live"`
	Cause string `json:"cause,omitempty"`
}

// ServeRequest is one request to the running gateway process, as filed and,
// once done, as answered.
type ServeRequest struct {
	ID          int64     `json:"id"`
	Kind        string    `json:"kind"`
	Upstream    string    `json:"upstream,omitempty"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	State       string    `json:"state"`
	// Set once State is done.
	Outcome string     `json:"outcome,omitempty"`
	Refusal string     `json:"refusal,omitempty"`
	DoneAt  *time.Time `json:"done_at,omitempty"`
	// Reload is the diff of a reload, applied or refused (a refused one
	// carries the diff it would have applied when the file loaded).
	Reload *ReloadChanges `json:"reload,omitempty"`
	Redial *RedialOutcome `json:"redial,omitempty"`
	// Recorded and Audit are the operator row serve wrote for it.
	Recorded bool         `json:"recorded"`
	Audit    *OperatorRow `json:"audit,omitempty"`
	Warnings []Warning    `json:"warnings,omitempty"`
	Messages []string     `json:"messages"`
}

// Reload asks the running gateway to re-read its configuration file and
// apply [[role]], [group_to_role] and [quota].
func (c *Client) Reload(ctx context.Context) (ServeRequest, error) {
	var out ServeRequest
	err := c.do(ctx, http.MethodPost, "/v1/reload", nil, struct{}{}, &out)
	return out, err
}

// RedialUpstream asks the running gateway to drop and dial one backend
// again.
func (c *Client) RedialUpstream(ctx context.Context, r RedialRequest) (ServeRequest, error) {
	var out ServeRequest
	err := c.do(ctx, http.MethodPost, "/v1/upstreams/redial", nil, r, &out)
	return out, err
}

// ServeRequestByID reads a request back, for one that was still pending.
func (c *Client) ServeRequestByID(ctx context.Context, id int64) (ServeRequest, error) {
	var out ServeRequest
	err := c.do(ctx, http.MethodGet, "/v1/serve-requests/"+strconv.FormatInt(id, 10), nil, nil, &out)
	return out, err
}

func init() { codeStatus[CodeServeNotRunning] = http.StatusServiceUnavailable }
