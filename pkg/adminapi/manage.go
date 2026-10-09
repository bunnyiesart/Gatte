package adminapi

import (
	"context"
	"net/http"
	"net/url"
)

// The console manages everything (design/adr/0050), since 1.6.0: http
// backends registered, signed and deregistered, the vault's values and the
// roles file written, through this API.
//
// FeatureConsoleManages is listed in WhoAmI.Features only when the backend
// serves these operations AND the configuration turns them on ([admin]
// console_manages = true). A front shows the buttons only when it is
// listed; with it absent every one of them answers feature_disabled (or,
// from an older backend, unknown_route).
const FeatureConsoleManages = "console_manages"

// CodeFeatureDisabled: the operation exists and the configuration does not
// turn it on. details.key names the key: "admin.console_manages" for every
// operation of FeatureConsoleManages, "roles_file" for the roles text when
// the configuration keeps its roles in the main file. Since 1.6.0.
const CodeFeatureDisabled = "feature_disabled"

// CodeUpstreamExists: POST /v1/upstreams names a backend already
// registered (409). Deregister it first, or choose another name. Since
// 1.6.0.
const CodeUpstreamExists = "upstream_exists"

// MaxSecretValueBytes bounds one vault value (PUT /v1/secrets/{name}).
const MaxSecretValueBytes = 64 << 10

// MaxUpstreamDocumentBytes bounds an OpenAPI document sent in
// RegisterUpstreamRequest.OpenAPIDocument: the ingestion's own ceiling.
const MaxUpstreamDocumentBytes = 4 << 20

// MaxRolesTextBytes bounds the roles file a PUT /v1/roles writes.
const MaxRolesTextBytes = 1 << 20

func init() {
	codeStatus[CodeFeatureDisabled] = http.StatusForbidden
	codeStatus[CodeUpstreamExists] = http.StatusConflict
}

// UpstreamAuth is an http entry's credential-injection descriptor: where
// the one secret it declares goes, never a value. Kind is "none",
// "bearer", "header" or "query"; Name is the header or query parameter for
// the last two; Secret is the vault NAME injected there.
type UpstreamAuth struct {
	Kind   string `json:"kind"`
	Name   string `json:"name,omitempty"`
	Secret string `json:"secret,omitempty"`
}

// UpstreamOperation is one operation of an http entry's frozen set: one
// tool, by the class the method gives it (ClassSafe or ClassSensitive).
type UpstreamOperation struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Class  string `json:"class"`
}

// UpstreamDetail answers GET /v1/upstreams/{name}: the entry as the list
// shows it, plus, for http, its descriptor and operation set, plus every
// tool the quarantine holds under its name.
type UpstreamDetail struct {
	Upstream
	Auth *UpstreamAuth `json:"auth,omitempty"`
	// Operations is the frozen set, sorted by name; OperationsSHA256 is
	// the digest the signature covers. http only.
	Operations       []UpstreamOperation `json:"operations,omitempty"`
	OperationsSHA256 string              `json:"operations_sha256,omitempty"`
	OperationsError  string              `json:"operations_error,omitempty"`
	Tools            []Tool              `json:"tools"`
}

// RegisterUpstreamRequest is the body of POST /v1/upstreams: an http
// backend from its OpenAPI document, as `upstream register -transport
// http` takes it. Exactly one of OpenAPIURL (fetched once, under the
// adapter's egress guard) and OpenAPIDocument (the document itself) is
// given. AuthKind is "bearer", "header", "query" or "none"; left empty,
// the document's securitySchemes may derive one. KeyName is the vault NAME
// of the one secret a keyed entry injects (the CLI's -env).
type RegisterUpstreamRequest struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	OpenAPIURL      string `json:"openapi_url,omitempty"`
	OpenAPIDocument string `json:"openapi_document,omitempty"`
	AuthKind        string `json:"auth_kind,omitempty"`
	AuthName        string `json:"auth_name,omitempty"`
	KeyName         string `json:"key_name,omitempty"`
}

// RegisterUpstreamResult answers POST /v1/upstreams: the ingestion's
// report. Tools are the operations the document produced, each with its
// class; Skipped and IngestWarnings quote the document (escaped); Auth is
// the effective descriptor, and AuthDerived says it came from the
// document, not from the request. Signature is the entry's signature state
// right after registering ("no", or "yes"/"INVALID" when one was left
// under the name).
type RegisterUpstreamResult struct {
	ActionResult
	Name           string              `json:"name"`
	URL            string              `json:"url"`
	Source         string              `json:"source"`
	FetchedBytes   int                 `json:"fetched_bytes,omitempty"`
	BasePath       string              `json:"base_path,omitempty"`
	Auth           UpstreamAuth        `json:"auth"`
	AuthDerived    bool                `json:"auth_derived"`
	Tools          []UpstreamOperation `json:"tools"`
	Skipped        []string            `json:"skipped"`
	IngestWarnings []string            `json:"ingest_warnings"`
	Signature      string              `json:"signature"`
}

// DeregisterRequest is the body of DELETE /v1/upstreams/{name}: the name
// again, as the operator typed it. A mismatch is refused, because the
// operation removes the approvals with the entry.
type DeregisterRequest struct {
	Confirm string `json:"confirm"`
}

// DeregisterResult answers DELETE /v1/upstreams/{name}. Registered is
// whether the registry had the entry; the signature, the quarantine and
// the health state keyed by the name are removed either way.
type DeregisterResult struct {
	ActionResult
	Name             string `json:"name"`
	Registered       bool   `json:"registered"`
	SignatureRemoved bool   `json:"signature_removed"`
	ToolsForgotten   int    `json:"tools_forgotten"`
}

// SignResult answers POST /v1/upstreams/{name}/sign. KeyFingerprint is the
// signing key's public fingerprint; Trusted says it is in
// signer.trusted_keys, without which the gateway does not serve the entry.
// Messages carry what `sign` printed.
type SignResult struct {
	ActionResult
	Name           string `json:"name"`
	KeyFingerprint string `json:"key_fingerprint"`
	Trusted        bool   `json:"trusted"`
}

// Secret is one vault name: InVault says the vault holds a value under it
// (never returned), DeclaredBy the registered entries that declare it.
type Secret struct {
	Name       string   `json:"name"`
	InVault    bool     `json:"in_vault"`
	DeclaredBy []string `json:"declared_by,omitempty"`
}

// SecretList answers GET /v1/secrets. With RegistryRead false the registry
// could not be read (Problems says why): only the vault's names are listed
// and DeclaredBy is absent; GET /v1/upstreams on the operator socket has
// each entry's env_var_names.
type SecretList struct {
	Secrets      []Secret  `json:"secrets"`
	RegistryRead bool      `json:"registry_read"`
	Problems     []Problem `json:"problems,omitempty"`
}

// SecretValue is the body of PUT /v1/secrets/{name}. The value is written
// once and never returned, recorded or logged.
type SecretValue struct {
	Value string `json:"value"`
}

// SecretResult answers a secret set or delete. Existed says the vault held
// a value under the name before.
type SecretResult struct {
	ActionResult
	Name    string `json:"name"`
	Existed bool   `json:"existed"`
}

// RolesText answers GET /v1/roles: the roles file as it is on disk.
type RolesText struct {
	Text   string `json:"text"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// RolesRequest is the body of PUT /v1/roles.
type RolesRequest struct {
	Text string `json:"text"`
}

// RolesResult answers PUT /v1/roles. The file is written and NOT applied:
// call POST /v1/reload on the operator socket next (ReloadNeeded).
type RolesResult struct {
	ActionResult
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	ReloadNeeded bool   `json:"reload_needed"`
}

// GetUpstream returns one registered entry in detail (1.6.0).
func (c *Client) GetUpstream(ctx context.Context, name string) (UpstreamDetail, error) {
	var v UpstreamDetail
	return v, c.do(ctx, http.MethodGet, "/v1/upstreams/"+url.PathEscape(name), nil, nil, &v)
}

// RegisterUpstream registers an http backend from its OpenAPI document
// (1.6.0, FeatureConsoleManages).
func (c *Client) RegisterUpstream(ctx context.Context, r RegisterUpstreamRequest) (RegisterUpstreamResult, error) {
	var v RegisterUpstreamResult
	return v, c.do(ctx, http.MethodPost, "/v1/upstreams", nil, r, &v)
}

// DeregisterUpstream removes an entry and everything keyed by its name;
// confirm repeats the name (1.6.0, FeatureConsoleManages).
func (c *Client) DeregisterUpstream(ctx context.Context, name, confirm string) (DeregisterResult, error) {
	var v DeregisterResult
	return v, c.do(ctx, http.MethodDelete, "/v1/upstreams/"+url.PathEscape(name), nil, DeregisterRequest{Confirm: confirm}, &v)
}

// SignUpstream signs an entry with the root signing key, on the accounts
// socket (1.6.0, FeatureConsoleManages).
func (c *Client) SignUpstream(ctx context.Context, name string) (SignResult, error) {
	var v SignResult
	return v, c.do(ctx, http.MethodPost, "/v1/upstreams/"+url.PathEscape(name)+"/sign", nil, struct{}{}, &v)
}

// ListSecrets returns the vault's names, never a value (1.6.0,
// FeatureConsoleManages).
func (c *Client) ListSecrets(ctx context.Context) (SecretList, error) {
	var v SecretList
	return v, c.do(ctx, http.MethodGet, "/v1/secrets", nil, nil, &v)
}

// SetSecret writes one vault value (1.6.0, FeatureConsoleManages). A
// connected backend keeps the old value until it is redialled.
func (c *Client) SetSecret(ctx context.Context, name, value string) (SecretResult, error) {
	var v SecretResult
	return v, c.do(ctx, http.MethodPut, "/v1/secrets/"+url.PathEscape(name), nil, SecretValue{Value: value}, &v)
}

// DeleteSecret removes one vault value (1.6.0, FeatureConsoleManages).
func (c *Client) DeleteSecret(ctx context.Context, name string) (SecretResult, error) {
	var v SecretResult
	return v, c.do(ctx, http.MethodDelete, "/v1/secrets/"+url.PathEscape(name), nil, nil, &v)
}

// GetRoles returns the roles file's text (1.6.0, FeatureConsoleManages).
func (c *Client) GetRoles(ctx context.Context) (RolesText, error) {
	var v RolesText
	return v, c.do(ctx, http.MethodGet, "/v1/roles", nil, nil, &v)
}

// PutRoles validates and writes the roles file; it does not apply it --
// call Reload on the operator socket next (1.6.0, FeatureConsoleManages).
func (c *Client) PutRoles(ctx context.Context, text string) (RolesResult, error) {
	var v RolesResult
	return v, c.do(ctx, http.MethodPut, "/v1/roles", nil, RolesRequest{Text: text}, &v)
}
