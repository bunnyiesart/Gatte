package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/bunnyiesart/Gatte/internal/peercred"
)

// Client talks to one management socket. It is safe for concurrent use.
//
// It has no way to be given request headers, so a web front cannot forward
// a browser's Origin or Cookie through it: the front terminates the
// browser itself (pkg/frontkit) and calls the API as its own process.
type Client struct {
	socket    string
	front     string
	timeout   time.Duration
	serverUID []uint32
	http      *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithFront names the calling front ([a-z0-9._-], at most 32 bytes). It
// becomes the [NAME] tag of the operator rows this client causes. Display
// only; it decides nothing.
func WithFront(name string) Option { return func(c *Client) { c.front = name } }

// WithServerUID pins the uids allowed to serve the operator socket; the
// client refuses a server with any other (ErrImpostor). Under systemd the
// kernel reports systemd, uid 0, which created the socket.
func WithServerUID(uids ...uint32) Option {
	return func(c *Client) { c.serverUID = append([]uint32(nil), uids...) }
}

// withAccountsServerUID replaces uid 0 as the accounts socket's required
// server. Tests only (export_test.go): nothing outside a test has a reason
// to accept an accounts backend that is not root.
func withAccountsServerUID(uid uint32) Option {
	return func(c *Client) { c.serverUID = []uint32{uid} }
}

// WithTimeout bounds each call (default 30 s).
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// New returns a client of the operator socket at path.
func New(path string, opts ...Option) *Client { return newClient(path, nil, opts) }

// NewAccounts returns a client of the accounts socket at path. It refuses
// to talk to a server that is not uid 0 (ErrImpostor), so a fake socket
// another account put in place cannot collect account creations.
func NewAccounts(path string, opts ...Option) *Client {
	return newClient(path, []uint32{0}, opts)
}

func newClient(path string, serverUID []uint32, opts []Option) *Client {
	c := &Client{socket: path, timeout: 30 * time.Second, serverUID: serverUID}
	for _, o := range opts {
		o(c)
	}
	c.http = &http.Client{Transport: &http.Transport{
		DialContext:            c.dial,
		MaxIdleConns:           2,
		IdleConnTimeout:        20 * time.Second,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 16 << 10,
	}}
	return c
}

// dial connects to the socket and checks who serves it.
func (c *Client) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, err
	}
	if len(c.serverUID) == 0 {
		return conn, nil
	}
	cred, err := peercred.Of(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrImpostor, err)
	}
	cred.Release()
	for _, uid := range c.serverUID {
		if cred.UID == uid {
			return conn, nil
		}
	}
	_ = conn.Close()
	return nil, fmt.Errorf("%w (served by uid %d)", ErrImpostor, cred.UID)
}

var frontRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// do sends one request. body is marshalled as JSON when not nil; out is
// decoded from a 2xx JSON answer.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	_, err := c.doRaw(ctx, method, path, q, body, out)
	return err
}

func (c *Client) doRaw(ctx context.Context, method, path string, q url.Values, body, out any) (*http.Response, error) {
	if c.front != "" && !frontRe.MatchString(c.front) {
		return nil, fmt.Errorf("gatte admin: front name %q: use 1-32 of a-z 0-9 . _ -", c.front)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	u := "http://gatte-admin" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.front != "" {
		req.Header.Set(FrontHeader, c.front)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var er ErrorResponse
		if json.Unmarshal(data, &er) == nil && er.Error != nil && er.Error.Code != "" {
			er.Error.Status = resp.StatusCode
			return resp, er.Error
		}
		return resp, &Error{Status: resp.StatusCode, Code: CodeInternal, Message: fmt.Sprintf("HTTP %d with no error body", resp.StatusCode)}
	}
	if out == nil {
		return resp, nil
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return resp, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return resp, fmt.Errorf("gatte admin: decoding %s %s: %w", method, path, err)
	}
	return resp, nil
}

// WhoAmI returns the API versions, the socket and who the kernel says you
// are.
func (c *Client) WhoAmI(ctx context.Context) (WhoAmI, error) {
	var v WhoAmI
	return v, c.do(ctx, http.MethodGet, "/v1/whoami", nil, nil, &v)
}

// Overview returns what needs attention.
func (c *Client) Overview(ctx context.Context) (Overview, error) {
	var v Overview
	return v, c.do(ctx, http.MethodGet, "/v1/overview", nil, nil, &v)
}

// ListTools returns the quarantine entries; server and show ("all",
// "review", "approved") may be empty.
func (c *Client) ListTools(ctx context.Context, server, show string) (ToolList, error) {
	q := url.Values{}
	if server != "" {
		q.Set("server", server)
	}
	if show != "" {
		q.Set("show", show)
	}
	var v ToolList
	return v, c.do(ctx, http.MethodGet, "/v1/tools", q, nil, &v)
}

// ReviewTool returns what an approval decides on.
func (c *Client) ReviewTool(ctx context.Context, server, tool string) (ToolReview, error) {
	var v ToolReview
	return v, c.do(ctx, http.MethodGet, "/v1/tools/review", url.Values{"server": {server}, "tool": {tool}}, nil, &v)
}

// ApproveTool approves the fingerprint that was shown, and only it.
func (c *Client) ApproveTool(ctx context.Context, r ApproveRequest) (ApproveResult, error) {
	var v ApproveResult
	return v, c.do(ctx, http.MethodPost, "/v1/tools/approve", nil, r, &v)
}

// ReviewToolSet returns every tool of server that waits for review and the
// manifest naming that set (FeatureToolReviewSet).
func (c *Client) ReviewToolSet(ctx context.Context, server string) (ToolReviewSet, error) {
	var v ToolReviewSet
	return v, c.do(ctx, http.MethodGet, "/v1/tools/review-set", url.Values{"server": {server}}, nil, &v)
}

// ApproveToolSet approves the review set that was shown, all of it or
// nothing (FeatureToolReviewSet).
func (c *Client) ApproveToolSet(ctx context.Context, r ApproveSetRequest) (ApproveSetResult, error) {
	var v ApproveSetResult
	return v, c.do(ctx, http.MethodPost, "/v1/tools/approve-set", nil, r, &v)
}

// RevokeTool returns an approved tool to pending.
func (c *Client) RevokeTool(ctx context.Context, r ToolRef) (RevokeResult, error) {
	var v RevokeResult
	return v, c.do(ctx, http.MethodPost, "/v1/tools/revoke", nil, r, &v)
}

// ListBlocks returns the blocklist.
func (c *Client) ListBlocks(ctx context.Context) (BlockList, error) {
	var v BlockList
	return v, c.do(ctx, http.MethodGet, "/v1/access/blocks", nil, nil, &v)
}

// BlockSubject blocks an analyst from the next request on.
func (c *Client) BlockSubject(ctx context.Context, r BlockRequest) (BlockResult, error) {
	var v BlockResult
	return v, c.do(ctx, http.MethodPost, "/v1/access/block", nil, r, &v)
}

// ListMaintenance returns the maintenance in force (feature maintenance).
func (c *Client) ListMaintenance(ctx context.Context) (MaintenanceList, error) {
	var v MaintenanceList
	return v, c.do(ctx, http.MethodGet, "/v1/maintenance", nil, nil, &v)
}

// StartMaintenance puts one backend, or the gateway, in planned
// maintenance (feature maintenance).
func (c *Client) StartMaintenance(ctx context.Context, r MaintenanceRequest) (MaintenanceResult, error) {
	var v MaintenanceResult
	return v, c.do(ctx, http.MethodPost, "/v1/maintenance/on", nil, r, &v)
}

// EndMaintenance ends one backend's, or the gateway's, maintenance
// (feature maintenance).
func (c *Client) EndMaintenance(ctx context.Context, r MaintenanceTarget) (MaintenanceResult, error) {
	var v MaintenanceResult
	return v, c.do(ctx, http.MethodPost, "/v1/maintenance/off", nil, r, &v)
}

// UnblockSubject lifts a block.
func (c *Client) UnblockSubject(ctx context.Context, r BlockRequest) (BlockResult, error) {
	var v BlockResult
	return v, c.do(ctx, http.MethodPost, "/v1/access/unblock", nil, r, &v)
}

// ListAudit returns one page of the trail.
func (c *Client) ListAudit(ctx context.Context, q AuditQuery) (AuditPage, error) {
	v := url.Values{}
	if q.Limit > 0 {
		v.Set("limit", strconv.Itoa(q.Limit))
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	if q.Subject != "" {
		v.Set("subject", q.Subject)
	}
	if q.Outcome != "" {
		v.Set("outcome", q.Outcome)
	}
	if q.Source != "" {
		v.Set("source", q.Source)
	}
	if q.Before > 0 {
		v.Set("before", strconv.Itoa(q.Before))
	}
	if !q.Until.IsZero() {
		v.Set("until", q.Until.UTC().Format(time.RFC3339))
	}
	if q.Tool != "" {
		v.Set("tool", q.Tool)
	}
	if q.Server != "" {
		v.Set("server", q.Server)
	}
	var p AuditPage
	return p, c.do(ctx, http.MethodGet, "/v1/audit", v, nil, &p)
}

// VerifyAudit walks the hash chain.
func (c *Client) VerifyAudit(ctx context.Context, r VerifyRequest) (VerifyResult, error) {
	var v VerifyResult
	return v, c.do(ctx, http.MethodPost, "/v1/audit/verify", nil, r, &v)
}

// ListUpstreams returns the registered backends.
func (c *Client) ListUpstreams(ctx context.Context) (UpstreamList, error) {
	var v UpstreamList
	return v, c.do(ctx, http.MethodGet, "/v1/upstreams", nil, nil, &v)
}

// QuotaUsage returns the quota counters.
func (c *Client) QuotaUsage(ctx context.Context, q QuotaQuery) (QuotaList, error) {
	v := url.Values{}
	if q.Analyst != "" {
		v.Set("analyst", q.Analyst)
	}
	if q.Account != "" {
		v.Set("account", q.Account)
	}
	if !q.Since.IsZero() {
		v.Set("since", q.Since.UTC().Format(time.RFC3339))
	}
	var l QuotaList
	return l, c.do(ctx, http.MethodGet, "/v1/quota", v, nil, &l)
}

// People returns roles, groups and who the trail has seen.
func (c *Client) People(ctx context.Context) (People, error) {
	var v People
	return v, c.do(ctx, http.MethodGet, "/v1/people", nil, nil, &v)
}

// Connect returns how an analyst connects, with the scripts rendered.
func (c *Client) Connect(ctx context.Context, username string) (Connect, error) {
	q := url.Values{}
	if username != "" {
		q.Set("username", username)
	}
	var v Connect
	return v, c.do(ctx, http.MethodGet, "/v1/connect", q, nil, &v)
}

// ConnectScript returns one script and its file name.
func (c *Client) ConnectScript(ctx context.Context, os, username string) (string, string, error) {
	q := url.Values{"os": {os}}
	if username != "" {
		q.Set("username", username)
	}
	var text string
	resp, err := c.doRaw(ctx, http.MethodGet, "/v1/connect/script", q, nil, &text)
	if err != nil {
		return "", "", err
	}
	name := ""
	if _, params, perr := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); perr == nil {
		name = params["filename"]
	}
	return text, name, nil
}

// AssignableGroups returns the groups an account may be given.
func (c *Client) AssignableGroups(ctx context.Context) (GroupList, error) {
	var v GroupList
	return v, c.do(ctx, http.MethodGet, "/v1/groups", nil, nil, &v)
}

// ListAccounts returns the IdP's accounts.
func (c *Client) ListAccounts(ctx context.Context) (AccountList, error) {
	var v AccountList
	return v, c.do(ctx, http.MethodGet, "/v1/accounts", nil, nil, &v)
}

// GetAccount returns one account.
func (c *Client) GetAccount(ctx context.Context, username string) (Account, error) {
	var v Account
	return v, c.do(ctx, http.MethodGet, "/v1/accounts/"+url.PathEscape(username), nil, nil, &v)
}

// CheckAccount validates a draft, with no side effect.
func (c *Client) CheckAccount(ctx context.Context, d AccountDraft) (AccountCheck, error) {
	var v AccountCheck
	return v, c.do(ctx, http.MethodPost, "/v1/account-check", nil, d, &v)
}

// AddAccount creates an account with a one-time password. NOT idempotent:
// after an error or a dropped connection, GetAccount first, and if it
// exists call ResetAccountPassword instead of retrying.
func (c *Client) AddAccount(ctx context.Context, n NewAccount) (PasswordResult, error) {
	if n.Groups == nil {
		n.Groups = []string{}
	}
	var v PasswordResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts", nil, n, &v)
}

// SetAccountGroups replaces an account's groups.
func (c *Client) SetAccountGroups(ctx context.Context, username string, groups []string) (AccountResult, error) {
	if groups == nil {
		groups = []string{}
	}
	var v AccountResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts/"+url.PathEscape(username)+"/groups", nil, GroupsRequest{Groups: groups}, &v)
}

// DisableAccount refuses new logins.
func (c *Client) DisableAccount(ctx context.Context, username string) (AccountResult, error) {
	var v AccountResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts/"+url.PathEscape(username)+"/disable", nil, nil, &v)
}

// EnableAccount allows logins again.
func (c *Client) EnableAccount(ctx context.Context, username string) (AccountResult, error) {
	var v AccountResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts/"+url.PathEscape(username)+"/enable", nil, nil, &v)
}

// ResetAccountPassword replaces the password with a new one-time password;
// each call invalidates the previous one.
func (c *Client) ResetAccountPassword(ctx context.Context, username string) (PasswordResult, error) {
	var v PasswordResult
	return v, c.do(ctx, http.MethodPost, "/v1/accounts/"+url.PathEscape(username)+"/reset-password", nil, nil, &v)
}
