// Package adminapi is the contract of Gatte's management API
// (design/adr/0040, api/admin.openapi.yaml) as Go types, plus a Client that
// talks to it over its UNIX socket.
//
// A front imports this package and pkg/frontkit and nothing else from
// Gatte. Every string in every response is untrusted text: escape it for
// your medium and make hidden code points visible (frontkit.VisibleText),
// and draw review text from its segments (frontkit.DrawSegments).
package adminapi

import "time"

// ContractVersion is the api/admin.openapi.yaml info.version these types
// implement.
const ContractVersion = "1.0.0"

// Default socket paths (design/adr/0040 §1).
const (
	DefaultOperatorSocket = "/run/mcp-gateway-admin/operator/operator.sock"
	DefaultAccountsSocket = "/run/mcp-gateway-admin/accounts/accounts.sock"
)

// Socket names, as WhoAmI.Socket and Error.Details["socket"] carry them.
const (
	SocketOperator = "operator"
	SocketAccounts = "accounts"
)

// FrontHeader is the header that labels the calling front.
const FrontHeader = "Gatte-Front"

// OperatorRow is the operator row an action wrote to the audit trail.
type OperatorRow struct {
	Identity  string    `json:"identity"`
	Tool      string    `json:"tool"`
	Reason    string    `json:"reason"`
	Timestamp time.Time `json:"timestamp"`
}

// Warning is a machine key plus an English fallback.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Known warning codes. The set is open.
const (
	WarnNeverSeen        = "never_seen"
	WarnNoRoleGrants     = "no_role_grants"
	WarnWildcardGrant    = "wildcard_grant"
	WarnIdPReload        = "idp_reload"
	WarnAuditWriteFailed = "audit_write_failed"
)

// ActionResult is the common part of every state-changing response.
type ActionResult struct {
	Changed  bool         `json:"changed"`
	Recorded bool         `json:"recorded"`
	Audit    *OperatorRow `json:"audit,omitempty"`
	Warnings []Warning    `json:"warnings,omitempty"`
	Messages []string     `json:"messages"`
}

// HasWarning reports whether the result carries the warning code.
func (r ActionResult) HasWarning(code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// Operator is who the backend attributes this connection's rows to.
type Operator struct {
	UID      uint32 `json:"uid"`
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Via      string `json:"via,omitempty"`
}

// WhoAmI answers GET /v1/whoami.
type WhoAmI struct {
	APIVersions     []string `json:"api_versions"`
	ContractVersion string   `json:"contract_version"`
	Features        []string `json:"features"`
	GatewayVersion  string   `json:"gateway_version"`
	Socket          string   `json:"socket"`
	ConfigPath      string   `json:"config_path"`
	Operator        Operator `json:"operator"`
	Front           string   `json:"front,omitempty"`
}

// Attention kinds. The set is open.
const (
	AttentionChanged  = "changed"
	AttentionPending  = "pending"
	AttentionUnsigned = "unsigned"
)

// Attention is one thing only an operator can resolve.
type Attention struct {
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Server   string `json:"server,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Upstream string `json:"upstream,omitempty"`
}

// OverviewCounts are the overview's numbers.
type OverviewCounts struct {
	Tools          int `json:"tools"`
	ApprovedUsable int `json:"approved_usable"`
	Review         int `json:"review"`
	Upstreams      int `json:"upstreams"`
	Blocked        int `json:"blocked"`
}

// Problem is a part of an answer that could not be read.
type Problem struct {
	Code    string `json:"code"`
	Part    string `json:"part"`
	Message string `json:"message"`
}

// Overview answers GET /v1/overview.
type Overview struct {
	Attention    []Attention    `json:"attention"`
	Counts       OverviewCounts `json:"counts"`
	RecentDenied []AuditRecord  `json:"recent_denied"`
	Problems     []Problem      `json:"problems,omitempty"`
}

// Tool statuses. The set is open.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusChanged  = "changed"
)

// Tool is one quarantine entry.
type Tool struct {
	Server       string    `json:"server"`
	Tool         string    `json:"tool"`
	Status       string    `json:"status"`
	Usable       bool      `json:"usable"`
	ApprovedHash string    `json:"approved_hash"`
	ObservedHash string    `json:"observed_hash"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ToolCounts are over every entry, whatever the filter.
type ToolCounts struct {
	All      int `json:"all"`
	Review   int `json:"review"`
	Approved int `json:"approved"`
}

// ToolList answers GET /v1/tools.
type ToolList struct {
	Tools  []Tool     `json:"tools"`
	Counts ToolCounts `json:"counts"`
}

// Segment kinds. The set is open: draw an unknown kind visibly.
const (
	SegmentText        = "text"
	SegmentHidden      = "hidden"
	SegmentInvalidByte = "invalid_byte"
)

// Segment is one run of review text, computed from the raw bytes.
type Segment struct {
	Kind      string `json:"kind"`
	Text      string `json:"text,omitempty"`
	CodePoint string `json:"code_point,omitempty"`
	Byte      string `json:"byte,omitempty"`
}

// Text is a value as advertised, and its segments.
type Text struct {
	Raw      string    `json:"raw"`
	Segments []Segment `json:"segments"`
}

// ReviewLine is one line of a definition's canonical form.
type ReviewLine struct {
	Depth    int       `json:"depth"`
	Segments []Segment `json:"segments"`
}

// Diff line operations. The set is open.
const (
	DiffContext = "context"
	DiffAdd     = "add"
	DiffDel     = "del"
	DiffGap     = "gap"
)

// DiffLine is one line of the approved-to-observed diff.
type DiffLine struct {
	Op       string    `json:"op"`
	Depth    int       `json:"depth"`
	Segments []Segment `json:"segments"`
}

// Definition is one stored tool definition.
type Definition struct {
	Fingerprint      string       `json:"fingerprint"`
	Kept             bool         `json:"kept"`
	Name             *Text        `json:"name,omitempty"`
	Description      *Text        `json:"description,omitempty"`
	InputSchema      any          `json:"input_schema,omitempty"`
	OutputSchema     any          `json:"output_schema,omitempty"`
	Lines            []ReviewLine `json:"lines,omitempty"`
	HiddenCodePoints int          `json:"hidden_code_points"`
}

// RoleCoverage is a role that can call a tool once it is approved.
type RoleCoverage struct {
	Role     string `json:"role"`
	How      string `json:"how"`
	Wildcard bool   `json:"wildcard,omitempty"`
}

// ToolReview answers GET /v1/tools/review.
type ToolReview struct {
	Tool       Tool           `json:"tool"`
	Observed   Definition     `json:"observed"`
	Approved   *Definition    `json:"approved,omitempty"`
	Diff       []DiffLine     `json:"diff,omitempty"`
	CallableBy []RoleCoverage `json:"callable_by"`
	ReviewText string         `json:"review_text"`
}

// ApproveRequest is the body of POST /v1/tools/approve.
type ApproveRequest struct {
	Server      string `json:"server"`
	Tool        string `json:"tool"`
	Fingerprint string `json:"fingerprint"`
}

// ApproveResult answers POST /v1/tools/approve.
type ApproveResult struct {
	ActionResult
	PreviousStatus   string         `json:"previous_status"`
	PreviousBaseline string         `json:"previous_baseline,omitempty"`
	Tool             Tool           `json:"tool"`
	CallableBy       []RoleCoverage `json:"callable_by,omitempty"`
}

// ToolRef names one tool.
type ToolRef struct {
	Server string `json:"server"`
	Tool   string `json:"tool"`
}

// RevokeResult answers POST /v1/tools/revoke.
type RevokeResult struct {
	ActionResult
	WasApprovedAt string `json:"was_approved_at,omitempty"`
	Tool          Tool   `json:"tool"`
}

// Block is one blocked subject.
type Block struct {
	Subject   string    `json:"subject"`
	BlockedBy string    `json:"blocked_by"`
	BlockedAt time.Time `json:"blocked_at"`
	Reason    string    `json:"reason"`
}

// BlockList answers GET /v1/access/blocks.
type BlockList struct {
	Blocks []Block `json:"blocks"`
}

// BlockRequest is the body of POST /v1/access/block and /unblock.
type BlockRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
}

// BlockResult answers a block or an unblock.
type BlockResult struct {
	ActionResult
	Subject string `json:"subject"`
}

// Audit outcomes. The set is open.
const (
	OutcomeAllowed = "allowed"
	OutcomeDenied  = "denied"
	OutcomeFailed  = "failed"
)

// AuditRecord is one row of the trail.
type AuditRecord struct {
	Position        int       `json:"position"`
	Timestamp       time.Time `json:"timestamp"`
	AnalystIdentity string    `json:"analyst_identity"`
	AnalystName     string    `json:"analyst_name,omitempty"`
	Tool            string    `json:"tool"`
	TargetUpstream  string    `json:"target_upstream"`
	Outcome         string    `json:"outcome"`
	Reason          string    `json:"reason,omitempty"`
	SourceAddress   string    `json:"source_address,omitempty"`
}

// AuditQuery narrows GET /v1/audit. Zero values are left out.
type AuditQuery struct {
	Limit   int
	Since   time.Time
	Subject string
	Outcome string
	Source  string
	Before  int
}

// AuditPage answers GET /v1/audit.
type AuditPage struct {
	Records    []AuditRecord `json:"records"`
	Limit      int           `json:"limit"`
	More       bool          `json:"more,omitempty"`
	NextBefore int           `json:"next_before,omitempty"`
}

// VerifyRequest is the body of POST /v1/audit/verify.
type VerifyRequest struct {
	ExpectHead string `json:"expect_head,omitempty"`
}

// ChainBreak is where the chain first stops verifying.
type ChainBreak struct {
	Position     int         `json:"position"`
	Record       AuditRecord `json:"record"`
	HashExpected string      `json:"hash_expected"`
	HashStored   string      `json:"hash_stored"`
}

// SIEMAnchor says where the trail's anchor lives.
type SIEMAnchor struct {
	Path  string `json:"path"`
	Chain string `json:"chain"`
}

// VerifyResult answers POST /v1/audit/verify.
type VerifyResult struct {
	Intact               bool        `json:"intact"`
	Count                int         `json:"count"`
	Head                 string      `json:"head"`
	Empty                bool        `json:"empty,omitempty"`
	RetroactivelyChained int         `json:"retroactively_chained"`
	FirstBreak           *ChainBreak `json:"first_break,omitempty"`
	HeadMatches          *bool       `json:"head_matches,omitempty"`
	SIEM                 *SIEMAnchor `json:"siem,omitempty"`
	Messages             []string    `json:"messages,omitempty"`
}

// Upstream is one registered backend. It never carries a secret value.
type Upstream struct {
	Name         string    `json:"name"`
	Transport    string    `json:"transport"`
	Command      string    `json:"command,omitempty"`
	Args         []string  `json:"args,omitempty"`
	URL          string    `json:"url,omitempty"`
	Image        string    `json:"image,omitempty"`
	Network      string    `json:"network"`
	NetworkError string    `json:"network_error,omitempty"`
	EnvVarNames  []string  `json:"env_var_names"`
	Signature    string    `json:"signature"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// UpstreamList answers GET /v1/upstreams.
type UpstreamList struct {
	Upstreams []Upstream `json:"upstreams"`
}

// QuotaUsage is one counter.
type QuotaUsage struct {
	AnalystIdentity string     `json:"analyst_identity"`
	Account         string     `json:"account"`
	WindowStart     time.Time  `json:"window_start"`
	WindowEnd       *time.Time `json:"window_end,omitempty"`
	Used            int        `json:"used"`
	Limit           *int       `json:"limit,omitempty"`
	Remaining       *int       `json:"remaining,omitempty"`
}

// QuotaQuery narrows GET /v1/quota.
type QuotaQuery struct {
	Analyst string
	Account string
	Since   time.Time
}

// QuotaList answers GET /v1/quota.
type QuotaList struct {
	Usage []QuotaUsage `json:"usage"`
}

// Group is a [group_to_role] key and its role.
type Group struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// Role is a role with its groups and tools.
type Role struct {
	Name   string   `json:"name"`
	Groups []string `json:"groups"`
	Tools  []string `json:"tools"`
}

// Seen is an analyst the trail has seen.
type Seen struct {
	Identity string    `json:"identity"`
	Name     string    `json:"name,omitempty"`
	LastCall time.Time `json:"last_call"`
	Calls    int       `json:"calls"`
	Blocked  bool      `json:"blocked"`
}

// People answers GET /v1/people.
type People struct {
	Roles  []Role  `json:"roles"`
	Groups []Group `json:"groups"`
	Seen   []Seen  `json:"seen"`
}

// Connect script systems.
const (
	OSMacOS   = "macos"
	OSLinux   = "linux"
	OSWindows = "windows"
)

// ConnectScript is one rendered connect script.
type ConnectScript struct {
	OS       string `json:"os"`
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Run      string `json:"run"`
	Content  string `json:"content"`
}

// Connect answers GET /v1/connect.
type Connect struct {
	Ready        bool            `json:"ready"`
	Missing      []string        `json:"missing,omitempty"`
	URL          string          `json:"url,omitempty"`
	ClientID     string          `json:"client_id,omitempty"`
	CallbackPort int             `json:"callback_port,omitempty"`
	ServerName   string          `json:"server_name,omitempty"`
	Username     string          `json:"username,omitempty"`
	HasCA        bool            `json:"has_ca,omitempty"`
	Command      string          `json:"command,omitempty"`
	Scripts      []ConnectScript `json:"scripts,omitempty"`
}

// Account is an IdP account. The password hash is never returned.
type Account struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`
}

// AccountList answers GET /v1/accounts.
type AccountList struct {
	Accounts []Account `json:"accounts"`
}

// AssignableGroup is a group an account may be given.
type AssignableGroup struct {
	Name  string   `json:"name"`
	Role  string   `json:"role"`
	Tools []string `json:"tools"`
}

// GroupList answers GET /v1/groups.
type GroupList struct {
	Groups []AssignableGroup `json:"groups"`
}

// AccountDraft is the body of POST /v1/account-check.
type AccountDraft struct {
	DisplayName string   `json:"display_name,omitempty"`
	Username    string   `json:"username,omitempty"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

// FieldProblem is one validation problem of a draft.
type FieldProblem struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// AccountCheck answers POST /v1/account-check.
type AccountCheck struct {
	OK        bool              `json:"ok"`
	Username  string            `json:"username"`
	Suggested bool              `json:"suggested"`
	Problems  []FieldProblem    `json:"problems"`
	Groups    []AssignableGroup `json:"groups"`
}

// NewAccount is the body of POST /v1/accounts.
type NewAccount struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Email       string   `json:"email,omitempty"`
	Groups      []string `json:"groups"`
}

// GroupsRequest is the body of POST /v1/accounts/{username}/groups.
type GroupsRequest struct {
	Groups []string `json:"groups"`
}

// AccountResult answers an account change that sets no password.
type AccountResult struct {
	ActionResult
	Account Account `json:"account"`
}

// PasswordResult answers an account change that generates a one-time
// password. OneTimePassword is shown once and never kept.
type PasswordResult struct {
	ActionResult
	Account         Account `json:"account"`
	OneTimePassword string  `json:"one_time_password"`
}
