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
const ContractVersion = "1.6.0"

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
	// WarnSensitiveUncleared (1.5.0, design/adr/0048): an approval covered
	// a sensitive tool, which is approved and NOT served until it is
	// cleared (clearTool). Not a failure: the default-deny working.
	WarnSensitiveUncleared = "sensitive_uncleared"
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
	// Since 1.1.0, with FeatureBackendHealth (design/adr/0041).
	AttentionBackendUnavailable = "backend_unavailable"
	AttentionBackendMaintenance = "backend_maintenance"
	AttentionGatewayMaintenance = "gateway_maintenance"
	AttentionServeNotReporting  = "serve_not_reporting"
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
	// Health is present with FeatureBackendHealth, and absent when it
	// could not be read (a Problem with part "health" says so).
	Health *Health `json:"health,omitempty"`
}

// Tool statuses. The set is open.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusChanged  = "changed"
)

// Security classes (design/adr/0048 Decisão 5), as Tool.Class carries
// them. Open set: an unknown class is served as sensitive by the gateway.
const (
	// ClassSafe is the empty string: a tool that only reads.
	ClassSafe = ""
	// ClassSensitive is a tool that can act. Approval is not enough for
	// it: Usable stays false until it is cleared (clearTool) at the
	// approved fingerprint, and the gateway serves it only to a role
	// marked non_read that names it explicitly.
	ClassSensitive = "sensitive"
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
	// Class is the tool's security class, since 1.5.0: empty (safe) or
	// "sensitive". SensitiveClearedHash is the approved fingerprint an
	// operator cleared for serving, empty when never cleared or when the
	// baseline moved since; a sensitive tool is usable only while it
	// equals approved_hash. Usable already says so: do not re-derive it.
	Class                string `json:"class,omitempty"`
	SensitiveClearedHash string `json:"sensitive_cleared_hash,omitempty"`
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
	// SegmentNewline is a line break in a multi-line field (a tool's
	// description): structure, not a hidden character. Draw it as a break.
	SegmentNewline = "newline"
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

// RoleCoverage is a role that can call a tool once it is approved -- or,
// for a sensitive tool, once it is cleared.
//
// Every `callable_by` (ToolReview, ApproveResult, ApprovedTool) is the
// honest list for the tool's class (1.5.0, design/adr/0048 Decisão 5): for
// a safe tool, the roles whose grants cover it; for a sensitive one, ONLY
// the roles marked non_read that name it in `tools`, since the gateway
// refuses every other coverage of a sensitive tool -- a wildcard, a
// [role.grants] name, an explicit name on a read role -- on every call. So
// for a sensitive tool Wildcard is never true, the wildcard_grant warning
// never fires, and an empty list means no role could reach it once cleared
// (no_role_grants says so in those words).
type RoleCoverage struct {
	Role     string `json:"role"`
	How      string `json:"how"`
	Wildcard bool   `json:"wildcard,omitempty"`
	// NonRead (1.5.0, design/adr/0048): the role carries `non_read =
	// true`. A sensitive tool is reachable only through a role with this
	// marking that names it in `tools` -- Wildcard false and How a
	// `tools = [...]` line; ClearResult.ClearedBy lists exactly those.
	NonRead bool `json:"non_read,omitempty"`
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

// ToolReviewSet answers GET /v1/tools/review-set (design/adr/0043): every
// tool of one backend that waits for review, each as ToolReview shows it,
// read in ONE read of the backend's entries, and the manifest that names
// exactly this set. Since 1.2.0, with FeatureToolReviewSet.
type ToolReviewSet struct {
	Server string `json:"server"`
	// Manifest is the value to send to approve-set. Empty when nothing
	// waits.
	Manifest string       `json:"manifest"`
	Tools    []ToolReview `json:"tools"`
	Pending  int          `json:"pending"`
	Changed  int          `json:"changed"`
	// HiddenCodePoints is the sum over every observed definition.
	HiddenCodePoints int `json:"hidden_code_points"`
	// Approvable is false when nothing waits, or when an observed
	// definition was not kept and so cannot be shown; Reason says which.
	Approvable bool   `json:"approvable"`
	Reason     string `json:"reason,omitempty"`
}

// ApproveSetRequest is the body of POST /v1/tools/approve-set.
type ApproveSetRequest struct {
	Server   string `json:"server"`
	Manifest string `json:"manifest"`
}

// ApprovedTool is one tool an approve-set approved.
type ApprovedTool struct {
	PreviousStatus   string         `json:"previous_status"`
	PreviousBaseline string         `json:"previous_baseline,omitempty"`
	Tool             Tool           `json:"tool"`
	CallableBy       []RoleCoverage `json:"callable_by"`
}

// ApproveSetResult answers POST /v1/tools/approve-set. Audit is the
// summary row, (tool approve set); Rows are the (tool approve) row of each
// tool, in the order of Approved.
type ApproveSetResult struct {
	ActionResult
	Server   string         `json:"server"`
	Manifest string         `json:"manifest"`
	Approved []ApprovedTool `json:"approved"`
	Rows     []OperatorRow  `json:"rows"`
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

// ClearResult answers POST /v1/tools/clear (1.5.0, design/adr/0048
// Decisão 5): a sensitive tool cleared for serving at its approved
// fingerprint. ClearedBy are the roles that reach it -- marked non_read and
// naming it in `tools` -- which is what the backend required before
// clearing; a refusal (`no_non_read_grant`) carries `details.callable_by`,
// the roles that cover the tool without reaching it.
type ClearResult struct {
	ActionResult
	Tool      Tool           `json:"tool"`
	ClearedBy []RoleCoverage `json:"cleared_by"`
}

// Block is one blocked subject.
type Block struct {
	Subject   string    `json:"subject"`
	BlockedBy string    `json:"blocked_by"`
	BlockedAt time.Time `json:"blocked_at"`
	Reason    string    `json:"reason"`
	// Until is when the block ends by itself, absent for a block with no
	// end; Expired says it has, and is no longer enforced. Since 1.4.0,
	// with FeatureBlockUntil (design/adr/0046).
	Until   *time.Time `json:"until,omitempty"`
	Expired bool       `json:"expired,omitempty"`
}

// BlockList answers GET /v1/access/blocks.
type BlockList struct {
	Blocks []Block `json:"blocks"`
}

// BlockRequest is the body of POST /v1/access/block and /unblock.
type BlockRequest struct {
	Subject string `json:"subject"`
	Reason  string `json:"reason,omitempty"`
	// Until ends the block by itself (block only). Send it only with
	// FeatureBlockUntil (1.4.0).
	Until *time.Time `json:"until,omitempty"`
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
	// Until (exclusive), Tool and Server: since 1.4.0, with
	// FeatureAuditFilters (design/adr/0046).
	Until  time.Time
	Tool   string
	Server string
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
	// Health is present with FeatureBackendHealth.
	Health *BackendHealth `json:"health,omitempty"`
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

// Features a backend lists in WhoAmI.Features since 1.1.0. A front calls an
// operation of a feature only when the backend lists it.
const (
	// FeatureMaintenance: the three /v1/maintenance operations
	// (design/adr/0041).
	FeatureMaintenance = "maintenance"
	// FeatureBackendHealth: `health` on Overview and on each Upstream.
	FeatureBackendHealth = "backend_health"
	// FeatureToolReviewSet: GET /v1/tools/review-set and POST
	// /v1/tools/approve-set (design/adr/0043), since 1.2.0.
	FeatureToolReviewSet = "tool_review_set"
	// FeatureToolClear: POST /v1/tools/clear, `class` and
	// `sensitive_cleared_hash` on each Tool, `non_read` on each
	// RoleCoverage, the (tool clear) operator row, the warning
	// sensitive_uncleared and the error codes not_sensitive, not_approved
	// and no_non_read_grant (design/adr/0048), since 1.5.0.
	FeatureToolClear = "tool_clear"
)

// Maintenance scopes.
const (
	ScopeUpstream = "upstream"
	ScopeGateway  = "gateway"
)

// Maintenance is one maintenance row (design/adr/0041 item 6). Exactly
// Message, Until, UntilPassed and StartedAt reach analysts; SetBy and SetAt
// are operator only.
type Maintenance struct {
	Message     string     `json:"message"`
	Until       *time.Time `json:"until,omitempty"`
	UntilPassed bool       `json:"until_passed,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	SetBy       string     `json:"set_by"`
	SetAt       time.Time  `json:"set_at"`
}

// MaintenanceRequest is the body of POST /v1/maintenance/on.
type MaintenanceRequest struct {
	Scope    string     `json:"scope"`
	Upstream string     `json:"upstream,omitempty"`
	Message  string     `json:"message"`
	Until    *time.Time `json:"until,omitempty"`
}

// MaintenanceTarget is the body of POST /v1/maintenance/off.
type MaintenanceTarget struct {
	Scope    string `json:"scope"`
	Upstream string `json:"upstream,omitempty"`
}

// MaintenanceResult answers a start or an end.
type MaintenanceResult struct {
	ActionResult
	Scope       string       `json:"scope"`
	Upstream    string       `json:"upstream,omitempty"`
	Maintenance *Maintenance `json:"maintenance,omitempty"`
	Previous    *Maintenance `json:"previous,omitempty"`
}

// UpstreamMaintenance is one backend in maintenance.
type UpstreamMaintenance struct {
	Maintenance
	Upstream string `json:"upstream"`
}

// MaintenanceList answers GET /v1/maintenance.
type MaintenanceList struct {
	Gateway   *Maintenance          `json:"gateway,omitempty"`
	Upstreams []UpstreamMaintenance `json:"upstreams"`
}

// Backend states (BackendHealth.State). The set is open.
const (
	BackendUp           = "up"
	BackendReconnecting = "reconnecting"
	BackendDown         = "down"
	BackendMaintenance  = "maintenance"
	// BackendUnknown: the gateway process has not reported this backend,
	// or is not reporting at all.
	BackendUnknown = "unknown"
)

// Serve states (ServeStatus.State). The set is open.
const (
	ServeRunning       = "running"
	ServeNotReporting  = "not_reporting"
	ServeNeverReported = "never_reported"
)

// BackendHealth is what the gateway process last wrote about one backend,
// merged with its maintenance row (design/adr/0041 item 7). Operator view:
// Cause and Maintenance.SetBy never reach an analyst.
type BackendHealth struct {
	Name  string `json:"name"`
	State string `json:"state"`
	// Live is the liveness underneath State.
	Live        bool       `json:"live"`
	Since       *time.Time `json:"since,omitempty"`
	LastAttempt *time.Time `json:"last_attempt,omitempty"`
	// NextAttempt is approximate: the last round's start plus the round
	// interval.
	NextAttempt *time.Time   `json:"next_attempt,omitempty"`
	Cause       string       `json:"cause,omitempty"`
	Maintenance *Maintenance `json:"maintenance,omitempty"`
}

// ServeStatus is what the gateway process last wrote about itself; the
// management backend reads it from the database, so it is also how a
// front learns that serve is not running.
type ServeStatus struct {
	State                string     `json:"state"`
	Boot                 *time.Time `json:"boot,omitempty"`
	LastRoundAt          *time.Time `json:"last_round_at,omitempty"`
	RoundIntervalSeconds int        `json:"round_interval_seconds,omitempty"`
}

// Health is the gateway's and every registered backend's health.
type Health struct {
	Serve              ServeStatus     `json:"serve"`
	GatewayMaintenance *Maintenance    `json:"gateway_maintenance,omitempty"`
	Backends           []BackendHealth `json:"backends"`
}
