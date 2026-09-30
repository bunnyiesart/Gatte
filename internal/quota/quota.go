// Package quota is the domain package for the per-analyst quota
// (design/adr/0030-quota-por-analista.md): how much of a third party's
// finite budget one analyst may spend through the gateway inside one
// window, and what happens once it is spent.
//
// It exists because every upstream shares one credential per entry among
// all analysts -- the only mode this gateway has -- and a shared credential
// with no ceiling means one analyst in a loop burns the whole team's
// VirusTotal allowance. The gateway could not previously even observe that
// happening: the provider's 429 answers the shared key, arrives inside the
// `threatintel` process, and does not say who spent it.
//
// # What is counted, and why it is none of the three obvious things
//
// The counted unit is one *account at a provider*. Not the upstream, not
// the tool, not the environment variable that holds the key.
//
// Not the upstream. A threat-intel backend is one registry entry serving
// dozens of tools, and many of them consume no third-party account at all
// -- they answer from MITRE, CISA, Exploit-DB, DNS or local libraries. A
// ceiling on "threatintel" punishes the analyst running two hundred
// `decode` calls and does nothing about the one running twenty
// `lookup_ip`.
//
// Not the tool. A single `lookup_ip` can fan out to several accounts in
// parallel, VirusTotal and Shodan among them, while `decode` touches none:
// a per-tool counter is wrong by a factor that swings from 0 to N. And
// `enrich` only learns its own fan-out at runtime, after classifying the
// indicator it was handed.
//
// Not the variable name. THREATINTEL_MALWAREBAZAAR_API_KEY,
// THREATINTEL_THREATFOX_API_KEY and THREATINTEL_URLHAUS_API_KEY can hold
// the same value -- one abuse.ch account. Counting by variable name opens
// three independent budgets against one account.
//
// So a Provider here is an account, and the operator declares which tools
// spend it. One tool may spend several; several tools may spend one.
//
// # Where the limit lives, and where the counter lives
//
// They are deliberately in different places, by the criterion ADR-0009 §2
// already set for roles: a limit decides what somebody may do, so it is
// policy and belongs in the reviewed, version-controlled TOML; a counter
// is how much has been spent, so it is operational state and belongs in
// the database. Putting the limit in the database would hand the operator
// a command that widens policy with no reviewable diff, which is exactly
// what ADR-0009 §2 rejected.
//
// That split is structural here, not a convention: a Charge carries the
// limit with it, from the file into the reservation, and the storage
// adapter's schema has no column to put a limit in. Nothing can raise a
// limit with an UPDATE, because there is nothing to update.
//
// # The window
//
// Fixed, not sliding, and aligned by truncation in UTC. Sliding would mean
// storing one timestamp per call, which is a second audit trail under
// another name; and truncating in UTC avoids deciding in which offset the
// day rolls over -- a question the audit trail leaves open by storing
// RFC3339Nano with whatever offset the caller had.
//
// The UTC part is load-bearing, not cosmetic. Truncate works on absolute
// time, so it lands on the same instant whatever the location; but the
// window start is stored, and stored as text, and 2026-09-14T00:00:00Z and
// 2026-09-13T21:00:00-03:00 are the same instant spelled two ways. Two
// spellings are two rows, and two rows are two budgets. See
// Provider.WindowStart and Charge.Validate, which refuses a window start
// carrying any offset but zero.
//
// # Time comes from the caller
//
// Nothing here reads the clock. `now` is a parameter, the same shape
// audit.Record uses for its Timestamp and for the same reason: the window
// boundary is an input to a decision, and a test of what happens when a
// window rolls over must not have to wait for midnight.
//
// # Fail closed
//
// A counter that cannot be read, or cannot be written, refuses the call --
// with no distinction between the two. ADR-0004 fails closed on an
// unreadable registry, verifyEntry refuses to decide integrity without the
// state that governs it, and quarantine treats a route with no entry as
// unapproved. A quota that turned into a free pass when its counter broke
// would be the one control in this system with the inverse behaviour, and
// anyone wanting the team's budget would only have to break the counter.
// Gate.Admit is where that is enforced: every error the Store can return,
// of every kind, comes back as a refusal, and the only way past it is a
// nil error.
//
// # What this package never holds
//
// No credential value, and no field capable of holding one: a Provider
// names an account, never its key -- the key is a name in the registry
// entry's EnvVarNames, resolved by the Credential Vault at spawn time and
// never here. Counters are per analyst, so one analyst's spending never
// moves another's remaining balance, and no message produced here names an
// analyst.
//
// # Two ports, and the split is the security property
//
// Store, which the request path holds, can only reserve: it cannot read a
// counter and it cannot lower one. Reader, which only the Operator Console
// holds, can only read. Neither can be reached from the other, and nothing
// anywhere can write a counter downward.
//
// Reading matters -- a quota that is only visible when it blows is a quota
// that blows, and an operator who cannot see consumption cannot size a
// limit -- but it must not be reachable from a tool call. The counter is a
// record of which accounts an analyst has been querying, which is to say a
// summary of what they are investigating; a Gate able to read it would be
// one component away from an analyst enumerating a colleague's work. The
// operator already reads the whole audit trail and owns the database file,
// so Reader grants them nothing they did not have, and the request path
// gains nothing at all. See Store and Reader, and the fitness function that
// keeps internal/gateway from acquiring the second one.
//
// Per the ports & adapters split this project follows
// (context/05-testabilidade-e-contratos.md), this package
// contains no reference to database/sql, SQL, or any other infrastructure
// detail. The sqlite subpackage is the adapter, and it holds no policy:
// what a call costs, which window it falls in and whether a limit was
// passed are decided by the pure functions here, so the rules can never
// diverge between the Go code and a WHERE clause.
package quota

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Sentinel errors. Callers check these with errors.Is, since both the
// domain and its adapters wrap them with context.
var (
	// ErrInvalidProvider is returned when a Provider fails Validate, or
	// when NewPlan is given a set it cannot accept.
	ErrInvalidProvider = errors.New("quota: invalid provider")

	// ErrInvalidReservation is returned when a Reservation fails Validate.
	// It is a defensive error: every Reservation the gateway makes is built
	// by Plan.Charges, so a malformed one means a caller assembled it by
	// hand and got it wrong. It is classified as a refusal, never as a
	// pass -- see Gate.Admit.
	ErrInvalidReservation = errors.New("quota: invalid reservation")

	// ErrExhausted means the analyst has spent this window's allowance for
	// one of the accounts the call would consume. Nothing was debited: a
	// reservation is all-or-nothing.
	//
	// The gateway records this as audit.OutcomeDenied with the reason
	// "quota exhausted", and -- deliberately -- does not collapse it into
	// an opaque error. What leaks is the operator's own published limit,
	// not the SOC's security posture, which is the same line ErrForbidden
	// already draws.
	ErrExhausted = errors.New("quota: exhausted")

	// ErrUnavailable means the quota could not be established: the counter
	// could not be read, could not be written, or the request was
	// malformed. The call is refused. Read and write failures are
	// deliberately the same error, because whoever wants free quota has no
	// preference between them -- if writing could fail open, the attack
	// would be to make writing fail.
	ErrUnavailable = errors.New("quota: unavailable")
)

// Provider is one account at a third party, and the unit this component
// counts. It is what an operator declares as a [[quota.provider]] block.
//
// One entry is one *account*, not one service name. The three abuse.ch
// services (MalwareBazaar, ThreatFox, URLhaus) authenticate with a single
// key issued to a single account, so they are one Provider naming all
// three services' tools -- three Providers would be three budgets against
// one account, which is the counting mistake this type exists to avoid.
//
// A Provider holds no key and no field that could hold one. The account's
// credential reaches the upstream as a name in that registry entry's
// EnvVarNames, resolved in memory at spawn time by the Credential Vault
// (ADR-0003); this package never sees it and has nowhere to put it.
type Provider struct {
	// Name identifies the account, and is the key the counter is stored
	// under. It is operator-chosen and operator-facing: it appears in the
	// refusal an analyst reads, so "virustotal" and "abusech" are the kind
	// of name wanted, not an opaque id.
	Name string

	// Upstream is the registry entry whose credential carries this
	// account's key, e.g. "threatintel".
	//
	// This package does not check that Upstream exists, or that Tools are
	// namespaced under it. Neither fact is visible from here: the registry
	// is not in hand, and the namespacing rule has one owner already
	// (config.Validate, splitting with gateway.SplitNamespaced). The
	// cross-check against the registry happens where the file and the
	// registry are both in hand -- a [[quota.provider]] naming an upstream
	// that is absent stops the gateway from starting at Connect, and stops
	// Reconcile from bringing anything new up (ADR-0030 decision 4).
	Upstream string

	// Limit is how many calls one analyst may make against this account
	// per Window. Per analyst, never pooled: a pool ceiling would
	// reintroduce the exact defect this component exists to remove, with
	// the first analyst in a loop exhausting everybody. With seven
	// analysts and limit N the naive worst case looks like 7N. It is 14N.
	//
	// The window is FIXED and aligned by truncation, not sliding, so two
	// adjacent windows are two independent counters: an analyst who spends
	// the whole allowance just before a boundary and the whole allowance
	// just after has made 2N calls inside one window's length. Measured on
	// 14 set 2026, 200 calls in two seconds against a declared limit of
	// 100 per 24h. So the operator sizes N as the budget divided by TWICE
	// the number of heads, and writes that arithmetic beside the line.
	//
	// The fixed window stays -- a sliding one is a second accounting model
	// on the request path, which ADR-0030 decision 4 declines. What was
	// wrong was the sizing rule, which did not know about its own window.
	//
	// Zero, negative and absent are all refused, never read as "no limit".
	// The precedent is quarantine's refresh_interval = 0, refused with a
	// message telling the operator to raise it, so that a security control
	// switched off for a minute and left off cannot exist without the file
	// admitting it.
	Limit int

	// Window is the length of the accounting period. Windows are fixed and
	// aligned by truncation in UTC -- see WindowStart. Zero and negative
	// are refused for the same reason as Limit.
	Window time.Duration

	// Tools are the namespaced tool names that spend this account, e.g.
	// "threatintel.lookup_ip". A call to any of them debits one unit.
	//
	// One unit per call per account, even when the upstream hits the
	// account twice for one call -- `lookup_hash` queries MalwareBazaar
	// and ThreatFox, which are one abuse.ch account, and is charged once.
	// The declared form has no way to say "twice", and inventing one was
	// left out of this iteration deliberately; the residual is an
	// undercount, recorded here because ADR-0030 decision 5 is explicit
	// that undercounting is the direction that burns the budget.
	Tools []string
}

// Validate checks that p satisfies the quota's policy contract:
//
//   - Name must be non-empty and free of leading or trailing whitespace.
//   - Upstream must be non-empty.
//   - Limit must be greater than zero.
//   - Window must be greater than zero.
//   - Tools must be non-empty, with no empty and no repeated entry.
//
// Every violated rule is reported, not just the first, joined onto
// ErrInvalidProvider -- the operator fixing a config file should see the
// whole list in one run, as config.Validate does for the rest of the file.
func (p Provider) Validate() error {
	var errs []error

	// Whitespace is refused rather than trimmed for the same reason
	// access.ValidateRole refuses it in a role name: "virustotal " is a
	// distinct key from "virustotal", so a stray space silently opens a
	// second budget the first window it is written.
	if p.Name != strings.TrimSpace(p.Name) {
		errs = append(errs, fmt.Errorf("provider name %q has leading or trailing whitespace", p.Name))
	}
	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, errors.New("provider with empty name"))
	}
	if strings.TrimSpace(p.Upstream) == "" {
		errs = append(errs, fmt.Errorf("provider %q has no upstream", p.Name))
	}
	if p.Limit <= 0 {
		errs = append(errs, fmt.Errorf("provider %q has limit %d: a limit must be greater than zero; "+
			"raise it to the number of calls one analyst may make per window, and do not remove it to disable the quota",
			p.Name, p.Limit))
	}
	if p.Window <= 0 {
		errs = append(errs, fmt.Errorf("provider %q has window %s: a window must be a positive duration, e.g. \"24h\"",
			p.Name, p.Window))
	}
	if len(p.Tools) == 0 {
		errs = append(errs, fmt.Errorf("provider %q lists no tools: an account no tool spends is a limit that never "+
			"applies, which is a control that is off without the file saying so", p.Name))
	}
	seen := make(map[string]struct{}, len(p.Tools))
	for _, tool := range p.Tools {
		if strings.TrimSpace(tool) == "" {
			errs = append(errs, fmt.Errorf("provider %q has an empty tool name", p.Name))
			continue
		}
		if _, dup := seen[tool]; dup {
			// Listing a tool twice under one account would debit it twice
			// per call. That may one day be what somebody wants, but it
			// would be a deliberate cost field, not a repeated line.
			errs = append(errs, fmt.Errorf("provider %q lists tool %q twice", p.Name, tool))
			continue
		}
		seen[tool] = struct{}{}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalidProvider}, errs...)...)
}

// WindowStart returns the beginning of the accounting window containing t:
// t truncated to p.Window, in UTC.
//
// The .UTC() is not decoration. time.Truncate works on absolute time since
// the zero instant, so it picks the same *instant* whatever location t
// carries -- but the result is stored, stored as text, and the same
// instant spells itself differently in two offsets. A gateway whose clock
// returns local time would key one window as "2026-09-13T21:00:00-03:00"
// and another process, or the same one after a TZ change, would key the
// identical window as "2026-09-14T00:00:00Z". Two keys, two counters, two
// budgets. Fixing the spelling here fixes it for everything downstream,
// and Charge.Validate refuses anything that arrives spelled otherwise.
func (p Provider) WindowStart(t time.Time) time.Time {
	return t.UTC().Truncate(p.Window)
}

// Charge is one account's share of one call: what to debit, how much room
// there is, and which window it falls in. It is produced by Plan.Charges
// and consumed by a Store, and it is how the limit travels from the
// configuration file to the point of decision without ever being stored.
//
// A zero Charge grants nothing: Fits is false for any real usage, because
// a limit nobody set is not a limit of infinity.
type Charge struct {
	// Provider is the account name being debited.
	Provider string
	// Limit is the account's per-analyst allowance for this window, copied
	// from the declared policy. It is never persisted; see the package
	// doc.
	Limit int
	// WindowStart is the beginning of the accounting window, in UTC. It is
	// part of the counter's identity.
	WindowStart time.Time
	// WindowEnd is when this window's allowance resets. It is carried so a
	// refusal can tell the analyst when to try again rather than leaving
	// them to work it out from a duration.
	WindowEnd time.Time
}

// Fits reports whether a post-debit usage of used stays within this
// charge's allowance.
//
// This is the whole "is it exhausted" rule, and it is here rather than in
// the adapter's SQL so that there is exactly one place where a limit is
// compared against a count. A Store applies its debit and asks this
// question about the result; it never phrases the comparison itself.
func (c Charge) Fits(used int) bool {
	return used <= c.Limit
}

// Window returns the length of this charge's accounting window.
func (c Charge) Window() time.Duration {
	return c.WindowEnd.Sub(c.WindowStart)
}

// Validate checks that c is a well-formed charge: a named account, a
// positive limit, a non-zero window start carrying no UTC offset, and an
// end strictly after the start.
//
// The offset rule is the one worth stating out loud. The window start is
// the counter's key and is stored as text, so a charge arriving as
// 2026-09-13T21:00:00-03:00 would open a second counter for a window that
// already has one, silently doubling the allowance. Refusing is the
// difference between a loud error and a quota that quietly stopped
// counting.
func (c Charge) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Provider) == "" {
		errs = append(errs, errors.New("charge with empty provider"))
	}
	if c.Limit <= 0 {
		errs = append(errs, fmt.Errorf("charge for %q has limit %d, want greater than zero", c.Provider, c.Limit))
	}
	if c.WindowStart.IsZero() {
		errs = append(errs, fmt.Errorf("charge for %q has a zero window start", c.Provider))
	}
	if _, offset := c.WindowStart.Zone(); offset != 0 {
		errs = append(errs, fmt.Errorf("charge for %q has window start %s, which is not in UTC: "+
			"the window start is the counter's key and is stored as text, so the same instant in two offsets is two counters",
			c.Provider, c.WindowStart.Format(time.RFC3339Nano)))
	}
	if !c.WindowEnd.After(c.WindowStart) {
		errs = append(errs, fmt.Errorf("charge for %q ends at %s, which is not after its start %s",
			c.Provider, c.WindowEnd.Format(time.RFC3339Nano), c.WindowStart.Format(time.RFC3339Nano)))
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalidReservation}, errs...)...)
}

// Exhausted returns the error a Store must return when a charge cannot be
// taken, wrapping ErrExhausted.
//
// It is exported because adapters build it, and it is a function rather
// than a free-form message because the wording is the thing the analyst
// reads at 03h: it names the account and when the window resets, and
// deliberately names no analyst -- neither the caller, who already knows
// who they are, nor anybody else, since nothing this package produces
// should be usable to learn about another analyst's work.
func Exhausted(c Charge) error {
	return &ExhaustedError{Provider: c.Provider, Limit: c.Limit, Window: c.Window(), ResetsAt: c.WindowEnd.UTC()}
}

// ExhaustedError is the typed form of an exhausted charge, so the serving
// adapter can tell the analyst WHEN to try again without parsing a
// message (design/adr/0042 item 2). Every field is the operator's
// declared policy or the window arithmetic over it -- the account name,
// the limit, the window, its end -- and none is a count: the refusal says
// the allowance is spent, not how much anybody spent. It unwraps to
// ErrExhausted, and its text is the one Exhausted always produced.
type ExhaustedError struct {
	Provider string
	Limit    int
	Window   time.Duration
	ResetsAt time.Time
}

func (e *ExhaustedError) Error() string {
	return fmt.Sprintf("%v: %q allows %d call(s) per analyst per %s, and this window is spent; it resets at %s",
		ErrExhausted, e.Provider, e.Limit, e.Window, e.ResetsAt.Format(time.RFC3339))
}

func (e *ExhaustedError) Unwrap() error { return ErrExhausted }

// Plan is the validated, immutable set of declared accounts, and the index
// from a tool name to the accounts it spends.
//
// Immutable once built, like access.Policy and for the same reason:
// rebuilding it is how it changes, which keeps the request path free of
// any locking discipline. Also like access.Policy, the immutability is
// enforced by copying rather than documented -- Tools is a slice, so
// storing the caller's Provider verbatim would leave the plan sharing a
// backing array with whoever built it.
type Plan struct {
	providers []Provider
	// byTool maps a namespaced tool name to the charges it incurs, already
	// sorted by account name. Sorted because the order decides which
	// account a multi-account refusal names, and an operator reading two
	// refusals should not see them disagree; and because a Store debiting
	// rows in a stable order across all callers is one fewer way for two
	// concurrent reservations to interleave badly.
	byTool map[string][]Provider
	// free holds tools the operator declared to spend no budgeted account.
	// It changes no charge -- a tool in here costs exactly what a tool
	// nobody mentioned costs, which is nothing -- and exists so that
	// "costs nothing" and "nobody said" stop being the same state. The
	// gateway cross-checks the served tools of a budgeted upstream against
	// charged-or-free and does not route a tool in neither.
	//
	// Why that check needs this set: the unit of charging is the namespaced
	// tool name, and a name absent from byTool is admitted without touching
	// the Store. That is correct for casemgmt, logsearch and docsearch, and it
	// is a permanent free path when the tool belongs to `threatintel` and spends
	// VirusTotal. Measured on 14 set 2026: an account declared over
	// `threatintel.virustotal` alone admitted 5000 calls to five other
	// VirusTotal-spending tools without one Store lookup, and nothing at
	// startup said so.
	free map[string]struct{}
}

// NewPlan builds a Plan from the declared accounts. It validates every
// Provider and refuses duplicate account names.
//
// A duplicate name is refused rather than merged because two blocks with
// one name are two budgets against one account -- the abuse.ch mistake
// wearing a different hat -- and because the counter is keyed by name, so
// the second block's limit would win or lose depending on map order.
//
// NewPlan(nil, nil) is valid and returns an empty plan: no account declared
// means no tool is charged, which is the honest state for casemgmt, logsearch
// and docsearch, where there is no external budget to protect
// (ADR-0030 decision 9). It is a plan that charges nothing, not a missing
// plan -- see NewGate, which refuses a nil one.
//
// freeTools is the operator saying, out loud, that a tool spends no
// budgeted account. It changes nothing about what anything costs. It exists
// because "this tool is free" and "nobody mentioned this tool" were the
// same state, and they are not the same fact: for a tool of an upstream
// whose third-party budget is being protected, silence is a permanent free
// path against that budget and the startup said nothing about it. The
// second parameter is on the constructor rather than tucked into a setter
// so that every caller has to answer the question.
func NewPlan(providers []Provider, freeTools []string) (*Plan, error) {
	p := &Plan{
		providers: make([]Provider, 0, len(providers)),
		byTool:    make(map[string][]Provider),
		free:      make(map[string]struct{}, len(freeTools)),
	}

	byName := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if err := provider.Validate(); err != nil {
			return nil, err
		}
		if _, dup := byName[provider.Name]; dup {
			return nil, fmt.Errorf("%w: duplicate provider %q", ErrInvalidProvider, provider.Name)
		}
		byName[provider.Name] = struct{}{}

		stored := provider
		stored.Tools = slices.Clone(provider.Tools)
		p.providers = append(p.providers, stored)
	}

	slices.SortFunc(p.providers, func(a, b Provider) int { return strings.Compare(a.Name, b.Name) })
	for _, provider := range p.providers {
		for _, tool := range provider.Tools {
			p.byTool[tool] = append(p.byTool[tool], provider)
		}
	}

	for _, tool := range freeTools {
		name := strings.TrimSpace(tool)
		if name == "" {
			return nil, fmt.Errorf("%w: a free tool entry is empty", ErrInvalidProvider)
		}
		if _, dup := p.free[name]; dup {
			return nil, fmt.Errorf("%w: duplicate free tool %q", ErrInvalidProvider, name)
		}
		// A tool cannot be both charged and declared free: the two
		// statements contradict, and silently letting the charge win would
		// leave a file that says one thing and a gateway that does another
		// -- which is the shape of every finding this component exists to
		// avoid. Refused rather than reconciled.
		if _, charged := p.byTool[name]; charged {
			return nil, fmt.Errorf(
				"%w: tool %q is declared free and is also charged by an account; "+
					"it cannot be both -- remove it from free_tools, or from the account's tools",
				ErrInvalidProvider, name)
		}
		p.free[name] = struct{}{}
	}
	return p, nil
}

// IsDeclared reports whether the operator has SAID something about this
// tool: that it is charged to an account, or that it spends nothing.
//
// It is not a permission check and nothing on the request path calls it --
// Admit decides what a call costs and does not care whether anyone declared
// it. This exists for the gateway, which asks the question over the tools a
// budgeted upstream actually serves, every time it builds a routing table,
// and does not route a tool for which the answer is no. Silence about a tool of an upstream whose
// budget is being protected is the one case where "costs nothing" is not a
// safe default, because the provider bills it anyway.
func (p *Plan) IsDeclared(tool string) bool {
	if _, charged := p.byTool[tool]; charged {
		return true
	}
	_, free := p.free[tool]
	return free
}

// FreeTools returns the tools declared to spend nothing, sorted. A copy:
// the plan is immutable to its callers.
func (p *Plan) FreeTools() []string {
	out := make([]string, 0, len(p.free))
	for tool := range p.free {
		out = append(out, tool)
	}
	slices.Sort(out)
	return out
}

// Charges returns what one call to tool costs, as one Charge per account,
// with every window resolved against now. It returns nil when no declared
// account names that tool -- the ordinary case, covering every tool of
// every upstream with no external budget, and the tools of `threatintel` that
// answer from MITRE, CISA, DNS or a local library.
//
// The charges come back sorted by account name; see Plan.byTool.
func (p *Plan) Charges(tool string, now time.Time) []Charge {
	providers := p.byTool[tool]
	if len(providers) == 0 {
		return nil
	}

	charges := make([]Charge, 0, len(providers))
	for _, provider := range providers {
		start := provider.WindowStart(now)
		charges = append(charges, Charge{
			Provider:    provider.Name,
			Limit:       provider.Limit,
			WindowStart: start,
			WindowEnd:   start.Add(provider.Window),
		})
	}
	return charges
}

// Providers returns the declared accounts, sorted by name. The returned
// slice and every Tools slice in it are copies: a caller that mutates what
// it gets back does not rewrite what the live plan charges.
func (p *Plan) Providers() []Provider {
	out := make([]Provider, 0, len(p.providers))
	for _, provider := range p.providers {
		clone := provider
		clone.Tools = slices.Clone(provider.Tools)
		out = append(out, clone)
	}
	return out
}

// Reservation is one call's request to spend quota: who is calling, and
// every account the call will touch.
//
// It is all-or-nothing by construction -- one value covering every account
// of one call, handed to the Store as a unit. `lookup_ip` reserves six
// accounts; if one is spent, the call is refused whole and the other five
// are not debited, because the gateway cannot make the upstream perform
// five sixths of a fan-out it does not control.
type Reservation struct {
	// Analyst is the identity the spending is attributed to. It must be
	// access.Identity.Subject -- the claim the IdP asserts and a user
	// cannot change -- and never Name, which an IdP may let a user edit
	// (renaming would reset the counter), and never SourceAddress, which
	// gateway.Caller documents as observed rather than attested.
	Analyst string
	// Charges is every account this call spends, each with the limit and
	// window already resolved. Never empty; see Validate.
	Charges []Charge
}

// Validate checks that r is a well-formed reservation: an analyst, at
// least one charge, no account charged twice, and every charge valid.
//
// An empty Charges list is refused rather than treated as "nothing to do".
// A reservation is a request to debit, and a request to debit nothing
// reaching a Store means a caller lost the charges somewhere between the
// plan and the port -- which would otherwise read as a silent grant. The
// legitimate "this tool costs nothing" case never builds a Reservation at
// all; see Gate.Admit.
func (r Reservation) Validate() error {
	var errs []error

	if strings.TrimSpace(r.Analyst) == "" {
		errs = append(errs, errors.New("reservation with no analyst identity"))
	}
	if len(r.Charges) == 0 {
		errs = append(errs, errors.New("reservation with no charges"))
	}

	seen := make(map[string]struct{}, len(r.Charges))
	for _, c := range r.Charges {
		if err := c.Validate(); err != nil {
			// Unwrap one level and append the rules themselves: the charge
			// already joined onto ErrInvalidReservation, and joining it
			// again would print the sentinel twice. Each of its messages
			// already names the account, so no second prefix is added
			// either.
			errs = append(errs, unwrapJoined(err)...)
			continue
		}
		if _, dup := seen[c.Provider]; dup {
			errs = append(errs, fmt.Errorf("provider %q charged twice in one reservation", c.Provider))
			continue
		}
		seen[c.Provider] = struct{}{}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(append([]error{ErrInvalidReservation}, errs...)...)
}

// unwrapJoined returns the errors joined into err, dropping the leading
// sentinel a Validate method prepends. It exists so a nested validation
// failure reads as one sentinel and a list of rules, not as the sentinel
// repeated at every level.
func unwrapJoined(err error) []error {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}
	parts := joined.Unwrap()
	if len(parts) > 1 && errors.Is(parts[0], ErrInvalidReservation) {
		return parts[1:]
	}
	return parts
}

// Store is the port through which the domain durably counts what an
// analyst has spent. Implementations are adapters (the sqlite subpackage)
// and must honour the contract on Reserve.
//
// It has exactly one method, and that is a decision rather than an
// accident of what is needed so far. A method that answered "how much has
// analyst X used" would put that answer one call away from the request
// path -- the counter is a record of investigative activity, and a SOC
// analyst's queries are exactly the thing another analyst should not be
// able to enumerate. The operator's need to read consumption is real and
// is served by Reader, a separate port they alone hold; what must not
// exist is a Gate that can read, and the way to guarantee that is for the
// interface it holds to have no such method.
//
// And a method that lowered a counter would be the `quota reset` that
// ADR-0030 decision 8 refuses on different grounds: handing an analyst 120
// units back does not create 120 lookups at VirusTotal, it takes them from
// the rest of the team with no diff and no review. That one exists on
// neither port: nothing in this component writes a counter downward.
type Store interface {
	// Reserve atomically debits one unit from every account in r, for
	// r.Analyst, in each charge's window. Its contract:
	//
	//   - All or nothing. Either every charge is debited and Reserve
	//     returns nil, or nothing is debited at all. A partial reservation
	//     would bill an analyst for accounts a refused call never reached.
	//
	//   - It returns an error wrapping ErrExhausted, built with Exhausted,
	//     when any charge's post-debit usage fails Charge.Fits. Nothing is
	//     debited in that case: a refused call does not spend quota.
	//
	//   - The debit and the check are one atomic operation, not a read
	//     followed by a write. Dispatch does not serialise calls -- N
	//     goroutines call concurrently over one session, with no queue and
	//     no pool, several per analyst under ADR-0035's cap -- so a
	//     read-then-write would let N callers all read limit-1 and all
	//     pass.
	//
	//   - It returns ErrInvalidReservation if r.Validate() fails, and
	//     nothing is written.
	//
	//   - Any other error means the counter could not be read or written.
	//     It is a refusal, never a pass; see Gate.Admit.
	//
	// An implementation must not consult a stored limit: the limit arrives
	// in the Charge, from the operator's reviewed file, and the counter's
	// storage has no business holding a copy it could be widened by.
	Reserve(ctx context.Context, r Reservation) error
}

// Usage is one counter as it stands: what one analyst has spent against
// one account inside one window. It is what the Operator Console prints.
//
// It carries no limit, and that is not an omission. The limit lives in the
// operator's reviewed file and is never written to the counter's storage
// (see the package doc), so the only honest thing a storage adapter can
// report is the count. The console pairs each row with the declared
// Provider it belongs to -- which is also why a row for an account nobody
// declares any more still prints: it is what was spent, and hiding it
// would hide exactly the history that explains a limit somebody tightened.
type Usage struct {
	// Analyst is the access.Identity.Subject the spending is attributed
	// to, the same value the audit trail's AnalystIdentity carries, so an
	// operator can move between the two without a translation step.
	Analyst string
	// Provider is the account name that was debited.
	Provider string
	// WindowStart is the beginning of the accounting window, in UTC.
	WindowStart time.Time
	// Used is how many calls have been charged in that window. It is never
	// negative and never decreases while the window is current.
	Used int
}

// Reader is the operator-facing read port: the Operator Console's view of
// the counters, and the only way anything in this system reads one.
//
// It is deliberately NOT part of Store, and the separation is the whole
// point rather than a tidiness preference. The Gateway holds a Store and
// therefore cannot read a counter even by mistake; the console holds a
// Reader and cannot debit one. A single interface carrying both methods
// would put "how much has this analyst spent" one call away from the
// request path -- see Store for why that answer must stay out of reach of
// a tool call.
//
// What the operator gains here they already had: they read the entire
// audit trail with `mcp-gateway audit`, and they own the SQLite file this
// counts in. What they gain in *ergonomics* is the thing that makes the
// control usable -- a limit nobody can observe consumption against is a
// number picked once and never checked, and a quota whose first signal is
// an analyst blocked mid-incident is a quota that blows.
//
// There is still no way down. Reader reads and Store adds; nothing in this
// component, on either port, subtracts.
type Reader interface {
	// Usage returns every counter, ordered by analyst, then account, then
	// window start. Rows of windows long past are included: they are the
	// only record of what a limit has actually cost, and the console
	// narrows by window rather than the port doing it.
	//
	// The port takes no filter for the reason audit.Recorder.List takes
	// none: filtering in one caller keeps the ordering guarantee in one
	// place, and this table is small by construction -- one row per
	// (analyst, account, window), which for seven analysts and eight
	// accounts on a daily window is a few thousand rows a year. If it ever
	// outgrows memory, that is a change to this port, not to its caller.
	Usage(ctx context.Context) ([]Usage, error)
}

// Gate is the request path's entry point: the declared policy and the
// counter, joined, answering the one question Dispatch asks between
// admitting a tool and recording that the call was allowed.
type Gate struct {
	plan  *Plan
	store Store
	// self answers Standing for gatte.status, one analyst at a time
	// (design/adr/0042 item 3). Optional; see self.go.
	self SelfReader
}

// NewGate joins a Plan to a Store. Both are required, and a nil one is an
// error rather than a quiet "then there is no quota": a security control
// that switches itself off because a wire was left unconnected is the
// failure mode require_signed and quarantine's refresh_interval were both
// written to avoid. An installation that declares no account passes an
// empty Plan, deliberately, from NewPlan(nil).
func NewGate(plan *Plan, store Store) (*Gate, error) {
	if plan == nil {
		return nil, errors.New("quota: gate needs a plan; pass the result of NewPlan(nil) to declare no quota")
	}
	if store == nil {
		return nil, errors.New("quota: gate needs a store; a nil store would make every call free")
	}
	return &Gate{plan: plan, store: store}, nil
}

// Admit reserves the quota one call to tool costs analyst, at time now. It
// returns nil when the call may proceed, and an error when it may not.
//
// # Every error is a refusal
//
// This is the fail-closed rule of ADR-0030 decision 6, and it is enforced
// here rather than left to the caller to remember. Admit returns exactly
// two classes of failure and there is no third:
//
//   - ErrExhausted, when the allowance is spent. Nothing was debited.
//   - ErrUnavailable, for absolutely everything else -- a counter that
//     could not be read, a counter that could not be written, a malformed
//     reservation, a context deadline, an adapter error nobody has
//     anticipated yet.
//
// Read failures and write failures are the same class on purpose.
// Distinguishing them invites treating one as infrastructure noise, and
// whoever wants free quota has no preference between the two: if a failed
// write could pass, the attack would be to make the write fail.
//
// The caller has no success value to misread, only a nil error, so the
// single mistake that could open this gate is discarding the error
// entirely -- the same mistake that would discard the audit record three
// lines later in Dispatch, and as visible.
//
// # When there is nothing to charge
//
// A tool no declared account names costs nothing and is admitted without
// touching the Store. That is the common case, not an escape hatch: it
// covers every tool of casemgmt, logsearch and docsearch, which have no
// external budget to protect, and the tools of `threatintel` that consume no
// third-party account. An empty Plan admits everything, unconditionally and
// before any other check, which is what an installation with no
// [[quota.provider]] block has asked for.
func (g *Gate) Admit(ctx context.Context, analyst, tool string, now time.Time) error {
	// An installation with no account declared has asked for no quota, and
	// gets exactly that: this gate says nothing about any call, including
	// the malformed ones refused below. Those checks exist because a call
	// nobody can be billed for is a call no limit can hold -- and with no
	// limit anywhere there is nothing to hold, so refusing here would only
	// move a refusal the audit trail already makes (a record with no
	// analyst does not validate) to a different line with a different
	// error. With no [quota] section the gateway behaves exactly as it did
	// before this package existed, which is what the empty plan promises.
	if len(g.plan.providers) == 0 {
		return nil
	}
	// Checked before the plan is consulted, so that a call the gateway
	// cannot attribute is refused even when the tool happens to be free.
	// An empty subject means identity resolution went wrong upstream of
	// here, and a call nobody can be billed for is a call nobody can be
	// held to a limit.
	if strings.TrimSpace(analyst) == "" {
		return fmt.Errorf("%w: %w: empty analyst identity", ErrUnavailable, ErrInvalidReservation)
	}
	if strings.TrimSpace(tool) == "" {
		return fmt.Errorf("%w: %w: empty tool name", ErrUnavailable, ErrInvalidReservation)
	}
	// A zero clock would truncate every window to the same instant in year
	// one: one eternal window, and a limit that is spent once and never
	// resets. That is a wiring mistake, and it is refused loudly rather
	// than absorbed, exactly as audit.Record refuses a zero Timestamp.
	if now.IsZero() {
		return fmt.Errorf("%w: %w: zero clock reading", ErrUnavailable, ErrInvalidReservation)
	}

	charges := g.plan.Charges(tool, now)
	if len(charges) == 0 {
		return nil
	}

	err := g.store.Reserve(ctx, Reservation{Analyst: analyst, Charges: charges})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrExhausted):
		return err
	default:
		// Deliberately total: every remaining error, of every kind, lands
		// here. There is no branch that inspects the error and proceeds.
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
}

// Plan returns the plan this gate enforces. It is here for the composition
// root, which cross-checks the declared accounts against the registry at
// Connect; the request path does not need it.
func (g *Gate) Plan() *Plan {
	return g.plan
}
