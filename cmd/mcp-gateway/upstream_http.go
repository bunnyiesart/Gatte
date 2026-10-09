// Operator Console -- the http half of "upstream register": turning the
// -openapi document into the frozen operation set the entry stores and
// signs (ADR-0047 §3; ADR-0048, step 4 of its implementation order).

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	gwrest "github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/visible"
)

// authKindNone is the -auth-kind spelling for "keyless, and I mean it":
// the registry's keyless value is the empty string, which the flag cannot
// distinguish from "not given", and "not given" lets the ingestion derive a
// descriptor from the document's securitySchemes. An operator registering a
// public API whose document nevertheless declares an apiKey scheme needs a
// way to say no, and this is it.
const authKindNone = "none"

// fetchTimeout bounds the one network read register may do: a document
// server that takes longer than this is down, and the operator is at a
// prompt, not in a retry loop.
const fetchTimeout = 30 * time.Second

// httpIngestReport is what the console prints after an http entry is
// registered: the tools the document produced and what the ingestion
// decided or dropped on the way. It holds no credential and no field that
// could -- the ingestion never sees one (resthttp.Ingest's post-condition).
type httpIngestReport struct {
	// source names where the document came from, for the operator's eyes:
	// the file path, or the URL (which parseBase guaranteed carries no
	// userinfo or query).
	source string
	// fetched is true when source is a URL that was read over the network.
	fetched bool
	ops     []gwrest.Operation
	// basePath is what was folded into the registered URL from the
	// document's servers[0], or "".
	basePath    string
	authDerived bool
	skipped     []string
	warnings    []string
	// bytes is the document's size.
	bytes int
}

// httpFlagsRefusal reports why the three http-only flags cannot accompany a
// non-http entry, or "" when none was given. Refused here, by name, rather
// than left to registry.Validate: Validate knows AuthKind and AuthName but
// not -openapi, and an operator who typed all three for a stdio entry should
// be told once about the one mistake, not three times about its symptoms.
func httpFlagsRefusal(transport registry.Transport, openapi, authKind, authName string) string {
	var given []string
	if openapi != "" {
		given = append(given, "-openapi")
	}
	if authKind != "" {
		given = append(given, "-auth-kind")
	}
	if authName != "" {
		given = append(given, "-auth-name")
	}
	if len(given) == 0 {
		return ""
	}
	return fmt.Sprintf("%s %s to -transport http only; a %s entry's tools come from the backend itself, and its credentials are handed to the process by name (-env), not injected on a request.",
		strings.Join(given, ", "), opPlural(len(given), "applies", "apply"), transport)
}

// httpRegistration is the http half of a register request, as the
// console's flags and the management API's body both give it
// (design/adr/0050 §2: "the same path as upstream register -transport
// http: same ingestion, same refusals, same report").
type httpRegistration struct {
	// openapi is the -openapi argument: an http(s) URL, or, only with
	// allowFile, a file path. Unused when document is set.
	openapi string
	// document is the document itself (the API's openapi_document);
	// source is how the report names it.
	document []byte
	source   string
	// allowFile lets openapi name a file. The CLI runs as the operator, at
	// their prompt; the API never reads a path a client named.
	allowFile          bool
	authKind, authName string
	// fetched, when set, is told the size and source of a document read
	// over the network, the moment it was read.
	fetched func(n int, source string)
}

// ingestRefusal is a refusal of the http ingestion: the text the console
// writes to stderr, and whether its usage follows. The API answers msg.
type ingestRefusal struct {
	msg   string
	usage bool
}

func (e *ingestRefusal) Error() string { return strings.TrimSpace(e.msg) }

func refuse(usage bool, format string, args ...any) error {
	return &ingestRefusal{msg: fmt.Sprintf(format, args...), usage: usage}
}

// ingestForRegister is the console's ingestHTTP: it writes a refusal, and
// the usage when the refusal is about a flag, to stderr, and the one
// network read to stdout.
//
// Post-condition: on exitOK the entry's Operations decode under its
// AuthKind/AuthName (Ingest's post-condition) and the returned report
// describes them; on any other code the reason was written to stderr and
// nothing was registered.
func ingestForRegister(entry *registry.UpstreamServer, openapi, authKind, authName string, stdout, stderr io.Writer) (*httpIngestReport, int) {
	report, err := ingestHTTP(context.Background(), entry, httpRegistration{openapi: openapi, allowFile: true, authKind: authKind, authName: authName,
		// Said now, on stdout, because it is the one network read this
		// command makes and the operator should see that it happened and
		// what it read -- the URL names no credential (parseBase refused
		// userinfo and a query before the request was built).
		fetched: func(n int, source string) { fmt.Fprintf(stdout, "Fetched %d bytes from %s.\n", n, source) }})
	if err != nil {
		var ir *ingestRefusal
		if !errors.As(err, &ir) {
			ir = &ingestRefusal{msg: err.Error() + "\n"}
		}
		fmt.Fprint(stderr, ir.msg)
		if ir.usage {
			upstreamUsage(stderr)
		}
		return nil, exitCannotRun
	}
	return report, exitOK
}

// ingestHTTP fills an http entry's URL, auth descriptor and Operations
// from its OpenAPI document, and returns the report the console prints
// after registering. It runs BEFORE the configuration is read or the
// database opened, like every other refusal in upstreamRegister, so a
// document the gateway cannot serve costs nothing and names the rule it
// broke. The CLI and the management API both register through it.
//
// Order, and why: the arguments are checked first, without I/O (a document
// given, the url acceptable to the adapter, the auth kind one of the four
// words, and the registry's document-independent rules -- name, env names
// and their count -- by preIngestRefusal), so an operator who mistyped a
// flag is not made to wait for a fetch that was going to be thrown away;
// then the document is read (file, one guarded GET, or the bytes sent);
// then resthttp.Ingest translates it under the operator's descriptor, or
// derives one. The entry comes back with URL = the ingestion's BaseURL
// (the url with the document's base path folded in, ADR-0047 §6), the
// effective descriptor and the canonical, already-validated Operations.
// registry.Validate and dialTimeRefusal still run on it afterwards
// (validateEntry), as for any entry.
//
// Pre-condition: entry.Transport is http. Post-condition: on nil the
// entry's Operations decode under its AuthKind/AuthName; on error it is an
// *ingestRefusal and nothing was registered. No credential value is
// available to this function, so none can be in what it returns.
func ingestHTTP(ctx context.Context, entry *registry.UpstreamServer, in httpRegistration) (*httpIngestReport, error) {
	authKind, authName := in.authKind, in.authName
	if in.openapi == "" && in.document == nil {
		// The registry's own words for what is missing (the URL first, then
		// the operation set), plus the flag that fills the set -- Validate
		// cannot know about -openapi, and "requires a non-empty operation
		// set" alone sends the operator looking for a flag named
		// -operations.
		err := entry.Validate()
		if err == nil {
			err = errors.New("http transport requires an operation set")
		}
		return nil, refuse(true, "%v\n\n-openapi FILE|URL is required for -transport http: the operation set the entry\nsigns is generated from an OpenAPI 3.x document (design/adr/0047 §3), and\nnothing re-reads it after registration.\n\n", err)
	}

	// -auth-kind, before any I/O. "none" is the console's spelling of the
	// registry's "" with no derivation: the ingestion gets NoDerive, so it
	// neither derives a descriptor from the document nor validates the set
	// under one (a derived descriptor would reserve its slot and refuse a
	// parameter there that a keyless entry may carry).
	forceKeyless := authKind == authKindNone
	if forceKeyless {
		authKind = ""
	}
	if !registry.AuthKind(authKind).Valid() {
		return nil, refuse(true, "-auth-kind %q is not one of %q, %q, %q or %q.\n\n", authKind, registry.AuthBearer, registry.AuthHeader, registry.AuthQuery, authKindNone)
	}
	if authName != "" && !registry.AuthKind(authKind).NamesLocation() {
		return nil, refuse(true, "-auth-name applies to -auth-kind %q or %q only: bearer injects a fixed Authorization\nheader, and a keyless entry injects nothing.\n\n", registry.AuthHeader, registry.AuthQuery)
	}
	if forceKeyless && authName != "" {
		return nil, refuse(true, "-auth-name was given with -auth-kind none; a keyless entry injects nothing.\n\n")
	}

	// The -url, by the adapter's rule, before the document is read: a URL
	// the adapter would refuse at every start makes the fetch pointless,
	// and ValidateBaseURL does no I/O.
	if err := gwrest.ValidateBaseURL(entry.URL); err != nil {
		return nil, refuse(true, "-url: %v\n\n", err)
	}
	// The registry's own rules that do not depend on the document -- the
	// name, the env names, and, when the operator chose the descriptor,
	// "a keyed entry names exactly one secret, a keyless one none" -- on a
	// copy whose operation set is a placeholder, so a URL document is not
	// fetched for an entry that was going to be refused anyway. A
	// descriptor still to be derived is checked only as far as no derived
	// outcome could pass: more than one -env is wrong keyed or keyless.
	if err := preIngestRefusal(*entry, authKind, authName, forceKeyless); err != nil {
		return nil, refuse(true, "%v\n\n", err)
	}

	var doc []byte
	var report *httpIngestReport
	if in.document != nil {
		if len(in.document) > gwrest.MaxDocumentBytes {
			return nil, refuse(false, "-openapi: the document is over the %d-byte limit the ingestion reads\n", gwrest.MaxDocumentBytes)
		}
		doc, report = in.document, &httpIngestReport{source: in.source}
	} else {
		var err error
		doc, report, err = loadOpenAPIDocument(ctx, in.openapi, in.allowFile)
		if err != nil {
			return nil, refuse(false, "-openapi: %s\n", visible.Escape(err.Error()))
		}
	}
	if report.fetched && in.fetched != nil {
		in.fetched(len(doc), report.source)
	}

	res, err := gwrest.Ingest(doc, gwrest.IngestOptions{AuthKind: authKind, AuthName: authName, BaseURL: entry.URL, NoDerive: forceKeyless})
	if err != nil {
		// The error quotes the document (a path, a key, a scheme's name):
		// escaped like everything else the console prints that a third
		// party chose (internal/visible).
		return nil, refuse(false, "refusing to register %q: %s: %s\n", entry.Name, report.source, visible.Escape(err.Error()))
	}

	entry.URL = res.BaseURL
	entry.AuthKind = registry.AuthKind(res.AuthKind)
	entry.AuthName = res.AuthName
	entry.Operations = res.Operations
	report.ops = res.Ops
	report.basePath = res.BasePath
	report.authDerived = res.AuthDerived
	report.skipped = res.Skipped
	report.warnings = res.Warnings
	report.bytes = len(doc)
	return report, nil
}

// validateEntry is what every entry passes before the database is opened,
// whatever its transport and whoever registers it: the registry's rules,
// then the dialer's (podman's, the REST adapter's), which the domain
// package cannot know -- an entry the dialer would refuse forever must not
// register, sign and then fail at every restart. report is the http
// ingestion's, or nil. The error is an *ingestRefusal.
func validateEntry(entry registry.UpstreamServer, report *httpIngestReport) error {
	// Validated here rather than left to the adapter: a malformed entry is
	// bad usage, and reporting it before the database is even opened means
	// the operator sees the rule they broke and nothing else.
	if err := entry.Validate(); err != nil {
		msg := fmt.Sprintf("%v\n\n", err)
		if report != nil && report.authDerived {
			// The rule Validate just applied -- a keyed entry names exactly
			// one secret -- was triggered by a descriptor the operator did
			// not type, so say where it came from and the three ways out.
			msg += fmt.Sprintf("The auth kind %q%s was derived from the document's securitySchemes, which\nmakes this a keyed entry. Pass -env NAME with the secret to inject there,\n-auth-kind to choose another location, or -auth-kind none to register keyless.\n\n",
				entry.AuthKind, nameNote(entry.AuthName))
		}
		return &ingestRefusal{msg: msg, usage: true}
	}
	if err := dialTimeRefusal(entry); err != nil {
		return refuse(true, "%v\n\n", err)
	}
	return nil
}

// preIngestRefusal is the document-independent half of registry.Validate
// for an http entry (see the call site in ingestForRegister for why it runs
// before the document is read). It returns Validate's own error, so the
// operator reads the same words as when the full entry is validated.
func preIngestRefusal(entry registry.UpstreamServer, authKind, authName string, forceKeyless bool) error {
	entry.Operations = []byte(`[{}]`)
	switch {
	case authKind != "" || forceKeyless:
		entry.AuthKind, entry.AuthName = registry.AuthKind(authKind), authName
	case len(entry.EnvVarNames) == 0:
		entry.AuthKind, entry.AuthName = registry.AuthNone, ""
	case len(entry.EnvVarNames) == 1:
		// Any keyed descriptor the document may yield accepts one secret;
		// bearer is the one that needs no name.
		entry.AuthKind, entry.AuthName = registry.AuthBearer, ""
	default:
		// More than one -env is wrong whatever descriptor the document
		// yields; the rest of the entry is still checked first, so the
		// first rule broken is the one reported.
		probe := entry
		probe.EnvVarNames, probe.AuthKind, probe.AuthName = nil, registry.AuthNone, ""
		if err := probe.Validate(); err != nil {
			return err
		}
		return fmt.Errorf("%w: http transport needs exactly one env var name (the secret to inject) for a keyed entry and none for a keyless one; got %d", registry.ErrInvalid, len(entry.EnvVarNames))
	}
	return entry.Validate()
}

// loadOpenAPIDocument reads the -openapi argument: an http(s) URL is fetched
// once through the adapter's guarded client (resthttp.FetchDocument -- the
// same transport, resolved-address policy and origin pin as a tool call,
// no credential, no proxy, the ingestion's byte ceiling); anything else is
// a file path, read up to the same ceiling. Never a bare http.Get: the
// console runs on the gateway's host, inside its network, and a document
// URL is an operator-typed string that could name the metadata endpoint as
// easily as a spec (ADR-0048 Decisão 6).
//
// allowFile false refuses anything but a URL: the management API never
// reads a path a client named (design/adr/0050 §2). ctx bounds the fetch
// along with fetchTimeout -- the API's request has a shorter deadline.
func loadOpenAPIDocument(ctx context.Context, ref string, allowFile bool) ([]byte, *httpIngestReport, error) {
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		d := gwrest.New(nil, gwrest.WithHTTPClientTimeout(fetchTimeout))
		doc, err := d.FetchDocument(ctx, ref, gwrest.MaxDocumentBytes)
		if err != nil {
			// The URL is not repeated here: FetchDocument's error already
			// names what it requested when a request was made, and when
			// the URL itself was refused (userinfo, a query) the refusal
			// says which rule, which is the part worth reading.
			return nil, nil, err
		}
		return doc, &httpIngestReport{source: ref, fetched: true}, nil
	}
	if !allowFile {
		return nil, nil, errors.New("the document must be an http(s) URL, or sent as the document itself")
	}

	f, err := os.Open(ref)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	doc, err := io.ReadAll(io.LimitReader(f, gwrest.MaxDocumentBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", ref, err)
	}
	if len(doc) > gwrest.MaxDocumentBytes {
		return nil, nil, fmt.Errorf("%s: the document is over the %d-byte limit the ingestion reads", ref, gwrest.MaxDocumentBytes)
	}
	return doc, &httpIngestReport{source: ref}, nil
}

// opAuthLine renders an http entry's credential-injection descriptor the
// way `upstream register` and `sign` show it: the location and the name,
// never a value (the registry has no field for one).
func opAuthLine(s registry.UpstreamServer) string {
	switch s.AuthKind {
	case registry.AuthNone:
		return "none (keyless)"
	case registry.AuthBearer:
		return "bearer (Authorization: Bearer <secret>)"
	case registry.AuthHeader:
		return "header " + s.AuthName + ": <secret>"
	case registry.AuthQuery:
		return "query ?" + s.AuthName + "=<secret>"
	}
	return string(s.AuthKind) + " " + s.AuthName
}

// opOperationsLine renders the frozen operation set as a count and the
// SHA-256 the signature covers (signer canonical/v3-http hashes exactly
// these bytes), so what `sign` prints is what it attests to.
func opOperationsLine(s registry.UpstreamServer) string {
	var ops []gwrest.Operation
	if decoded, err := gwrest.Decode(s.Operations, string(s.AuthKind), s.AuthName); err == nil {
		ops = decoded
	}
	sum := sha256.Sum256(s.Operations)
	count := "an undecodable set"
	if ops != nil {
		count = fmt.Sprintf("%d %s", len(ops), opPlural(len(ops), "operation", "operations"))
	}
	return fmt.Sprintf("%s, sha256 %s", count, hex.EncodeToString(sum[:8])+"...")
}

// className is the word for a class in a table: ClassSafe is the zero value
// (quarantine.Class), and an empty cell beside "sensitive" would read as
// "not classified" rather than "safe".
func className(c quarantine.Class) string {
	if c == quarantine.ClassSafe {
		return "safe"
	}
	return string(c)
}

// printIngestReport writes the tools an http registration of entry `name`
// produced, what the ingestion skipped and warned about, and what the
// operator has to do next -- after the entry is in the registry, so the
// table describes something that exists. cmd renders a console command for
// the next-step hints, on their own lines as every console hint is.
func printIngestReport(w io.Writer, r *httpIngestReport, name string, cmd func(string) string) bool {
	safe, sensitive := 0, 0
	for _, op := range r.ops {
		if gwrest.ClassOf(op.Method) == quarantine.ClassSensitive {
			sensitive++
		} else {
			safe++
		}
	}
	fmt.Fprintf(w, "\n%d %s generated from %s (%d safe, %d sensitive)", len(r.ops), opPlural(len(r.ops), "tool", "tools"), r.source, safe, sensitive)
	if len(r.skipped) > 0 {
		fmt.Fprintf(w, "; %d %s skipped", len(r.skipped), opPlural(len(r.skipped), "operation", "operations"))
	}
	if r.basePath != "" {
		fmt.Fprintf(w, "; base path %s folded into the url", r.basePath)
	}
	fmt.Fprint(w, ".\n\n")

	tw := opTable(w)
	fmt.Fprintln(tw, "  TOOL\tMETHOD\tPATH\tCLASS")
	for _, op := range r.ops {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", op.Name, op.Method, op.Path, className(gwrest.ClassOf(op.Method)))
	}
	if err := tw.Flush(); err != nil {
		return false
	}

	// Skipped and Warnings quote the document. Ingest escapes what it
	// quotes; the console escapes again on the way out, because this is
	// where the terminal is and a line that reached here unescaped would
	// repaint the tool table just printed (internal/visible; Escape is
	// idempotent on its own output).
	if len(r.skipped) > 0 {
		fmt.Fprint(w, "\nSkipped -- declared by the document, not in the set:\n")
		for _, line := range r.skipped {
			fmt.Fprintf(w, "  %s\n", visible.Escape(line))
		}
	}
	if len(r.warnings) > 0 {
		fmt.Fprint(w, "\nWarnings:\n")
		for _, line := range r.warnings {
			fmt.Fprintf(w, "  %s\n", visible.Escape(line))
		}
	}
	if r.authDerived {
		fmt.Fprint(w, "\nThe auth descriptor above was DERIVED from the document's securitySchemes, not\nchosen by you. Check it: the gateway will inject the -env secret there on every\ncall. Pass -auth-kind to choose, or -auth-kind none to register keyless.\n")
	}

	fmt.Fprintf(w, "\nEach tool waits in the quarantine until it is approved; once the entry is\nsigned and the gateway has dialled it, review them with:\n\n    %s -server %s\n\nThe operation set is frozen with the entry: a change to the document is not\npicked up until the entry is deregistered and registered again -- \"upstream\nupdate\" does not re-ingest.\n", cmd("tool review"), opShellQuote(name))
	if sensitive > 0 {
		fmt.Fprintf(w, "\n%d sensitive %s (POST, PUT, PATCH or DELETE): approval alone does not make one\ncallable. After approving, release each one deliberately:\n\n    %s %s TOOL\n\nand grant it BY NAME in a role marked non_read -- a wildcard grant never covers\na sensitive tool (design/adr/0048 Decisão 5).\n",
			sensitive, opPlural(sensitive, "tool", "tools"), cmd("tool clear"), opShellQuote(name))
	}
	return true
}
