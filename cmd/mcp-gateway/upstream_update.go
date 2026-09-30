// Operator Console -- "upstream update": a new image digest for an oci
// entry, keeping the approvals whose definitions did not change
// (design/adr/0043).

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/quarantine"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

func upstreamUpdate(args []string, stdout, stderr io.Writer) int {
	fs, configPath := opFlagSet("upstream update", stderr)
	image := fs.String("image", "", "the new digest-pinned image: NAME@sha256:<64 hex> (required)")
	if code, ok := opParse(fs, args, stdout, stderr, upstreamUsage); !ok {
		return code
	}
	if fs.NArg() != 1 || *image == "" {
		fmt.Fprint(stderr, "update takes -image NAME@sha256:HEX and exactly one argument: the name of the entry\n\n")
		upstreamUsage(stderr)
		return exitCannotRun
	}
	name := fs.Arg(0)
	return opRun(*configPath, stdout, stderr, func(e *opEnv) int {
		return runUpstreamUpdate(e, name, *image)
	})
}

// runUpstreamUpdate replaces the image of one oci entry and nothing else.
//
// What it keeps is the point of it. `deregister` + `register` + `sign`
// forgets the quarantine, because a name registered again may be anything
// (ADR-0013 item 2); for an image upgrade that sent every tool back to
// review, and an operator facing forty identical definitions learns to
// approve without reading. Here the operator says it is the same backend,
// and the rules that make that safe are the existing ones: an approval is
// of a definition's fingerprint, so it holds only while the new image
// advertises the byte-identical definition, and a different one is
// `changed` -- unusable, audited, diffed -- at the next discovery. The
// entry itself changed, so the signature stored for the old image no
// longer verifies it and the gateway refuses the backend, whatever
// signer.require_signed says, until root signs the new entry.
func runUpstreamUpdate(e *opEnv, name, image string) int {
	before, err := e.upstreams().Get(e.ctx(), name)
	switch {
	case errors.Is(err, registry.ErrNotFound):
		fmt.Fprintf(e.stderr, "no upstream named %q is registered.\n\nList what is:\n\n    %s\n", name, e.cmd("upstream list"))
		return exitProblem
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}
	if before.Transport != registry.TransportOCI {
		fmt.Fprintf(e.stderr, "%q is a %s entry: only an oci entry runs an image. To change what a stdio\nentry runs, deregister it and register it again -- which puts its tools back\nin review.\n", name, before.Transport)
		return exitCannotRun
	}
	if before.Image == image {
		fmt.Fprintf(e.stdout, "%q already runs %s. Nothing to do.\n", name, image)
		return exitOK
	}
	next := before
	next.Image = image
	if err := next.Validate(); err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	if err := dialTimeRefusal(next); err != nil {
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	}
	tools, err := e.tools().List(e.ctx(), name)
	if err != nil {
		fmt.Fprintf(e.stderr, "quarantine: %v\n", err)
		return exitCannotRun
	}
	after, err := e.images().UpdateImage(e.ctx(), name, image)
	switch {
	case errors.Is(err, registry.ErrInvalid):
		fmt.Fprintf(e.stderr, "%v\n", err)
		return exitCannotRun
	case err != nil:
		fmt.Fprintf(e.stderr, "registry: %v\n", err)
		return exitCannotRun
	}

	var approved, pending, changed int
	for _, t := range tools {
		switch t.Status {
		case quarantine.StatusApproved:
			approved++
		case quarantine.StatusChanged:
			changed++
		default:
			pending++
		}
	}
	fmt.Fprintf(e.stdout, "Updated %q.\n\n", name)
	tw := opTable(e.stdout)
	fmt.Fprintf(tw, "  image was\t%s\n", before.Image)
	fmt.Fprintf(tw, "  image now\t%s\n", after.Image)
	fmt.Fprintf(tw, "  quarantine kept\t%d approved, %d pending, %d changed\n", approved, pending, changed)
	if !opFlushTable(tw, e.stderr) {
		return exitProblem
	}
	oldRepo, _, _ := strings.Cut(before.Image, "@")
	newRepo, _, _ := strings.Cut(after.Image, "@")
	if oldRepo != newRepo {
		fmt.Fprintf(e.stdout, "\nWARNING: the repository changed too (%s -> %s). The approvals are kept\nbecause you said this is the same backend; if it is not, deregister it instead.\n", oldRepo, newRepo)
	}

	fmt.Fprintf(e.stdout, `
The approvals were kept, and each holds only while the new image advertises
exactly the definition that was approved: one whose name, description or
schemas differ becomes CHANGED at the next discovery and is not served until
you review it, like any change to an approved tool. A tool the new image
adds starts pending.
`)
	state, serr := entrySignatureState(e, after)
	switch {
	case serr != nil:
		fmt.Fprintf(e.stderr, "\nWARNING: whether %q is signed could not be determined: %v\n", name, serr)
	case state == sigInvalid:
		fmt.Fprintf(e.stdout, "\nThe stored signature is for the old image and does not verify this entry, so\nthe gateway stops serving %q within one reconciliation interval and refuses\nit -- whatever signer.require_signed says -- until it is signed again. As root:\n\n    %s %s\n", name, e.cmd("sign"), name)
	case state == sigUnsigned && e.cfg.Signer.SignaturesRequired():
		fmt.Fprintf(e.stdout, "\nThe entry is not signed, so the gateway refuses it until it is. As root:\n\n    %s %s\n", e.cmd("sign"), name)
	case state == sigUnsigned:
		fmt.Fprintf(e.stdout, "\nWARNING: the entry is not signed and signer.require_signed is false, so the new\nimage is served from the next reconciliation with no signature. Sign it:\n\n    %s %s\n", e.cmd("sign"), name)
	}
	fmt.Fprintf(e.stdout, "\nAfter it is signed and discovered, see what changed:\n\n    %s -server %s\n", e.cmd("tool review"), opShellQuote(name))

	actor, err := e.operator()
	if err == nil {
		reason := fmt.Sprintf("upstream %q image %s -> %s; quarantine kept: %d approved, %d pending, %d changed; approvals hold only for identical definitions; signature must be renewed %s",
			name, before.Image, after.Image, approved, pending, changed, actor.Tag())
		rec := audit.Record{AnalystIdentity: actor.Identity(), Tool: admin.UpstreamUpdate, TargetUpstream: admin.OperatorTarget,
			Timestamp: time.Now().UTC(), Outcome: audit.OutcomeAllowed, Reason: reason}
		err = retryBusy(e.ctx(), func() error { return e.recordOperatorAction(rec) })
	}
	if err != nil {
		fmt.Fprintf(e.stderr, "\n%q IS UPDATED, but the audit trail could not record it: %v\nRecord it by hand before anything else.\n", name, err)
		return exitProblem
	}
	return exitOK
}
