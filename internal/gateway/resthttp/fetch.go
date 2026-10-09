package resthttp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// MaxDocumentBytes is the ceiling Ingest applies to an OpenAPI document,
// exported so that the console reads a file, or FetchDocument a URL, up to
// the same number and no further: a document that cannot be ingested is not
// worth holding in memory first.
const MaxDocumentBytes = maxDocumentBytes

// ErrFetchFailed means FetchDocument reached the server (or tried to) and
// came back without the document: a transport error, a status other than
// 200, or a body over the ceiling. An error wrapping it names the method and
// URL that was requested -- which parseBase guarantees carries no userinfo,
// query or fragment, so no credential can be in it -- and still answers
// errors.Is for ErrEgressRefused, ErrBodyTooLarge and the context errors.
var ErrFetchFailed = errors.New("resthttp: openapi document fetch failed")

// FetchDocument retrieves one OpenAPI document from rawURL for the operator
// console's `upstream register -openapi URL`, under the SAME egress guard
// the adapter applies to a tool call (ADR-0048 Decisão 6): the transport is
// newTransport (no proxy, resolved-address policy in dialPinned and in
// net.Dialer.Control, no keep-alive), a redirect off the document's origin
// is refused by base.checkRedirect, and a literal host the policy refuses is
// refused before any socket is opened. It is the one function of this
// package that does I/O outside a call, and it is the console's, never the
// serving gateway's: the set is frozen at register (ADR-0047 §3) and nothing
// re-fetches it.
//
// The request carries no credential of any kind -- no Authorization, no
// cookie, nothing from the environment -- and none can be smuggled in the
// URL, because parseBase refuses userinfo, a query and a fragment. A
// document that needs a credential to read is downloaded by the operator
// and passed as a file; this is a deliberate limitation, not an omission: a
// key typed into a URL would be sent on the wire here and printed in every
// error that names the URL.
//
// Pre-condition: rawURL is an http or https URL parseBase accepts; maxBytes
// <= 0 selects MaxDocumentBytes. Post-condition: on nil error the result is
// the whole body of a 200 response of at most maxBytes; every non-nil error
// wraps ErrInvalidURL (the URL itself, before any I/O) or ErrFetchFailed,
// and never contains a credential, since none was available here.
func (d *Dialer) FetchDocument(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxDocumentBytes
	}
	b, err := parseBase(rawURL)
	if err != nil {
		return nil, err
	}
	// d.egress, not refuseAddr, for the same reason Dial uses it: the
	// test-only loopback allowance (export_test.go) must apply here exactly
	// as it does at the socket, and nothing outside _test.go changes it.
	if err := b.literalHostRefusal(d.egress); err != nil {
		return nil, err
	}
	path := b.path
	if path == "" {
		path = "/"
	}
	target := &url.URL{Scheme: b.scheme, Host: b.host, Path: path}
	where := b.origin + path

	client := &http.Client{
		Transport:     d.newTransport(),
		Timeout:       d.timeout,
		CheckRedirect: b.checkRedirect,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	req.Header.Set("Accept", "application/json, application/yaml, application/x-yaml, text/yaml;q=0.9, */*;q=0.1")

	resp, err := client.Do(req)
	if err != nil {
		// A *url.Error prints the request URL, which is fine here (nothing
		// secret can be in it) but redundant with `where`; its inner error
		// is what the operator needs, and wrapping that keeps errors.Is for
		// ErrEgressRefused and the context errors.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("%w: GET %s: %w", ErrFetchFailed, where, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Past maxRedirects, checkRedirect hands the last 3xx back as the
		// response, so a redirect loop lands here as "answered 302".
		return nil, fmt.Errorf("%w: GET %s answered %s", ErrFetchFailed, where, resp.Status)
	}
	body, err := readBody(resp.Body, maxBytes)
	if err != nil {
		if errors.Is(err, ErrBodyTooLarge) {
			return nil, fmt.Errorf("%w: GET %s: %w (the ingestion reads at most %d bytes)", ErrFetchFailed, where, err, maxBytes)
		}
		return nil, fmt.Errorf("%w: GET %s: read body: %w", ErrFetchFailed, where, err)
	}
	return body, nil
}
