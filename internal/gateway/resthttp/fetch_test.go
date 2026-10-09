package resthttp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
)

// FetchDocument is the console's one network read at register time (the
// -openapi URL), and these tests pin that it is the adapter's egress guard
// that reads it: same transport, same resolved-address policy, same origin
// pin on redirects, and never a credential on the wire. The loopback
// allowance is the test-only hook of export_test.go, as for every other
// httptest-backed test in this package.

const fetchedDoc = `{"openapi":"3.0.3","info":{"title":"t","version":"1"},"paths":{}}`

// TestFetchDocument_ReturnsTheBytesAndSendsNoCredential: the body comes back
// whole, as one GET, with nothing that could be a credential on the request.
func TestFetchDocument_ReturnsTheBytesAndSendsNoCredential(t *testing.T) {
	// A credential in the environment must not reach the request either:
	// nothing reads the environment, and this makes "nothing" testable.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")

	srv, got := recorder(t, http.StatusOK, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(fetchedDoc))
	})
	d := newDialer(t, nil)

	body, err := d.FetchDocument(context.Background(), srv.URL+"/openapi.json", 0)
	if err != nil {
		t.Fatalf("FetchDocument: %v", err)
	}
	if string(body) != fetchedDoc {
		t.Fatalf("body = %q, want the document", body)
	}
	if got.Method != http.MethodGet || got.Path != "/openapi.json" {
		t.Errorf("request = %s %s, want GET /openapi.json", got.Method, got.Path)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-Api-Key", "Proxy-Authorization"} {
		if v := got.Header.Get(h); v != "" {
			t.Errorf("request carried %s: %q; the fetch sends no credential", h, v)
		}
	}
	if !strings.Contains(got.Header.Get("Accept"), "application/json") {
		t.Errorf("Accept = %q, want JSON and YAML media types", got.Header.Get("Accept"))
	}
}

// TestFetchDocument_LoopbackIsRefusedWithoutTheTestHook: a production
// Dialer refuses a loopback document URL before any request leaves. This
// is what `upstream register -openapi http://127.0.0.1/...` meets at the
// prompt, and why the console's own URL test can only prove the refusal.
func TestFetchDocument_LoopbackIsRefusedWithoutTheTestHook(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(fetchedDoc))
	}))
	t.Cleanup(srv.Close)

	_, err := resthttp.New(nil).FetchDocument(context.Background(), srv.URL+"/openapi.json", 0)
	if !errors.Is(err, resthttp.ErrEgressRefused) || !errors.Is(err, resthttp.ErrInvalidURL) {
		t.Fatalf("FetchDocument(loopback) = %v, want ErrInvalidURL wrapping ErrEgressRefused", err)
	}
	if hits.Load() != 0 {
		t.Errorf("the server was reached %d times; a refused literal host must not be dialled", hits.Load())
	}
}

// TestFetchDocument_RefusesACrossOriginRedirect: a Location that leaves the
// document's origin is not followed (ADR-0048 Decisão 6, the structural
// host-pin), and the server it names never sees a request. A same-origin
// redirect is followed, as a tool call's would be.
func TestFetchDocument_RefusesACrossOriginRedirect(t *testing.T) {
	var elsewhereHits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereHits.Add(1)
		_, _ = w.Write([]byte(fetchedDoc))
	}))
	t.Cleanup(elsewhere.Close)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, elsewhere.URL+"/openapi.json", http.StatusFound)
		case "/old":
			http.Redirect(w, r, "/openapi.json", http.StatusMovedPermanently)
		default:
			_, _ = w.Write([]byte(fetchedDoc))
		}
	}))
	t.Cleanup(srv.Close)
	d := newDialer(t, nil)

	_, err := d.FetchDocument(context.Background(), srv.URL+"/away", 0)
	if !errors.Is(err, resthttp.ErrEgressRefused) || !errors.Is(err, resthttp.ErrFetchFailed) {
		t.Fatalf("FetchDocument(cross-origin redirect) = %v, want ErrFetchFailed wrapping ErrEgressRefused", err)
	}
	if elsewhereHits.Load() != 0 {
		t.Errorf("the redirect target was reached %d times", elsewhereHits.Load())
	}
	if strings.Contains(err.Error(), "/openapi.json") {
		t.Errorf("the refusal repeats the Location's path: %v", err)
	}

	body, err := d.FetchDocument(context.Background(), srv.URL+"/old", 0)
	if err != nil || string(body) != fetchedDoc {
		t.Fatalf("FetchDocument(same-origin redirect) = %q, %v; want the document", body, err)
	}
}

// TestFetchDocument_CeilingAndStatus: a body over maxBytes is refused whole,
// and anything but 200 is a failed fetch, not a document.
func TestFetchDocument_CeilingAndStatus(t *testing.T) {
	big := strings.Repeat("x", 100)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(big))
		case "/missing":
			http.NotFound(w, r)
		default:
			_, _ = w.Write([]byte(fetchedDoc))
		}
	}))
	t.Cleanup(srv.Close)
	d := newDialer(t, nil)

	_, err := d.FetchDocument(context.Background(), srv.URL+"/big", int64(len(big)-1))
	if !errors.Is(err, resthttp.ErrBodyTooLarge) || !errors.Is(err, resthttp.ErrFetchFailed) {
		t.Errorf("FetchDocument(over the ceiling) = %v, want ErrFetchFailed wrapping ErrBodyTooLarge", err)
	}
	if body, err := d.FetchDocument(context.Background(), srv.URL+"/big", int64(len(big))); err != nil || len(body) != len(big) {
		t.Errorf("FetchDocument(exactly the ceiling) = %d bytes, %v; want %d bytes", len(body), err, len(big))
	}
	_, err = d.FetchDocument(context.Background(), srv.URL+"/missing", 0)
	if !errors.Is(err, resthttp.ErrFetchFailed) || !strings.Contains(err.Error(), "404") {
		t.Errorf("FetchDocument(404) = %v, want ErrFetchFailed naming the status", err)
	}
	// MaxDocumentBytes is the ingestion's own ceiling, and 0 selects it.
	if resthttp.MaxDocumentBytes != 4<<20 {
		t.Errorf("MaxDocumentBytes = %d, want 4 MiB (the Ingest ceiling)", resthttp.MaxDocumentBytes)
	}
}

// TestFetchDocument_URLRulesAreTheBaseURLRules: the document URL is judged
// by parseBase before any I/O, so a credential cannot ride in it (userinfo,
// query) and a literal forbidden host is refused without a resolver. The
// refusal of a URL with userinfo never echoes the userinfo.
func TestFetchDocument_URLRulesAreTheBaseURLRules(t *testing.T) {
	d := resthttp.New(nil)
	for _, raw := range []string{
		"https://user:hunter2@api.example.com/openapi.json",
		"https://api.example.com/openapi.json?token=hunter2",
		"https://api.example.com/openapi.json#hunter2",
		"ftp://api.example.com/openapi.json",
		"https:///openapi.json",
		"",
	} {
		_, err := d.FetchDocument(context.Background(), raw, 0)
		if !errors.Is(err, resthttp.ErrInvalidURL) {
			t.Errorf("FetchDocument(%q) = %v, want ErrInvalidURL", raw, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("FetchDocument(%q) echoed the URL's secret part: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://169.254.169.254/openapi.json", "http://10.0.0.1/openapi.json", "http://[::1]/openapi.json"} {
		_, err := d.FetchDocument(context.Background(), raw, 0)
		if !errors.Is(err, resthttp.ErrInvalidURL) || !errors.Is(err, resthttp.ErrEgressRefused) {
			t.Errorf("FetchDocument(%q) = %v, want ErrInvalidURL wrapping ErrEgressRefused", raw, err)
		}
	}
}
