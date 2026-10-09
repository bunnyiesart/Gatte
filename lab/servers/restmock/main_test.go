package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The mock's own contract, in-process: the document is JSON, the key is
// demanded, the credcheck tells the truth, /echo reflects the key three
// ways, and the mock's stdout never carries the key. The end-to-end claim
// -- that the gateway masks what /echo reflects -- is the REST probe's
// (internal/gateway/resthttp, TestLabProbeREST), not this file's.

const testSecret = "restmock-test-7f3a9c"

func newTestServer(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	t.Setenv("MOCK_SECRET", testSecret)
	t.Setenv("MOCK_EXPECT", testSecret)
	out := &bytes.Buffer{}
	srv := httptest.NewServer(newHandler(testSecret, newEventLog(out)))
	t.Cleanup(srv.Close)
	return srv, out
}

func get(t *testing.T, url, key string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set(keyHeader, key)
	}
	// No redirects followed: /echo's 302 is the response under test.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestOpenAPIDocumentIsJSONAndPublic(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, body := get(t, srv.URL+"/openapi.json", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /openapi.json without a key = %d, want 200: the document is public", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the document is not JSON: %v", err)
	}
	if doc["openapi"] != "3.0.3" {
		t.Errorf("openapi = %v, want 3.0.3", doc["openapi"])
	}
	servers := doc["servers"].([]any)
	if got := servers[0].(map[string]any)["url"]; !strings.HasSuffix(got.(string), basePath) {
		t.Errorf("servers[0].url = %v, want it to end in %s so the ingestion folds the base path", got, basePath)
	}
	if bytes.Contains(body, []byte(testSecret)) {
		t.Fatal("the document carries the key")
	}
}

func TestOperationsDemandTheKey(t *testing.T) {
	srv, out := newTestServer(t)
	for _, path := range []string{"/check/192.0.2.7", "/echo"} {
		resp, body := get(t, srv.URL+basePath+path, "")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without a key = %d, want 401", path, resp.StatusCode)
		}
		if bytes.Contains(body, []byte(testSecret)) {
			t.Errorf("GET %s without a key: the 401 body quotes the key", path)
		}
		resp, _ = get(t, srv.URL+basePath+path, "wrong-"+testSecret)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s with a wrong key = %d, want 401", path, resp.StatusCode)
		}
	}
	if bytes.Contains(out.Bytes(), []byte(testSecret)) {
		t.Fatalf("stdout carries the key:\n%s", out.String())
	}
	if !strings.Contains(out.String(), `"authorized":false`) {
		t.Errorf("stdout does not record the refused requests:\n%s", out.String())
	}
}

func TestCheckReportsTheCredcheckAndTheParameters(t *testing.T) {
	srv, out := newTestServer(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+basePath+"/check/192.0.2.7?verbose=true", nil)
	req.Header.Set(keyHeader, testSecret)
	req.Header.Set("X-Request-Id", "probe-1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", resp.StatusCode, body)
	}
	var got struct {
		IP        string `json:"ip"`
		Verbose   bool   `json:"verbose"`
		RequestID string `json:"request_id"`
		Credcheck struct {
			Received    bool   `json:"received_expected_secret"`
			Fingerprint string `json:"fingerprint"`
		} `json:"credcheck"`
		Sources map[string]any `json:"sources"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if got.IP != "192.0.2.7" || !got.Verbose || got.RequestID != "probe-1" || got.Sources == nil {
		t.Errorf("parameters did not arrive where the document says: %+v", got)
	}
	if !got.Credcheck.Received || len(got.Credcheck.Fingerprint) != 8 {
		t.Errorf("credcheck = %+v, want received with an 8-hex fingerprint", got.Credcheck)
	}
	if bytes.Contains(body, []byte(testSecret)) || bytes.Contains(out.Bytes(), []byte(testSecret)) {
		t.Fatal("the key appears in the response or on stdout")
	}
	if !strings.Contains(out.String(), `"path":"`+basePath+`/check/192.0.2.7"`) || !strings.Contains(out.String(), `"authorized":true`) {
		t.Errorf("stdout does not record the served request:\n%s", out.String())
	}
}

func TestReportAcceptsEitherBranch(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, tc := range []struct {
		body string
		want int
	}{
		{`{"kind":"ip","ip":"192.0.2.7"}`, http.StatusCreated},
		{`{"kind":"domain","domain":"example.com"}`, http.StatusCreated},
		{`{"kind":"url","url":"x"}`, http.StatusBadRequest},
		{`[]`, http.StatusBadRequest},
	} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+basePath+"/report", strings.NewReader(tc.body))
		req.Header.Set(keyHeader, testSecret)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("POST %s = %d, want %d", tc.body, resp.StatusCode, tc.want)
		}
	}
}

func TestEchoReflectsTheKeyThreeWays(t *testing.T) {
	srv, out := newTestServer(t)
	resp, body := get(t, srv.URL+basePath+"/echo", testSecret)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, testSecret) {
		t.Errorf("Location = %q, want it to carry the key (that is the scenario)", loc)
	}
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, testSecret) {
		t.Errorf("Set-Cookie = %q, want it to carry the key", sc)
	}
	if !bytes.Contains(body, []byte(testSecret)) {
		t.Errorf("body = %s, want it to carry the key", body)
	}
	// The reflection is in the response, by design -- and still never on
	// the mock's own stdout, which only ever says path and credcheck.
	if bytes.Contains(out.Bytes(), []byte(testSecret)) {
		t.Fatalf("stdout carries the key:\n%s", out.String())
	}
}
