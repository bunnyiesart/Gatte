package gatteweb

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestServerNewPage_NoRolePrefill: the Add API form offers the grant field
// with a placeholder, not a prefilled "analyst" value, so registering never
// grants to a role the operator did not name (and that may not exist).
func TestServerNewPage_NoRolePrefill(t *testing.T) {
	f := testFront(t)
	w := httptest.NewRecorder()
	f.routes().ServeHTTP(w, httptest.NewRequest("GET", "/servers/new", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /servers/new: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	if !strings.Contains(s, `name="grant_role"`) {
		t.Fatal("the Add API form has no grant_role field")
	}
	if !strings.Contains(s, `placeholder="e.g. analyst"`) {
		t.Error("the grant_role field should carry a placeholder, not a prefill")
	}
	if strings.Contains(s, `value="analyst"`) {
		t.Error("the grant_role field still prefills \"analyst\"")
	}
}

// TestServerRegister_GrantFailureGetsOwnNotice: when the named role does not
// exist, the grant's refusal is its own error notice on the result page, not a
// line folded into the registration's status blob where it would be missed.
func TestServerRegister_GrantFailureGetsOwnNotice(t *testing.T) {
	f := testFront(t)
	form := url.Values{"name": {"testapi"}, "url": {"https://api.example.com"}, "grant_role": {"ghost"}}
	r := httptest.NewRequest("POST", "/servers", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	f.routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /servers: %d\n%s", w.Code, w.Body)
	}
	s := w.Body.String()
	msg := "no [[role]] named ghost"
	i := strings.Index(s, msg)
	if i < 0 {
		t.Fatalf("the grant refusal is missing from the result page:\n%s", s)
	}
	// The refusal must sit in an error notice, not the success status notice.
	notice := strings.LastIndex(s[:i], "<div class=\"notice")
	if notice < 0 || !strings.HasPrefix(s[notice:], `<div class="notice error"`) {
		t.Errorf("the grant refusal is not in a notice error block:\n%s", s[max(0, i-120):i+len(msg)])
	}
}
