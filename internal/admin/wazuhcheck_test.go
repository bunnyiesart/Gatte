package admin_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/egress"
	"github.com/bunnyiesart/Gatte/internal/idp"
	"github.com/bunnyiesart/Gatte/internal/idp/autheliafile"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// wazuhPassword is the indexer password the fake vault holds; no answer
// may carry it.
const wazuhPassword = "lab-only-indexer-pass"

// wazuhIndexer is a fake indexer that knows "dora" (not yet a Gatte account) and checks the
// credential it is sent.
func wazuhIndexer(t *testing.T, slow bool) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if slow {
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			return
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "gatte-check" || p != wazuhPassword {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/_plugins/_security/api/internalusers/dora":
			_, _ = w.Write([]byte(`{"dora":{"hash":"","backend_roles":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, ca
}

// wazuhService is the harness's service with the check pointed at srv.
// allowLoopback lets the egress guard reach httptest.
func wazuhService(t *testing.T, check config.WazuhCheck, allowLoopback bool) *admin.Service {
	t.Helper()
	h := newHarness(t)
	cfg := *h.cfg
	cfg.IdP.WazuhCheck = check
	d := admin.Deps{
		Config:   func() (*config.Config, error) { return &cfg, nil },
		Tools:    h.tools,
		Blocks:   h.blocks,
		Trail:    h.trail,
		Record:   func(context.Context, *config.Config, audit.Record) error { return nil },
		Accounts: func(cfg *config.Config) (idp.Directory, error) { return autheliafile.New(cfg.IdP.UsersFile), nil },
	}
	d.ResolveSecret = func(_ context.Context, _ *config.Config, name string) (vault.Secret, error) {
		if name != "WAZUH_CHECK_PASSWORD" {
			return vault.Secret{}, vault.ErrNotFound
		}
		return vault.NewSecret(wazuhPassword), nil
	}
	if allowLoopback {
		d.WazuhEgress = egress.Guard{Policy: func(netip.Addr) error { return nil }}
	}
	svc, err := admin.New(d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCheckAccount_Wazuh(t *testing.T) {
	srv, ca := wazuhIndexer(t, false)
	on := config.WazuhCheck{URL: srv.URL, User: "gatte-check", PasswordName: "WAZUH_CHECK_PASSWORD", CAFile: ca}

	cases := []struct {
		name     string
		check    config.WazuhCheck
		loopback bool
		username string
		status   string // "" means no wazuh_user at all
		say      string
	}{
		{"found", on, true, "dora", adminapi.WazuhUserFound, "Found in Wazuh"},
		{"not found", on, true, "carla.dias", adminapi.WazuhUserNotFound, "same username the person has in the SIEM"},
		{"disabled", config.WazuhCheck{}, true, "carla.dias", "", ""},
		{"username with a problem is not checked", on, true, "bad name!", "", ""},
		{"wrong credential name", withPassword(on, "MISSING"), true, "dora", adminapi.WazuhUserUnchecked, "no value named MISSING"},
		{"untrusted certificate", withCA(on, ""), true, "dora", adminapi.WazuhUserUnchecked, "certificate is not trusted"},
		{"loopback refused by the default guard", on, false, "dora", adminapi.WazuhUserUnchecked, "may reach"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := wazuhService(t, c.check, c.loopback)
			res, err := svc.CheckAccount(context.Background(), adminapi.AccountDraft{Username: c.username, DisplayName: "New Hire"})
			if err != nil {
				t.Fatal(err)
			}
			assertNoPassword(t, res)
			if c.status == "" {
				if res.WazuhUser != nil {
					t.Fatalf("wazuh_user %+v, want none", res.WazuhUser)
				}
				return
			}
			if res.WazuhUser == nil || res.WazuhUser.Status != c.status || !strings.Contains(res.WazuhUser.Message, c.say) {
				t.Fatalf("wazuh_user %+v, want %s saying %q", res.WazuhUser, c.status, c.say)
			}
			if c.status == adminapi.WazuhUserNotFound && !res.OK {
				t.Fatalf("a username not in Wazuh made the check fail: %+v", res)
			}
		})
	}
}

// TestCheckAccount_WazuhTimeout: an indexer that does not answer costs the
// wizard a bounded wait and answers unchecked, never an error.
func TestCheckAccount_WazuhTimeout(t *testing.T) {
	srv, ca := wazuhIndexer(t, true)
	svc := wazuhService(t, config.WazuhCheck{URL: srv.URL, User: "gatte-check", PasswordName: "WAZUH_CHECK_PASSWORD", CAFile: ca}, true)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := svc.CheckAccount(ctx, adminapi.AccountDraft{Username: "dora", DisplayName: "Dora"})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("the check waited %s", time.Since(start))
	}
	if res.WazuhUser == nil || res.WazuhUser.Status != adminapi.WazuhUserUnchecked || !strings.Contains(res.WazuhUser.Message, "no answer") {
		t.Fatalf("wazuh_user %+v, want unchecked with no answer", res.WazuhUser)
	}
	assertNoPassword(t, res)
}

func withPassword(w config.WazuhCheck, name string) config.WazuhCheck {
	w.PasswordName = name
	return w
}
func withCA(w config.WazuhCheck, ca string) config.WazuhCheck { w.CAFile = ca; return w }

func assertNoPassword(t *testing.T, res adminapi.AccountCheck) {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), wazuhPassword) {
		t.Fatalf("the answer carries the indexer password: %s", b)
	}
}
