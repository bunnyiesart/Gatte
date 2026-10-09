package adminhttp_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
	"github.com/bunnyiesart/Gatte/internal/audit"
	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The routes of design/adr/0050: the registry's on the operator socket,
// the ones that need root on the accounts socket, each absent from the
// other, and the feature listed in whoami only while the key is on.

type manageRoute struct{ method, path, body, socket string }

var manageRoutes = []manageRoute{
	{"GET", "/v1/upstreams/casemgmt", "", adminapi.SocketOperator},
	{"POST", "/v1/upstreams", `{"name":"x","url":"https://x.example","openapi_document":"{}"}`, adminapi.SocketOperator},
	{"DELETE", "/v1/upstreams/casemgmt", `{"confirm":"casemgmt"}`, adminapi.SocketOperator},
	{"POST", "/v1/upstreams/casemgmt/sign", "", adminapi.SocketAccounts},
	{"GET", "/v1/secrets", "", adminapi.SocketAccounts},
	{"PUT", "/v1/secrets/CASEMGMT_TOKEN", `{"value":"v"}`, adminapi.SocketAccounts},
	{"DELETE", "/v1/secrets/CASEMGMT_TOKEN", "", adminapi.SocketAccounts},
	{"GET", "/v1/roles", "", adminapi.SocketAccounts},
	{"PUT", "/v1/roles", `{"text":""}`, adminapi.SocketAccounts},
}

func manageService(t *testing.T, on bool) *admin.Service {
	t.Helper()
	cfg := &config.Config{Admin: config.Admin{ConsoleManages: on}}
	svc, err := admin.New(admin.Deps{
		Config: func() (*config.Config, error) { return cfg, nil },
		Record: func(context.Context, *config.Config, audit.Record) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestManageRoutes_OnTheirSocketOnlyAndFeatureDisabledWithTheKeyOff(t *testing.T) {
	svc := manageService(t, false)
	op, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: svc})
	acc, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: svc})
	for _, r := range manageRoutes {
		right, wrong, other := op, acc, adminapi.SocketAccounts
		if r.socket == adminapi.SocketAccounts {
			right, wrong, other = acc, op, adminapi.SocketOperator
		}
		if status, code, body := call(t, right, r.method, r.path, r.body, nil); status != 403 || code != adminapi.CodeFeatureDisabled {
			t.Errorf("%s %s on its socket with the key off: %d %s %s", r.method, r.path, status, code, body)
		}
		status, code, body := call(t, wrong, r.method, r.path, r.body, nil)
		if status != 404 || code != adminapi.CodeWrongSocket || !strings.Contains(string(body), `"socket":"`+r.socket+`"`) {
			t.Errorf("%s %s on the %s socket: %d %s %s", r.method, r.path, other, status, code, body)
		}
	}
	// The older routes under /v1/upstreams/ are still theirs.
	if status, code, _ := call(t, op, "GET", "/v1/upstreams/redial", "", nil); status != 405 || code != adminapi.CodeMethodNotAllowed {
		t.Errorf("GET /v1/upstreams/redial: %d %s", status, code)
	}
}

func TestWhoAmI_ListsConsoleManagesOnlyWhileTheKeyIsOn(t *testing.T) {
	for _, on := range []bool{false, true} {
		sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketOperator, Service: manageService(t, on)})
		_, _, body := call(t, sock, "GET", "/v1/whoami", "", nil)
		var me adminapi.WhoAmI
		if err := json.Unmarshal(body, &me); err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(me.Features, adminapi.FeatureConsoleManages); got != on {
			t.Errorf("console_manages %v: features %v", on, me.Features)
		}
	}
}

func TestManageRoutes_TheDocumentRoutesTakeABodyOverTheDefaultLimit(t *testing.T) {
	sock, _ := serve(t, adminhttp.Options{Socket: adminapi.SocketAccounts, Service: manageService(t, true)})
	big := `{"text":"` + strings.Repeat("#", adminhttp.MaxBody+1) + `"}`
	// Over 64 KiB and under the roles limit: decoded, and refused by the
	// service (no roles_file here), not by the body limit.
	if status, code, body := call(t, sock, "PUT", "/v1/roles", big, nil); code == adminapi.CodePayloadTooLarge {
		t.Fatalf("PUT /v1/roles over 64 KiB: %d %s %s", status, code, body)
	}
	// Every other route keeps the 64 KiB.
	if status, code, _ := call(t, sock, "POST", "/v1/upstreams/x/sign", `{"pad":"`+strings.Repeat("#", adminhttp.MaxBody+1)+`"}`, nil); status != 413 || code != adminapi.CodePayloadTooLarge {
		t.Fatalf("sign with an oversized body: %d %s", status, code)
	}
}
