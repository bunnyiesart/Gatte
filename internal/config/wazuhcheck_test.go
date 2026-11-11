package config

import (
	"strings"
	"testing"
)

// TestWazuhCheck: [idp.wazuh_check] is off unless url is set, loads in its
// documented shape, and refuses each malformed key by name.
func TestWazuhCheck(t *testing.T) {
	if c := mustLoad(t, minimalConfig); c.IdP.WazuhCheck.Enabled() {
		t.Fatal("the check is on with no [idp.wazuh_check]")
	}

	good := minimalConfig + `
[idp.wazuh_check]
url           = "https://wazuh-indexer.example:9200"
user          = "gatte-check"
password_name = "WAZUH_CHECK_PASSWORD"
ca_file       = "/usr/local/etc/mcp-gateway/wazuh-ca.pem"
`
	c := mustLoad(t, good)
	if w := c.IdP.WazuhCheck; !w.Enabled() || w.User != "gatte-check" || w.PasswordName != "WAZUH_CHECK_PASSWORD" {
		t.Fatalf("loaded %+v", w)
	}

	bad := map[string]struct{ from, to, want string }{
		"http":             {`"https://wazuh-indexer.example:9200"`, `"http://wazuh-indexer.example:9200"`, "idp.wazuh_check.url"},
		"path":             {`"https://wazuh-indexer.example:9200"`, `"https://wazuh-indexer.example:9200/x"`, "idp.wazuh_check.url"},
		"userinfo":         {`"https://wazuh-indexer.example:9200"`, `"https://a:b@wazuh-indexer.example:9200"`, "idp.wazuh_check.url"},
		"no user":          {`"gatte-check"`, `""`, "idp.wazuh_check.user"},
		"colon in user":    {`"gatte-check"`, `"gatte:check"`, "idp.wazuh_check.user"},
		"value not name":   {`"WAZUH_CHECK_PASSWORD"`, `"s3cr3t-value!"`, "idp.wazuh_check.password_name"},
		"relative ca":      {`"/usr/local/etc/mcp-gateway/wazuh-ca.pem"`, `"wazuh-ca.pem"`, "idp.wazuh_check.ca_file"},
		"keys without url": {`"https://wazuh-indexer.example:9200"`, `""`, "url is empty"},
	}
	for name, b := range bad {
		t.Run(name, func(t *testing.T) {
			err := loadErr(t, strings.Replace(good, b.from, b.to, 1))
			if !strings.Contains(err.Error(), b.want) {
				t.Fatalf("error %v, want it to name %s", err, b.want)
			}
		})
	}

	t.Run("no vault", func(t *testing.T) {
		err := loadErr(t, withoutLine(t, good, "secrets_file"))
		if !strings.Contains(err.Error(), "idp.wazuh_check") {
			t.Fatalf("error %v, want it to name idp.wazuh_check", err)
		}
	})
}
