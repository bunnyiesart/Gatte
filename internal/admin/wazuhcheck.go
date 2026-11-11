package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/egress"
	"github.com/bunnyiesart/Gatte/internal/vault"
	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

// The Wazuh username check (design/adr/0063): on the account check, ask
// the Wazuh indexer's security plugin whether the username exists there,
// so a person's Gatte name matches the one the SIEM uses. Its answer is a
// line on the check, never a refusal, and an indexer that cannot be asked
// costs the wizard at most wazuhCheckTimeout.

// wazuhCheckTimeout bounds the whole exchange: the wizard waits on it. A
// variable only so a test can shorten it.
var wazuhCheckTimeout = 5 * time.Second

// wazuhCacheTTL is how long a found / not-found answer for one name is
// reused. The wizard re-checks on every step, and the indexer account
// holds REST API admin rights, so repeated asks are kept off it; it also
// slows walking the indexer's user list through this check.
const wazuhCacheTTL = 60 * time.Second

// wazuhCacheMax bounds the cache; past it, the cache is dropped whole.
const wazuhCacheMax = 256

// wazuhCache holds recent definite answers, keyed by indexer, user and name.
type wazuhCache struct {
	mu sync.Mutex
	m  map[string]wazuhCached
}

type wazuhCached struct {
	at  time.Time
	ans adminapi.WazuhUserCheck
}

func (c *wazuhCache) get(key string, now time.Time) (adminapi.WazuhUserCheck, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok || now.Sub(e.at) >= wazuhCacheTTL {
		return adminapi.WazuhUserCheck{}, false
	}
	return e.ans, true
}

func (c *wazuhCache) put(key string, now time.Time, ans adminapi.WazuhUserCheck) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= wazuhCacheMax {
		c.m = map[string]wazuhCached{}
	}
	c.m[key] = wazuhCached{at: now, ans: ans}
}

// wazuhAddrPolicy is the egress policy for the indexer. Unlike a
// backend's URL, which reaches the registry through the console, this
// URL is written by root in config.toml, and a SIEM indexer normally sits
// on the SOC's private network: private ranges are allowed. Everything
// else egress.RefuseAddr refuses stays refused -- loopback, link-local
// (the cloud metadata address), multicast and the rest.
func wazuhAddrPolicy(a netip.Addr) error {
	if a.Unmap().IsPrivate() {
		return nil
	}
	return egress.RefuseAddr(a)
}

// wazuhUser asks the indexer about username. nil when the check is off.
func (s *Service) wazuhUser(ctx context.Context, cfg *config.Config, username string) *adminapi.WazuhUserCheck {
	w := cfg.IdP.WazuhCheck
	if !w.Enabled() {
		return nil
	}
	key := w.URL + "\x00" + w.User + "\x00" + username
	if ans, ok := s.wazuh.get(key, s.d.Now()); ok {
		return &ans
	}
	unchecked := func(why string) *adminapi.WazuhUserCheck {
		return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserUnchecked, Message: "Could not check Wazuh: " + why + "."}
	}
	if s.d.ResolveSecret == nil {
		return unchecked("this backend cannot read the vault")
	}
	ctx, cancel := context.WithTimeout(ctx, wazuhCheckTimeout)
	defer cancel()

	pw, err := s.d.ResolveSecret(ctx, cfg, w.PasswordName)
	if errors.Is(err, vault.ErrNotFound) {
		return unchecked(fmt.Sprintf("the vault has no value named %s", w.PasswordName))
	}
	if err != nil {
		// A vault error never carries a value (vault.Provider's contract).
		s.d.Log.Warn("wazuh check: reading the vault", "name", w.PasswordName, "err", err)
		return unchecked("the vault could not be read")
	}

	client, err := wazuhClient(w, s.d.WazuhEgress)
	if err != nil {
		return unchecked(err.Error())
	}
	base, err := url.Parse(w.URL)
	if err != nil {
		return unchecked("the configured url does not parse")
	}
	// JoinPath escapes the name as one path segment, so a name cannot walk
	// to another endpoint of the indexer.
	endpoint := base.JoinPath("_plugins", "_security", "api", "internalusers", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return unchecked("the request could not be built")
	}
	req.SetBasicAuth(w.User, pw.Value())
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return unchecked(wazuhReason(err))
	}
	defer resp.Body.Close()

	var ans adminapi.WazuhUserCheck
	switch resp.StatusCode {
	case http.StatusOK:
		// A 200 counts only when it is the internal-users answer for this
		// name: a JSON object with the name as a top-level key. Anything
		// else (a proxy page, the cluster banner) would call every name found.
		var body map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
			return unchecked("the indexer's answer is not the internal users API")
		}
		if _, ok := body[username]; !ok {
			return unchecked("the indexer's answer does not name the user")
		}
		ans = adminapi.WazuhUserCheck{Status: adminapi.WazuhUserFound, Message: fmt.Sprintf("Found in Wazuh: %s.", username)}
	case http.StatusNotFound:
		ans = adminapi.WazuhUserCheck{Status: adminapi.WazuhUserNotFound, Message: fmt.Sprintf("Not found in Wazuh: %s. Use the same username the person has in the SIEM.", username)}
	case http.StatusUnauthorized, http.StatusForbidden:
		return unchecked(fmt.Sprintf("the indexer refused user %s (HTTP %d)", w.User, resp.StatusCode))
	default:
		return unchecked(fmt.Sprintf("the indexer answered HTTP %d", resp.StatusCode))
	}
	s.wazuh.put(key, s.d.Now(), ans)
	return &ans
}

// wazuhClient is an HTTP client pinned to the indexer: the shared egress
// transport (no proxy, every resolved address judged), certificate
// verification on, against ca_file when set, and no redirect followed --
// the request carries the password.
func wazuhClient(w config.WazuhCheck, guard egress.Guard) (*http.Client, error) {
	if guard.Policy == nil {
		guard.Policy = wazuhAddrPolicy
	}
	tr := guard.Transport()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if w.CAFile != "" {
		pem, err := os.ReadFile(w.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file %s could not be read", w.CAFile)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificate", w.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	tr.TLSClientConfig = tlsCfg
	return &http.Client{
		Transport:     tr,
		Timeout:       wazuhCheckTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// wazuhReason turns a transport error into a short reason. It never
// includes the request (whose header holds the password); the URL a
// *url.Error carries holds none, but the reason is built from its cause.
func wazuhReason(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return fmt.Sprintf("no answer within %s", wazuhCheckTimeout)
	case errors.Is(err, egress.ErrRefused):
		return "the indexer's address is not one this backend may reach (loopback, link-local or reserved)"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "the indexer's certificate is not trusted (set ca_file to its CA)"
	}
	return "could not reach the indexer: " + err.Error()
}
