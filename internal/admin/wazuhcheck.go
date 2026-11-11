package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
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

// wazuhCheckTimeout bounds the whole exchange: the wizard waits on it.
const wazuhCheckTimeout = 5 * time.Second

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
	endpoint := strings.TrimSuffix(w.URL, "/") + "/_plugins/_security/api/internalusers/" + url.PathEscape(username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) // nothing in it is needed

	switch resp.StatusCode {
	case http.StatusOK:
		return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserFound, Message: fmt.Sprintf("Found in Wazuh: %s.", username)}
	case http.StatusNotFound:
		return &adminapi.WazuhUserCheck{Status: adminapi.WazuhUserNotFound, Message: fmt.Sprintf("Not found in Wazuh: %s. Use the same username the person has in the SIEM.", username)}
	case http.StatusUnauthorized, http.StatusForbidden:
		return unchecked(fmt.Sprintf("the indexer refused user %s (HTTP %d)", w.User, resp.StatusCode))
	default:
		return unchecked(fmt.Sprintf("the indexer answered HTTP %d", resp.StatusCode))
	}
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
