package oidc

import (
	"errors"
	"net/http"
	"sync"
	"time"
)

// jwksRefetchInterval is the least time between two requests to the
// IdP's JWKS endpoint (design/adr/0035).
//
// go-oidc refetches the key set whenever a token names a kid it has not
// cached or fails its signature, and it has no cooldown. Every forged
// token an anonymous caller sent therefore became one request from this
// gateway to the IdP. Thirty seconds bounds that to two a minute whatever
// the traffic. The cost is paid once per key rotation: a token under a new
// key within thirty seconds of the previous fetch is refused until the
// window passes -- a retry, not an outage.
const jwksRefetchInterval = 30 * time.Second

// errRefetchLimited is what the key set sees when a fetch is refused. It
// becomes an ordinary rejection; the cached keys are kept.
var errRefetchLimited = errors.New("oidc: jwks refetch limited; retry after the window")

// refetchLimiter is the RoundTripper of the key set's HTTP client, and of
// nothing else: discovery goes through the unwrapped client. Attempts are
// counted, not successes, so a failing IdP is not hammered either.
//
// What is counted is a fetch, not a round trip. http.Client follows a
// redirect by calling RoundTrip again with r.Response set to the 3xx that
// led there; those hops belong to a fetch already admitted and pass. The
// client's own redirect cap (ten) bounds them.
type refetchLimiter struct {
	next     http.RoundTripper
	now      func() time.Time
	interval time.Duration

	mu   sync.Mutex
	last time.Time
}

func (l *refetchLimiter) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Response != nil {
		return l.next.RoundTrip(r)
	}
	l.mu.Lock()
	t := l.now()
	if !l.last.IsZero() && t.Sub(l.last) < l.interval {
		l.mu.Unlock()
		if r.Body != nil {
			_ = r.Body.Close()
		}
		return nil, errRefetchLimited
	}
	l.last = t
	l.mu.Unlock()
	return l.next.RoundTrip(r)
}

// limitedClient returns a copy of client whose requests go through a
// refetchLimiter.
func limitedClient(client *http.Client, now func() time.Time) *http.Client {
	next := client.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	if now == nil {
		now = time.Now
	}
	limited := *client
	limited.Transport = &refetchLimiter{next: next, now: now, interval: jwksRefetchInterval}
	return &limited
}
