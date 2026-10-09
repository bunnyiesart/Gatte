package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	gwoci "github.com/bunnyiesart/Gatte/internal/gateway/oci"
	gwrest "github.com/bunnyiesart/Gatte/internal/gateway/resthttp"
	gwstdio "github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	"github.com/bunnyiesart/Gatte/internal/registry"
	"github.com/bunnyiesart/Gatte/internal/vault"
)

// transportDialer routes each registry entry to the adapter for its
// transport: a local process (stdio), an ephemeral, digest-pinned
// container (oci), or a REST API the gateway itself calls (http). The oci
// adapter wraps the stdio one -- the container is a stdio child that is
// `podman run --rm -i` -- so the protocol handling, the built-not-inherited
// child environment, and dead-upstream detection are the same code for both
// (ported from the internal line, 28 Sep 2026). The http adapter is a
// different shape altogether: no process, no connection, one stateless
// upstream per entry whose every call re-resolves the entry's secret
// through the vault (design/adr/0047 §2, §5; design/adr/0048 Decisões 6, 7,
// 9). This struct is the only place the three meet.
type transportDialer struct {
	stdio    gateway.Dialer
	oci      gateway.Dialer
	resthttp gateway.Dialer
	// allowCredentialedStdio is [upstreams] allow_credentialed_stdio. See
	// credentialedStdioRefusal.
	allowCredentialedStdio bool
}

var _ gateway.Dialer = transportDialer{}

// newTransportDialer wires the three adapters. credentials is the Credential
// Vault the http adapter resolves a secret through on every call; the stdio
// and oci adapters never see it, because the gateway hands them the resolved
// values at dial time and nothing after that (ADR-0047 §5 is explicit that
// http is the "third place that touches plaintext", and this is where that
// place is given its vault). A nil credentials is accepted: the adapter then
// serves keyless http entries and refuses keyed ones at dial.
func newTransportDialer(cfg *config.Config, credentials vault.Provider) transportDialer {
	spawn := gwstdio.New(gwstdio.WithClientInfo("mcp-gateway", buildVersion))
	return transportDialer{
		stdio: spawn,
		oci: gwoci.New(spawn,
			gwoci.WithCleanupEnv(gwstdio.DefaultInheritedEnv()...),
			gwoci.WithLimits(ociLimits(cfg.OCI))),
		resthttp: gwrest.New(credentials,
			// The adapter's own body ceiling is the gateway's result ceiling:
			// a body the gateway would refuse as a Result (ADR-0014) is not
			// worth buffering first. Same number, read from the same place
			// serve.go hands gateway.Config.MaxResultBytes.
			gwrest.WithMaxBodyBytes(cfg.Response.MaxResultBytes()),
			// The client's whole-exchange timeout is a backstop for a caller
			// without a deadline; the gateway always sets one (ADR-0025,
			// gateway.Config.CallTimeout). Equalising the two means the
			// backstop can never cut an exchange the operator's call_timeout
			// still allows, so the error an analyst sees for a slow API is
			// the gateway's deadline, not the adapter's.
			gwrest.WithHTTPClientTimeout(cfg.Response.CallTimeoutOrDefault())),
		allowCredentialedStdio: cfg.Upstreams.AllowCredentialedStdio,
	}
}

// ociLimits turns the [oci] section into the adapter's limits: a key the
// operator wrote replaces the default, a key left out keeps it.
// config.Validate has already refused a bad value with the adapter's rule
// (TestOCIConfigRuleIsTheDialRule).
func ociLimits(c config.OCI) gwoci.Limits {
	l := gwoci.DefaultLimits()
	if c.User != "" {
		l.User = c.User
	}
	if c.PidsLimit != nil {
		l.PidsLimit = *c.PidsLimit
	}
	if c.Memory != "" {
		l.Memory = c.Memory
	}
	if c.CPUs != nil {
		l.CPUs = *c.CPUs
	}
	return l
}

func (d transportDialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	switch spec.Transport {
	case string(registry.TransportStdio):
		// len(env) is the count of names the entry declared: the gateway
		// resolves every one of them before dialling, or does not dial.
		if len(env) > 0 && !d.allowCredentialedStdio {
			return nil, fmt.Errorf("gateway: upstream %q: %w", spec.Name, errCredentialedStdio)
		}
		return d.stdio.Dial(ctx, spec, env)
	case string(registry.TransportOCI):
		return d.oci.Dial(ctx, spec, env)
	case string(registry.TransportHTTP):
		// No policy here, unlike stdio: the http adapter is the one that
		// uses the credential (it injects it on each request), so handing it
		// the resolved env is the point, not the hazard. env holds exactly
		// the one secret-ref name a keyed entry declares; the adapter keeps
		// the name and drops the value (ADR-0047 §5).
		return d.resthttp.Dial(ctx, spec, env)
	default:
		return nil, fmt.Errorf("gateway: upstream %q declares transport %q, which this gateway does not serve; "+
			"registered transports are %q (a local process), %q (an ephemeral container) and %q (a REST API)",
			spec.Name, spec.Transport, registry.TransportStdio, registry.TransportOCI, registry.TransportHTTP)
	}
}

// errCredentialedStdio is the refusal of a stdio entry that declares
// credential variables while [upstreams] allow_credentialed_stdio is off
// (design/adr/0034 item 4).
//
// A stdio backend runs as the gateway's own uid, with no namespace between
// it and the files that uid reads: open() on the age key is the whole
// vault, not just the credentials this entry was given. The oci transport
// puts the same backend in its own mount namespace, under another uid,
// without the gateway's files. The refusal says both ways out, because the
// operator who meets it is holding the entry that needs one.
var errCredentialedStdio = errors.New("a stdio upstream that declares credential variables runs as the gateway's own " +
	"user, where it can read the whole vault; register it as -transport oci -image NAME@sha256:..., or, on a host " +
	"without podman or for lab mocks, set [upstreams] allow_credentialed_stdio = true (design/adr/0034)")

// credentialedStdioRefusal is the console's copy of the dial-time rule in
// transportDialer.Dial, applied where the entry is written and signed so
// that an entry the serving process would refuse forever is refused at the
// prompt. It needs the configuration, which dialTimeRefusal does not.
func credentialedStdioRefusal(entry registry.UpstreamServer, cfg *config.Config) error {
	if entry.Transport != registry.TransportStdio || len(entry.EnvVarNames) == 0 {
		return nil
	}
	if cfg != nil && cfg.Upstreams.AllowCredentialedStdio {
		return nil
	}
	return errCredentialedStdio
}

// dialTimeRefusal reports the error the adapter for entry's transport would
// return at dial time for reasons registry.Validate cannot know -- podman's
// rules about wrapper flags and variable names, the variable names neither
// process adapter will set, and for http the base URL and the operation set
// as the resthttp adapter reads them -- or nil. The console asks it at
// register and sign so that an entry the serving process would refuse
// forever is refused at the prompt instead.
//
// For http the two checks are the adapter's own functions, not a copy of
// its rules: resthttp.ValidateBaseURL is parseBase, and resthttp.Decode is
// what Dial runs on the signed Operations (ADR-0048 Decisão 6: a spec can
// carry an SSRF inside a path or a header injection inside a parameter
// name, and the place to refuse it is before it is signed). Neither does
// I/O. The coherence of AuthKind with EnvVarNames is registry.Validate's
// rule (validateHTTP) and is not repeated here.
func dialTimeRefusal(entry registry.UpstreamServer) error {
	switch entry.Transport {
	case registry.TransportStdio:
		return gwstdio.ValidateEnvVarNames(entry.EnvVarNames)
	case registry.TransportOCI:
		if err := gwoci.ValidateWrapperArgs(entry.Args); err != nil {
			return err
		}
		return gwoci.ValidateEnvVarNames(entry.EnvVarNames)
	case registry.TransportHTTP:
		if err := gwrest.ValidateBaseURL(entry.URL); err != nil {
			return err
		}
		_, err := gwrest.Decode(entry.Operations, string(entry.AuthKind), entry.AuthName)
		return err
	}
	return nil
}

// stdioNetwork is what `upstream list -json` reports for a stdio entry: the
// child is a plain process in the gateway's own network namespace.
const stdioNetwork = "host"

// entryNetwork reports the network namespace a dial of entry runs in, or
// the error the oci adapter would refuse its Args with. It is the per-entry
// egress declaration the host firewall is derived from (design/adr/0033):
// the value comes from the signed Args, through the same rule that builds
// the podman argv, so the list cannot say one network while the dial joins
// another.
func entryNetwork(entry registry.UpstreamServer) (string, error) {
	switch entry.Transport {
	case registry.TransportOCI:
		return gwoci.ResolveNetwork(entry.Args)
	case registry.TransportHTTP:
		// Deliberately "host", and said out loud rather than left to the
		// default: for http the gateway process itself is the HTTP client,
		// so the egress runs in the gateway's own network namespace, and
		// the host firewall treats it as any outbound connection of the
		// shared uid. ADR-0033's vocabulary has no word for "this host, to
		// that host:port"; giving entryNetwork one (e.g. derived from
		// entry.URL) and teaching the deployment verifier to read it is
		// Phase D (ADR-0047 §6, "Não casa com entryNetwork"), not this
		// step. The adapter's own egress guard (resthttp, ADR-0048 Decisão
		// 6) is what bounds the destination meanwhile.
		return stdioNetwork, nil
	default:
		return stdioNetwork, nil
	}
}
