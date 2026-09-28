package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/bunnyiesart/Gatte/internal/config"
	"github.com/bunnyiesart/Gatte/internal/gateway"
	gwoci "github.com/bunnyiesart/Gatte/internal/gateway/oci"
	gwstdio "github.com/bunnyiesart/Gatte/internal/gateway/stdio"
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// transportDialer routes each registry entry to the adapter for its
// transport: a local process (stdio) or an ephemeral, digest-pinned
// container (oci). The oci adapter wraps the stdio one -- the container is a
// stdio child that is `podman run --rm -i` -- so the protocol handling, the
// built-not-inherited child environment, and dead-upstream detection are
// the same code for both (ported from the internal line, 28 Sep 2026).
type transportDialer struct {
	stdio gateway.Dialer
	oci   gateway.Dialer
	// allowCredentialedStdio is [upstreams] allow_credentialed_stdio. See
	// credentialedStdioRefusal.
	allowCredentialedStdio bool
}

var _ gateway.Dialer = transportDialer{}

func newTransportDialer(cfg *config.Config) transportDialer {
	spawn := gwstdio.New(gwstdio.WithClientInfo("mcp-gateway", buildVersion))
	return transportDialer{
		stdio: spawn,
		oci: gwoci.New(spawn,
			gwoci.WithCleanupEnv(gwstdio.DefaultInheritedEnv()...),
			gwoci.WithLimits(ociLimits(cfg.OCI))),
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
	default:
		return nil, fmt.Errorf("gateway: upstream %q declares transport %q, which this gateway does not serve; "+
			"registered transports are %q (a local process) and %q (an ephemeral container)",
			spec.Name, spec.Transport, registry.TransportStdio, registry.TransportOCI)
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
// rules about wrapper flags and variable names, and the variable names
// neither adapter will set -- or nil. The console asks it at register and
// sign so that an entry the serving process would refuse forever is
// refused at the prompt instead.
func dialTimeRefusal(entry registry.UpstreamServer) error {
	switch entry.Transport {
	case registry.TransportStdio:
		return gwstdio.ValidateEnvVarNames(entry.EnvVarNames)
	case registry.TransportOCI:
		if err := gwoci.ValidateWrapperArgs(entry.Args); err != nil {
			return err
		}
		return gwoci.ValidateEnvVarNames(entry.EnvVarNames)
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
	if entry.Transport != registry.TransportOCI {
		return stdioNetwork, nil
	}
	return gwoci.ResolveNetwork(entry.Args)
}
