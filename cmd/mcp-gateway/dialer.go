package main

import (
	"context"
	"fmt"

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
}

var _ gateway.Dialer = transportDialer{}

func newTransportDialer() transportDialer {
	spawn := gwstdio.New(gwstdio.WithClientInfo("mcp-gateway", buildVersion))
	return transportDialer{
		stdio: spawn,
		oci:   gwoci.New(spawn, gwoci.WithCleanupEnv(gwstdio.DefaultInheritedEnv()...)),
	}
}

func (d transportDialer) Dial(ctx context.Context, spec gateway.UpstreamSpec, env map[string]string) (gateway.Upstream, error) {
	switch spec.Transport {
	case string(registry.TransportStdio):
		return d.stdio.Dial(ctx, spec, env)
	case string(registry.TransportOCI):
		return d.oci.Dial(ctx, spec, env)
	default:
		return nil, fmt.Errorf("gateway: upstream %q declares transport %q, which this gateway does not serve; "+
			"registered transports are %q (a local process) and %q (an ephemeral container)",
			spec.Name, spec.Transport, registry.TransportStdio, registry.TransportOCI)
	}
}

// dialTimeRefusal reports the error the adapter for entry's transport would
// return at dial time for reasons registry.Validate cannot know -- podman's
// rules about wrapper flags and variable names -- or nil. The console asks
// it at register and sign so that an entry the serving process would refuse
// forever is refused at the prompt instead.
func dialTimeRefusal(entry registry.UpstreamServer) error {
	if entry.Transport != registry.TransportOCI {
		return nil
	}
	if err := gwoci.ValidateWrapperArgs(entry.Args); err != nil {
		return err
	}
	return gwoci.ValidateEnvVarNames(entry.EnvVarNames)
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
