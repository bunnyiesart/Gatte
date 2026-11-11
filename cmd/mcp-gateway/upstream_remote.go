// Operator Console -- the remote half of "upstream register": a native MCP
// server reached by URL (design/adr/0058).

package main

import (
	"github.com/bunnyiesart/Gatte/internal/registry"
)

// remoteFlags applies the remote-only flags to entry, or returns the usage
// error for a flag that does not apply. -auth-kind "none" and an absent
// -auth-kind both mean keyless; an absent -remote-kind is streamable, the
// one client transport this build dials (ADR-0058 §3).
func remoteFlags(entry *registry.UpstreamServer, openapi, authKind, authName, remoteKind string) string {
	if entry.Transport != registry.TransportRemote {
		if remoteKind != "" {
			return "-remote-kind applies to -transport remote only."
		}
		return ""
	}
	if openapi != "" {
		return "-openapi applies to -transport http only; a remote entry is a native MCP server that announces its own tools."
	}
	if authKind != "none" {
		entry.AuthKind = registry.AuthKind(authKind)
	}
	entry.AuthName = authName
	entry.RemoteKind = registry.RemoteKind(remoteKind)
	if remoteKind == "" {
		entry.RemoteKind = registry.RemoteStreamable
	}
	return ""
}

// opRemoteAuthLine renders where a remote entry sends its credential.
func opRemoteAuthLine(s registry.UpstreamServer) string {
	switch s.AuthKind {
	case registry.AuthNone:
		return "none (keyless)"
	case registry.AuthBearer:
		return "bearer (Authorization: Bearer <secret>), the gateway's own token"
	case registry.AuthHeader:
		return "header " + s.AuthName + ": <secret>, the gateway's own token"
	}
	return string(s.AuthKind) + " " + s.AuthName
}
