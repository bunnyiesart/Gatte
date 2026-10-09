// Package resthttp is the http adapter for [gateway.Dialer]: it turns a
// registered REST API into MCP tools, one tool per operation of the frozen,
// signed operation set the registry stores for the entry
// (design/adr/0047-upstreams-rest-e-mcp-gerado-de-openapi.md §2, §3;
// design/adr/0048-rest-de-openapi-classe-de-seguranca-e-guarda-de-egresso.md).
//
// It is a sibling of internal/gateway/stdio and internal/gateway/oci, and
// like them it depends only on the ports -- gateway.* and vault.Provider --
// never on a concrete store or vault (design/adr/0001 Compliance,
// internal/fitness). Unlike them it holds no live connection: an upstream
// handed out by this package is stateless (ADR-0047 §2), and its health is
// a fixed "up" (ADR-0048 Decisão 9).
//
// Three rules govern everything in this package.
//
//  1. The operation set is third-party text at every edge (ADR-0048
//     Decisão 6, Consequências). It is generated from an OpenAPI document the
//     operator pointed at, and a spec can carry an SSRF inside a path
//     ("//evil.tld", "../", a scheme), a header injection inside a parameter
//     name ("Host", "Transfer-Encoding", a CRLF), or a parameter that
//     shadows the slot the credential is injected into. operation.go
//     therefore validates fail-closed: a set that does not pass is not
//     served, and the same validation is exported so the operator console
//     refuses it at register/sign time, before it is ever signed.
//
//  2. The credential value is never held -- by this package's fields or by
//     what they reach. The adapter keeps the secret's NAME (the single
//     secret-ref of the entry) and re-resolves it through vault.Provider on
//     every call (ADR-0047 §5, the "third place that touches plaintext");
//     the transport keeps no idle connection, because an idle connection's
//     write buffer is the last request line with the value in it; every
//     error out of the HTTP client is redacted before it is returned
//     (ADR-0048 Decisão 7), because with AuthKind=query the live value is
//     in the URL that *url.Error prints; and the response envelope is
//     masked with the value the call injected before it is returned, so a
//     rotation between this resolve and the gateway's scrubResult cannot
//     leave an echo of the old value in clear (ADR-0047 §5, dated note).
//
//  3. The security class is derived from the method, in one place
//     ([ClassOf]), and travels OUTSIDE the quarantine fingerprint in
//     gateway.ToolDef.SecurityClass (ADR-0048 Decisão 5). It is not a
//     separate field of the operation: the method is signed, so the class
//     is covered by the digest without a second field that could disagree
//     with it.
//
// # Where things are, as of 07 out 2026
//
// operation.go is the operation model: the type, the fail-closed
// decode/validate of registry.UpstreamServer.Operations, the canonical
// encode the OpenAPI ingestion (ADR-0047 §3, step 4 of ADR-0048's order)
// uses to produce those bytes, and the method→class rule.
//
// openapi.go is the OpenAPI ingestion (ADR-0047 §3, ADR-0048 step 4):
// Ingest reads a 3.0.x/3.1.x document (JSON or YAML, our own minimal
// fail-closed parser, no OpenAPI library) and produces the frozen set
// through this package's own Validate/Encode/Decode, so the register
// writes exactly what the dialer will accept. Its file comment lists the
// decisions it takes where the ADRs left room.
//
// resthttp.go is the Dialer and the stateless upstream: Dial validates the
// signed base URL and the operation set and builds one host-pinned
// http.Client per entry (no I/O); CallTool places the arguments by prefix,
// re-resolves the secret, injects it where the descriptor says, and
// serialises status, headers and body as one canonical text block
// (envelope); scrubCallError is the Decisão 7 redaction.
//
// egress.go is the egress guard (Decisão 6): refuseAddr is the IP policy,
// applied to every resolved address in dialPinned and again in
// net.Dialer.Control; the host pin is base.checkRedirect in resthttp.go.
//
// Health is a fixed "up" (Decisão 9): nothing here produces
// gateway.ErrUpstreamGone, and an argument the operation cannot carry is a
// Result{IsError} naming the fault, not an error the gateway would report
// as the backend's (Decisão 9, dated note). Decisão 8's safe-only interim
// was not built, because the class seam it was waiting for landed before
// this adapter did.
package resthttp
