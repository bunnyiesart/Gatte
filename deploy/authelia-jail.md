# A lab OIDC provider: the `authelia` jail, and the CA behind it

A second FreeBSD jail in the same `jailmachine` VM as `mcp-gateway-test`,
running Authelia as an OpenID Connect 1.0 Provider so the gateway has a real
issuer to validate tokens against instead of a hand-rolled fixture. Like
`deploy/freebsd-jail.md`, none of this is a security control and none of it
is a deployment target -- `.hardening.toml` and the ADRs in `design/` are
unaffected by any of it.

Read `deploy/freebsd-jail.md` first for `jm`, `bastille`, and the
conventions this follows.

| | |
|---|---|
| Jail | `authelia` |
| IP | `10.17.89.20` on `bastille0` |
| Release | `15.1-RELEASE` |
| Names | `id.soc.internal` (this jail), `mcp.soc.internal` (10.17.90.10) |
| Issuer | `https://id.soc.internal` |
| Audience issued | `https://mcp.soc.internal/` |
| Packages | `authelia-4.39.20_5`, `nginx-1.30.4`, `curl`, `jq` |
| CA | on the **VM host**, `/usr/local/etc/soc-ca` |

Nothing here touches `mcp-gateway-test`; `authelia-host-setup.sh` refuses to
run against that jail name outright.

## Running it

```bash
./deploy/soc-ca-bootstrap.sh      # the CA (authelia-jail.sh calls this too)
./deploy/authelia-jail.sh         # create + provision the jail
./deploy/authelia-verify.sh       # prove it works, as user 'analyst'
./deploy/authelia-verify.sh dfirlead
```

All three are idempotent and safe to re-run. Everything the VM executes
lives in `deploy/vm/` and is staged in by `scp`, for the same reason
`scripts/deploy-to-jail.sh` exists: a sequence of ad-hoc `jm ssh` commands
is not reviewable and not reproducible.

| file | runs where |
|---|---|
| `deploy/soc-ca-bootstrap.sh` | Mac -- drives the CA setup |
| `deploy/authelia-jail.sh` | Mac -- drives jail creation |
| `deploy/authelia-verify.sh` | Mac -- drives verification |
| `deploy/vm/soc-ca-install.sh` | VM host |
| `deploy/vm/soc-ca-issue.sh` | VM host, becomes `/usr/local/etc/soc-ca/issue.sh` |
| `deploy/vm/authelia-host-setup.sh` | VM host |
| `deploy/vm/authelia-provision.sh` | inside the jail |
| `deploy/vm/authelia-verify.sh` | inside the jail |
| `deploy/vm/authelia-configuration.yml` | installed as `/usr/local/etc/authelia.yml` |
| `deploy/vm/authelia-nginx.conf` | installed as `/usr/local/etc/nginx/nginx.conf` |

# The CA

## The interface other streams depend on

Fixed, on the **VM host** (not inside a jail), so a jail can be rebuilt
without taking the trust anchor with it:

```
/usr/local/etc/soc-ca/ca.crt              0644  the root certificate
/usr/local/etc/soc-ca/ca.key              0600  the root private key
/usr/local/etc/soc-ca/issue.sh NAME IP    0755  issues NAME.crt / NAME.key
```

`issue.sh` writes into that same directory and prints the two paths it
produced on stdout, last two lines, in that order:

```bash
jm ssh -- /usr/local/etc/soc-ca/issue.sh mcp.soc.internal 10.17.90.10
# /usr/local/etc/soc-ca/mcp.soc.internal.crt
# /usr/local/etc/soc-ca/mcp.soc.internal.key
```

To get the root out of the VM and into a client's trust store:

```bash
jm ssh -- cat /usr/local/etc/soc-ca/ca.crt > soc-ca.crt
```

Leaf certs carry **both** SAN forms -- `DNS:NAME` and `IP:ADDR`. This is not
decoration. Go's `crypto/tls` and `curl` both verify an IP literal against
the IP SAN and nothing else, so a DNS-only cert fails the moment anything
connects by address; the usual reaction to that is `InsecureSkipVerify` or
`--insecure`, at which point the lab has stopped testing TLS while still
appearing to.

Defaults: root RSA-4096/SHA-256, 3650 days, `pathlen:0`. Leaves RSA-2048,
825 days, `serverAuth` only. Override with `SOC_CA_DAYS`,
`SOC_CA_LEAF_DAYS`, `SOC_CA_MIN_DAYS`, `SOC_CA_CN`.

## Idempotency, and why it is not just "always regenerate"

`soc-ca-install.sh` keeps an existing root if the certificate and key still
match each other and the cert has more than a year left; it replaces it
otherwise, and says so. Re-rolling a root invalidates every certificate
issued from it and every trust store that already pinned it, which in a
multi-stream lab means breaking somebody else's work between one run and the
next.

`issue.sh` skips re-issuing when `NAME.crt` already verifies against the
current root, has exactly the requested SAN set, and is good for another 30
days. `SOC_CA_FORCE=1` overrides. Re-issuing generates a fresh key, so
anything already serving the old pair has to be restarted -- that is the
reason for the skip, not politeness.

## openssl, not easy-rsa

`easy-rsa-3.2.6` is available and would work. `openssl` won because:

  - it is in the FreeBSD base system, so the CA scripts run on the VM host
    and inside any jail with no package installed first. `easy-rsa` is a
    package, and the CA lives one layer below the thing that needs to be
    rebuildable;
  - `easy-rsa` maintains a PKI state directory -- `index.txt`, `serial`, a
    `vars` file, a `pki/` tree. That state is the main value it adds
    (revocation, CRLs, renewal tracking) and this lab uses none of it. It
    would be state to keep idempotent for no return;
  - the whole issuance path is eleven lines of `openssl req` and
    `openssl x509 -req` with an extension file, which is auditable in one
    screen. Reviewing `issue.sh` requires no knowledge of `easy-rsa`'s
    variable precedence.

The cost is real and worth naming: **there is no revocation.** No CRL, no
OCSP, no `index.txt`. A leaf key that leaks stays valid until it expires or
the root is replaced. `easy-rsa` would have given that for free.

## What the CA is not

**This is not a public PKI.** Concretely:

  - the root key sits unencrypted on the same host as the leaf keys it
    signs, readable by root, with no HSM, no offline root, no intermediate.
    `pathlen:0` is the only structural limit;
  - no revocation, as above;
  - no name constraints. This root will happily sign a certificate for any
    name at all, including one that is not yours. Anything that trusts this
    root trusts a certificate for `login.microsoftonline.com` signed by it
    just as much. **Do not add `ca.crt` to a system-wide or browser trust
    store.** Point individual clients at it -- `curl --cacert`, Go's
    `RootCAs`, nginx's `ssl_trusted_certificate` -- and nowhere else;
  - no audit trail of what was issued beyond the files in the directory;
  - it exists only inside one developer's QEMU VM under `~/.jailmachine/`.

It is good for exactly one thing: making TLS in this lab real enough that
verification is on, so a code path that would fail against a real issuer
fails here too.

# The Authelia jail

## Shape

nginx terminates TLS on `0.0.0.0:443` with the CA-issued cert for
`id.soc.internal` and proxies to Authelia on `127.0.0.1:9091`. Authelia
never listens off-loopback, so there is no cleartext OIDC endpoint even
inside the jail.

The proxy is not decoration either: **Authelia derives the issuer and every
endpoint URL in the discovery document from the incoming request's host and
forwarded scheme.** `proxy_set_header Host $host` plus
`X-Forwarded-Proto https` is what makes `iss` come out as
`https://id.soc.internal`. Reach the jail by IP instead and discovery
advertises `https://10.17.89.20` and the tokens say so too -- which the
gateway, pinned to one issuer string, will reject. Consumers need the
hosts entry, not just the route.

There is no DNS in this lab. `authelia-host-setup.sh` writes
`id.soc.internal` and `mcp.soc.internal` into the VM host's `/etc/hosts` and
the `authelia` jail's. It deliberately does **not** write into
`mcp-gateway-test` -- that jail belongs to another stream. Whoever owns it
adds:

```
10.17.89.20	id.soc.internal
```

No `bastille rdr` is configured. The provider is reachable from the VM and
from jails on `bastille0`, and not from the Mac.

## The OIDC client

Registered as `mcp-gateway` in
`identity_providers.oidc.clients`. The gateway is an OAuth 2.0 **Resource
Server** -- it validates bearer tokens and never obtains one -- so the only
things about this registration that matter to it are what ends up inside the
token. The `redirect_uris` entry exists because Authelia requires one for
the authorization code grant, not because the gateway will ever be
redirected to.

Three settings carry the whole thing:

**`access_token_signed_response_alg: 'RS256'`.** This was the warned-about
trap and it is real. Authelia's default is `'none'`, and `'none'` means an
**opaque** access token -- a random string with no structure, verifiable
only by calling the introspection endpoint. A gateway that verifies
signatures against the JWKS gets nothing to verify. Setting an algorithm is
what makes the access token an RFC 9068 JWT (`typ: at+jwt`). Verified: the
issued token has three segments, `alg: RS256`, `kid: main`, and its
signature checks out against the published JWKS key.

**`claims_policies`.** Authelia does **not** put `groups` in an access token
by default. The default JWT access token carries the registered claims --
`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`, `scp` -- and
says nothing about group membership, even when the `groups` scope was
granted. Requesting the scope is not enough. A named claims policy attached
to the client with `access_token: ['groups', ...]` is what puts the claim
in. Without it, a gateway that maps groups to roles would authenticate every
user and authorise none of them, and the failure would look like a broken
role mapping rather than a missing claim.

**`audience` plus the RFC 8707 `resource` parameter.** The client is allowed
to request `https://mcp.soc.internal/`, and the claims policy sets
`access_token_audience_mode: 'specification'`, meaning `aud` contains the
granted resource indicators and *not* the client id.

That last one has a sharp edge worth knowing before you debug it at
midnight. **The audience is not automatic.** Measured, on this jail:

| authorization + token request | resulting `aud` |
|---|---|
| with `resource=https://mcp.soc.internal/` | `["https://mcp.soc.internal/"]` |
| without `resource` | `[]` (empty) |

An empty audience is the correct, fail-closed outcome -- the gateway rejects
it -- but a client that forgets `resource` gets a perfectly well-formed,
correctly signed JWT that is simply not for the gateway. `deploy/vm/authelia-verify.sh`
passes `resource` on both the authorization request and the token exchange.

Also set: `consent_mode: 'implicit'`, so the verification script can complete
the authorization code flow without driving a browser. That is a lab
decision. It is not defensible for a client a human is meant to consent to,
and it is the single setting here most likely to be copied somewhere it does
not belong.

## Test users

Two, in the file backend, argon2id hashes, both created by the provisioning
script:

| username | groups | email |
|---|---|---|
| `analyst` | `soc-analysts` | `analyst@soc.internal` |
| `dfirlead` | `dfir-leads`, `soc-analysts` | `dfirlead@soc.internal` |

`dfirlead` is in two groups on purpose: a single-group user cannot
distinguish "the gateway read the groups claim" from "the gateway assigned
the only role it knows".

## Secrets

**Nothing secret is in this repository, and nothing generated in the jail is
copied back to the Mac.** Everything is generated on first provisioning run,
inside the jail, into `/usr/local/etc/authelia/secrets/` (mode 0700, files
0600):

| file | what | how it is made |
|---|---|---|
| `session.secret` | session cookie signing | `openssl rand -hex 32` |
| `storage.encryption.key` | SQLite field encryption | `openssl rand -hex 32` |
| `identity_validation.jwt.secret` | password-reset JWTs | `openssl rand -hex 32` |
| `oidc.hmac.secret` | OAuth2 token HMAC | `openssl rand -hex 32` |
| `oidc.jwks.main.pem` | the RS256 issuer signing key | `openssl genpkey -algorithm RSA` 4096, PKCS#8 |
| `oidc.client.mcp-gateway.plain` | client secret, cleartext | `openssl rand -hex 32` |
| `oidc.client.mcp-gateway.digest` | the same, hashed | `authelia crypto hash generate pbkdf2 --variant sha512` |
| `user.<name>.plain` | test user password | `openssl rand -hex 16` |
| `user.<name>.argon2` | the same, hashed | `authelia crypto hash generate argon2` |

`authelia.yml` contains no secret values at all. It pulls each one at load
time with Authelia's `secret` template function, which works because the
packaged `rc.d` script already starts the daemon with
`--config.experimental.filters template`. Drop that flag and the daemon
reads the template actions as literal text and fails validation loudly,
which is the right failure.

Two of those files hold cleartext on purpose -- the client secret and the
user passwords -- because `authelia-verify.sh` has to present them the way a
real client would. They never leave the jail. If you want to look at one:

```bash
jm ssh -- bastille cmd authelia cat /usr/local/etc/authelia/secrets/user.analyst.plain
```

The provisioning script **never regenerates a secret that already exists.**
Rotating the JWKS key invalidates every token in flight and every cached
JWKS; rotating the storage encryption key makes the existing database
unreadable. To rotate deliberately: delete the specific file and re-run
`./deploy/authelia-jail.sh`.

The repo's DLP pre-commit hook is why the generated `users_database.yml` and
every `secrets/` file exist only in the jail. Nothing in `deploy/` should
ever need `--no-verify`; if it does, the file is wrong, not the hook.

# What is proven and what is assumed

`./deploy/authelia-verify.sh` runs inside the jail, over TLS, verifying
against `ca.crt`. **There is no `--insecure` anywhere in it**, deliberately:
a lab that skips certificate verification is not exercising the path it was
built to exercise. It exits non-zero on the first failed assertion.

## Proven, by that script, on 09 Sep 2026

1. `https://id.soc.internal/.well-known/openid-configuration` returns HTTP
   200 over TLS that verifies against the SOC CA root, parses as JSON,
   reports `issuer: https://id.soc.internal`, and advertises
   `jwks_uri: https://id.soc.internal/jwks.json`.
2. That JWKS serves one key: `kid=main kty=RSA alg=RS256 use=sig`.
3. A full authorization code flow (`POST /api/firstfactor` ->
   `GET /api/oidc/authorization` -> `POST /api/oidc/token`) returns
   `token_type: bearer`, `expires_in: 3599`.
4. The access token has three segments -- a JWT, not an opaque string --
   with header `{"alg":"RS256","kid":"main","typ":"at+jwt"}`.
5. Its `kid` resolves in the published JWKS, and its **RS256 signature
   verifies** against the RSA public key reconstructed from that JWKS
   entry. This is the check the gateway performs, done for real, not
   inferred from the header.
6. `aud` contains exactly `https://mcp.soc.internal/`.
7. `iss` is `https://id.soc.internal`.
8. `groups` is present and non-empty, and differs correctly per user.

Decoded access token claims, user `analyst`:

```json
{
  "aud": [ "https://mcp.soc.internal/" ],
  "client_id": "mcp-gateway",
  "email": "analyst@soc.internal",
  "exp": 1788944566,
  "groups": [ "soc-analysts" ],
  "iat": 1788940966,
  "iss": "https://id.soc.internal",
  "jti": "e2843d37-34d3-4972-9f13-f602ffc65538",
  "nbf": 1788940966,
  "preferred_username": "analyst",
  "scp": [ "openid", "profile", "email", "groups" ],
  "sub": "bb7502ab-cad7-45d0-8f0c-d8a5becfe4a4"
}
```

User `dfirlead`, same flow:

```json
{
  "aud": [ "https://mcp.soc.internal/" ],
  "client_id": "mcp-gateway",
  "email": "dfirlead@soc.internal",
  "exp": 1788944521,
  "groups": [ "dfir-leads", "soc-analysts" ],
  "iat": 1788940921,
  "iss": "https://id.soc.internal",
  "jti": "4dbcc453-a1bf-4ce7-9201-4d48f3c9717b",
  "nbf": 1788940921,
  "preferred_username": "dfirlead",
  "scp": [ "openid", "profile", "email", "groups" ],
  "sub": "d5832122-2c13-4db7-85e7-a31b714bc66d"
}
```

The client secret and the users' passwords are `<redacted>` here and were
never printed by the script.

## Assumed, not proven

  - ~~**That `mcp-gateway` accepts these tokens.**~~ **Settled, 09 Sep
    2026: it does.** A token from this flow gets HTTP 200 and a real tool
    list out of the running gateway, and `groups` maps to the right role --
    `analyst` sees 6 tools, `dfirlead` 8. See `deploy/gateway-serve.md`.
    Nothing in *this* jail changed to make that work.
  - ~~**That `mcp-gateway-test` can reach the provider.**~~ **Settled, 09
    Sep 2026: it does.** The gateway completes OIDC discovery against
    `https://id.soc.internal` at every start. One trap that cost an hour and
    is not this jail's fault: Go's `crypto/x509` does not read
    `/usr/local/etc/ssl/certs/`, where the gateway jail keeps `soc-ca.crt`,
    so discovery failed with "certificate signed by unknown authority" while
    `curl --cacert` on the same URL returned 200. Fixed with `SSL_CERT_FILE`
    on that process only -- **not** by putting this unconstrained root into
    a system trust store, which the section above forbids for good reason.
  - **The `bastille create` branch of `authelia-host-setup.sh`.** The jail
    was created by hand before the script existed, so every run so far has
    taken the "already exists" path. The create branch is two lines copied
    from `deploy/freebsd-jail.md` and is untested as written. A
    destroy-and-rebuild would settle it.
  - **Refresh tokens.** `offline_access` is in the client's allowed scopes
    and `refresh_token` in its grant types, but the verification flow does
    not request or exercise either.
  - **Any 2FA path.** TOTP and WebAuthn are disabled outright.

## Known broken / deliberately wrong

**The VM clock is roughly ten and a half hours behind real time.** Measured
09 Sep 2026: the Mac read `18:42Z`, the VM read `08:01Z`. This is the QEMU
guest drifting with no NTP.

Two consequences. First, Authelia's startup NTP check fails fatally and the
daemon exits before it ever listens, so `ntp.disable_startup_check: true` is
set in the config. That disables the *check*, not the dependency. Second,
and worse: `iat`, `nbf` and `exp` are all stamped from the VM's clock, so a
token minted here is a ten-hour-old token to any verifier with a correct
clock, and one minted after a VM suspend may be `nbf`-in-the-future. As long
as the issuer and the gateway are both inside this VM they agree with each
other and nothing breaks. The moment a verifier outside the VM is
introduced, **check the clock before debugging the token.**

Fixing it means setting the VM's clock, which affects the other stream's
jail as well, so it has been left alone rather than changed underneath
somebody.

Other deliberate deviations, none of which should be copied anywhere real:

  - `regulation.max_retries: 0` -- no brute-force lockout, because the
    verification script logs the same user in on every run and a lockout
    makes a working provider look broken.
  - `access_control.default_policy: 'one_factor'` with no rules. Authelia
    warns about this on every start; the warning is correct and ignored,
    because what is under test is the group claim, not the strength of the
    authentication behind it.
  - `consent_mode: 'implicit'` on the client, as above.
  - `log.level: 'debug'`, because the first thing anyone does when a token
    comes out wrong is read the log.
  - No SMTP. `notifier.filesystem` writes to
    `/var/log/authelia/notification.txt`; password reset is disabled anyway.

## Troubleshooting

```bash
jm ssh -- bastille cmd authelia service authelia status
jm ssh -- bastille cmd authelia tail -50 /var/log/authelia/authelia.log
jm ssh -- bastille cmd authelia tail -50 /var/log/nginx/error.log
jm ssh -- bastille cmd authelia authelia validate-config \
    --config /usr/local/etc/authelia.yml --config.experimental.filters template
```

The daemon's own stdout, including the fatal startup errors that never reach
the application log, goes to `/var/log/authelia.log` (note: not the one
under `/var/log/authelia/`) because the packaged `rc.d` script runs it under
`daemon -o`. That is where an unparseable config or a failed startup check
shows up.

## Tearing down

```bash
jm ssh -- bastille stop authelia
jm ssh -- bastille destroy authelia     # jail, secrets and all
```

The CA survives that -- it is on the VM host, not in the jail. To remove it
too, and break anything that pinned it:

```bash
jm ssh -- rm -rf /usr/local/etc/soc-ca
```
