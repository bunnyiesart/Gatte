# Your first gateway, in the lab

This tutorial is for someone new to Gatte. On one machine, as yourself, you
build Gatte, put one of the lab's mock backends behind it, approve its tools
and make a first authenticated call, then read that call in the audit
trail. It takes about half an hour. Nothing in it touches a real backend, a
real identity provider or a real credential.

It was run end to end on macOS; the same commands work on Linux.

## What you need

- A checkout of this repository, and a shell in its top directory.
- Go, the version in `go.mod`, and `make`.
- `sops` and `age` (with `age-keygen`) on your `PATH`. `make devtools`
  installs them, with the project's lint tools, into
  `$(go env GOPATH)/bin`; if you use that, add the directory to `PATH`.
- `openssl`, `python3` and `curl`.
- The loopback ports `8080` (the gateway) and `9400` (the stand-in
  identity provider) free. If one is taken, use another and change it in
  every step below.

Run every step in the same shell. If you open a new one, set `LAB`, `CFG`
and `PATH` again as in steps 2 and 6.

## 1. Build Gatte and the mock backends

```sh
make build lab-build
```

`make build` writes `bin/mcp-gateway`. `make lab-build` writes four mock MCP
servers into `bin/lab/` (`casemgmt`, `logsearch`, `docsearch`,
`threatintel`), the fake REST API `restmock` (not used in this tutorial;
`lab/README.md`, "The REST probe") and the `probe`. Each mock answers with synthetic data and
has a `<name>_credcheck` tool that says whether it received the credential
it expected, without ever returning the credential itself
([`lab/README.md`](../../lab/README.md)).

## 2. Make a lab directory

```sh
export PATH="$PWD/bin:$PATH"
mkdir -p ~/gatte-lab
cp bin/lab/casemgmt ~/gatte-lab/
cd ~/gatte-lab
LAB=$PWD
```

Everything the gateway needs goes into `$LAB`: keys, the vault, the
configuration and the database. Deleting the directory undoes the tutorial.

## 3. Start a stand-in identity provider

Gatte accepts a call only with a token from the OIDC issuer in its
configuration, and reads that issuer's discovery document when it starts.
The lab has no identity provider, so you make a stand-in: an RSA key, the
two documents Gatte reads, and a static web server for them on loopback.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out idp.key
mkdir -p idp/.well-known
cat > idp/.well-known/openid-configuration <<'EOF'
{"issuer": "http://127.0.0.1:9400",
 "jwks_uri": "http://127.0.0.1:9400/jwks.json",
 "authorization_endpoint": "http://127.0.0.1:9400/authorize",
 "token_endpoint": "http://127.0.0.1:9400/token",
 "response_types_supported": ["code"],
 "subject_types_supported": ["public"],
 "id_token_signing_alg_values_supported": ["RS256"]}
EOF
N=$(openssl rsa -in idp.key -noout -modulus | cut -d= -f2)
python3 - "$N" > idp/jwks.json <<'EOF'
import base64, json, sys
n = base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).rstrip(b"=").decode()
print(json.dumps({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "lab", "n": n, "e": "AQAB"}]}))
EOF
python3 -m http.server 9400 --bind 127.0.0.1 --directory idp > idp.log 2>&1 &
curl -s http://127.0.0.1:9400/.well-known/openid-configuration
```

The last command prints the discovery document back.

This stand-in has no login page: whoever holds `idp.key` can make any
token. That is what lets you make one in step 11, and it is why the
stand-in never leaves a lab. A real deployment points `[oidc]` at the
team's identity provider instead.

## 4. Make the signing key

Gatte serves a backend only if its registry entry carries a signature from
a key the configuration trusts.

```sh
mcp-gateway sign -generate-key -out "$LAB/signing.key" | tee keygen.txt
KEY=$(sed -n 's/^ *"\([A-Za-z0-9+/=]*\)",.*/\1/p' keygen.txt)
echo "$KEY"
```

The command prints the two lines the configuration needs; `KEY` holds the
public half, which step 6 puts in `trusted_keys`.

## 5. Make the vault

The mock `casemgmt` checks that `MOCK_SECRET` arrives and equals
`MOCK_EXPECT`. Both go into the vault, with a random value you never see:

```sh
age-keygen -o age.key
R=$(age-keygen -y age.key)
umask 077
V=$(openssl rand -hex 16)
printf '{"MOCK_SECRET": "%s", "MOCK_EXPECT": "%s"}\n' "$V" "$V" > secrets.json
sops --encrypt --age "$R" --input-type json --output-type json secrets.json > secrets.enc.json
rm secrets.json
unset V
```

`secrets.enc.json` is the only place the value exists now. Everything else
refers to it by name.

## 6. Write the configuration

```sh
CFG=$LAB/config.toml
cat > "$CFG" <<EOF
listen   = "127.0.0.1:8080"
database = "$LAB/gatte.db"

[oidc]
issuer   = "http://127.0.0.1:9400"
audience = "http://127.0.0.1:8080/mcp"

[vault]
secrets_file = "$LAB/secrets.enc.json"
age_key_file = "$LAB/age.key"

[signer]
key_file     = "$LAB/signing.key"
trusted_keys = ["$KEY"]

[quarantine]
refresh_interval = "30s"

# The mock is a local process that receives credentials; see step 8.
[upstreams]
allow_credentialed_stdio = true

[[role]]
name  = "lab-analyst"
tools = ["casemgmt.list_cases", "casemgmt.casemgmt_credcheck"]

[group_to_role]
"lab-analysts" = "lab-analyst"
EOF
```

What each part does:

- `listen` is loopback, as always: Gatte refuses any other address. The
  issuer and the audience may be `http` only because they are loopback.
- `[[role]]` grants two of the mock's tools to the role `lab-analyst`, and
  `[group_to_role]` gives that role to anyone whose token carries the group
  `lab-analysts`. The mock has a third tool, `get_case`, which no role
  grants.
- `refresh_interval = "30s"` makes the gateway notice changes quickly in the
  lab. The default is `5m`.

## 7. Check the host

```sh
mcp-gateway check -config "$CFG"
```

In the lab this ends with `2 failed, 1 warning`, and that is expected:

- `FAIL configuration file` and `FAIL signing key`: you own both, and so
  does the account that runs the gateway, which is also you. On a real host
  both belong to root, so that the account the gateway runs as cannot
  change its own policy or sign its own backends.
- `WARN vault file`: the same, for `secrets.enc.json`.

Every other line should be `PASS` or `SKIP`. Each FAIL and WARN line carries
the command that fixes it on a real host.

## 8. Register the mock and sign it

```sh
mcp-gateway upstream register -config "$CFG" -name casemgmt -transport stdio \
  -command "$LAB/casemgmt" -env MOCK_SECRET -env MOCK_EXPECT
mcp-gateway sign -config "$CFG" casemgmt
mcp-gateway upstream list -config "$CFG"
```

`register` says the entry is `NOT SIGNED`; `sign` signs it; `upstream list`
then shows `yes` in `SIGNED`.

`-env` takes names only; the values come from the vault when the gateway
starts the process. A `stdio` backend runs as the gateway's own user and
could read the whole vault, which is why step 6 had to opt in with
`allow_credentialed_stdio`. On a host with podman, a real backend is a
container instead ([Add a backend](../how-to/add-a-backend.md)).

## 9. Start the gateway

```sh
mcp-gateway serve -config "$CFG" > serve.log 2>&1 &
sleep 3
cat serve.log
```

Read the log. The lines that matter:

- `new tool observed; it is pending and not served until an operator
  approves it`, once for each of the mock's three tools.
- `mcp-gateway: serving` with `upstreams_connected=1`, `tools_discovered=3`
  and `tools_servable=0`.
- `no discovered tool is approved in Tool Quarantine, so every analyst will
  see an empty tool list`.

Every tool starts in quarantine. Nobody can call anything yet.

## 10. Review and approve the tools

```sh
mcp-gateway tool review -config "$CFG" -server casemgmt
```

This prints each of the three definitions in full: name, description, input
and output schema. Read them. At the end it says who can call each tool
once approved, and prints the set's manifest:

```text
Approving this set makes each tool callable by:

  casemgmt_credcheck       lab-analyst
  get_case                 (no role -- servable, callable by nobody)
  list_cases               lab-analyst

manifest  sha256:f657021cf1f877462aca4f2581b4a0e3b46980ab58e54c8ad2d58079d33375b7
```

Your manifest is the one on your screen. Approve exactly that set:

```sh
mcp-gateway tool approve -config "$CFG" -server casemgmt -manifest MANIFEST
```

Replace `MANIFEST` with the value on your `manifest` line. The command
prints the set again, then `Approved 3 tools of casemgmt`. If any tool of
`casemgmt` had changed since you ran `tool review`, it would approve
nothing.

The last line of the output says `No configured role covers get_case`.
Approving is not granting: `get_case` is now servable, and still nobody's,
because no role names it.

```sh
mcp-gateway tool list -config "$CFG"
```

All three tools now show `approved` and `USABLE` `yes`.

## 11. Make the first call

Make a token for an analyst in the group `lab-analysts`, valid for ten
minutes, signed by the stand-in identity provider:

```sh
cat > mint-token.sh <<'EOF'
#!/bin/sh
# mint-token.sh SUBJECT GROUP: a 10-minute token from the stand-in identity provider.
set -eu
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
now=$(date +%s)
h=$(printf '{"alg":"RS256","typ":"JWT","kid":"lab"}' | b64url)
p=$(printf '{"iss":"http://127.0.0.1:9400","aud":"http://127.0.0.1:8080/mcp","sub":"%s","name":"Lab analyst","groups":["%s"],"iat":%d,"exp":%d}' \
  "$1" "$2" "$now" $((now + 600)) | b64url)
s=$(printf '%s.%s' "$h" "$p" | openssl dgst -sha256 -sign idp.key | b64url)
printf '%s.%s.%s\n' "$h" "$p" "$s"
EOF
TOKEN=$(sh mint-token.sh analyst-1 lab-analysts)
```

The endpoint is MCP's streamable HTTP transport: one `POST` per JSON-RPC
message, with the answer on a `data:` line. A small helper:

```sh
mcp() {
  curl -s http://127.0.0.1:8080/mcp -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -H 'MCP-Protocol-Version: 2025-06-18' -d "$1" | sed -n 's/^data: //p'
}
```

List the tools this analyst can see:

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' |
  python3 -c 'import json, sys; print([t["name"] for t in json.load(sys.stdin)["result"]["tools"]])'
```

```text
['casemgmt.casemgmt_credcheck', 'casemgmt.list_cases', 'gatte.status']
```

The two granted tools, named `backend.tool`, and Gatte's own
`gatte.status`. `get_case` is not there: approved, but not granted.

Call a tool, then ask the mock whether its credential arrived:

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"casemgmt.list_cases","arguments":{}}}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"casemgmt.casemgmt_credcheck","arguments":{}}}'
```

The first answer carries two synthetic cases. The second ends with
`"received_expected_secret":true` and a short fingerprint: the mock received
the value from the vault, and neither your shell nor the answer ever held
it.

Now try what is not allowed:

```sh
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"casemgmt.get_case","arguments":{"case_id":"57769"}}}'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":5,"method":"tools/list"}'
```

The ungranted tool answers `unknown tool "casemgmt.get_case"`, exactly as a
tool that does not exist would. The request without a token gets `401`.

## 12. Read the audit trail

```sh
mcp-gateway audit -config "$CFG"
mcp-gateway audit -config "$CFG" -verify
```

Newest first, you find: the unauthenticated request (`(authentication)`,
`denied`), the refused `casemgmt.get_case` (`denied`, `not visible to
caller`), your two calls (`allowed`, by `analyst-1`), your approvals as
`(tool approve)` rows and one `(tool approve set)` row, attributed to
`(operator:YOU)`, the three `tool first seen` rows and the
`(backend health)` row the gateway wrote, and the `(boot)` row that opens
every start. `-verify` checks the hash chain and prints its head.

## 13. Stop the lab

```sh
kill %2 %1          # serve, then the stand-in identity provider
```

If your shell does not number them `%1` and `%2`, run `jobs` and kill both
by their numbers. To start again from nothing, delete `~/gatte-lab`.

## What you did

You ran the whole path a call takes through Gatte: a signed backend, a
vault that injects its credential, a quarantine that served nothing until
you approved exactly what you had read, a role that decided who sees which
tool, a token checked against an issuer, and a trail of all of it.

In the lab you did everything as one user. On a real host the work is
split: operator commands run as the service account (`sudo -u mcpgw`),
`sign` and `check` run as root, and the identity provider is the team's.
From here:

- the README's [Quick start](../../README.md#quick-start) sets up a real
  host;
- [Add a backend](../how-to/add-a-backend.md) and
  [Review and approve tools](../how-to/review-and-approve-tools.md) are the
  two tasks you just did, for production;
- [How a call is handled](../explanation/how-a-call-is-handled.md) explains
  each check the call went through.
