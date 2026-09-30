# Update a backend's container image

This guide is for an operator moving a container backend (`-transport oci`)
to a new image digest while keeping the approvals of the tools that did not
change. The decision record is `design/adr/0043`.

You need:

- a backend registered with `-transport oci` and signed
  ([Add a backend](add-a-backend.md)), and `serve` running;
- root on the host, and the service account `mcpgw`;
- the new image, of the same backend.

```sh
CFG=/usr/local/etc/mcp-gateway/config.toml
```

## Update or deregister?

`upstream update -image` keeps the backend's quarantine: each approval holds
while the new image advertises the byte-identical definition. That is right
only when the new image is the same backend at a new version.

Deregister it and register it again instead when it is not the same
backend: another project, another vendor, or a tool set you want reviewed
from nothing. Deregistering forgets every approval, so every tool comes back
as pending. `upstream update` warns when the image's repository changed
too, and keeps the approvals anyway, because you said it is the same
backend.

An `stdio` backend has no image: `upstream update` refuses it. To change
what an `stdio` entry runs, deregister it and register it again.

## Steps

1. Optional: tell analysts first. From the next call, calls to the backend
   are answered with your message and not sent to it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream maintenance on -config "$CFG" edr \
     -message "edr is being upgraded; back in about 15 minutes" -until 30m
   ```

2. Put the new image in the service account's image store and print its
   digest. Gatte never pulls (`--pull=never`), so an image the account does
   not have makes the backend fail:

   ```sh
   sudo -u mcpgw podman pull registry.example.org/edr-mcp:1.5
   sudo -u mcpgw podman inspect --format '{{index .RepoDigests 0}}' registry.example.org/edr-mcp:1.5
   ```

3. As the service account, move the entry to the new digest:

   ```sh
   sudo -u mcpgw mcp-gateway upstream update -config "$CFG" \
     -image registry.example.org/edr-mcp@sha256:<64 hex> edr
   ```

   It prints the old and new image and the quarantine it kept (`N approved,
   N pending, N changed`), and writes an `(upstream update)` row. It changes
   only the image; arguments and variable names stay as signed.

   The stored signature was for the old image and no longer verifies the
   entry: `upstream list` shows `INVALID` in `SIGNED` at once, and from the
   next reconciliation (within one `quarantine.refresh_interval`, default
   `5m`) the gateway refuses the entry, whatever `signer.require_signed`
   says. The backend's tools are unavailable from then until step 4.

4. As root, sign the entry again:

   ```sh
   sudo mcp-gateway sign -config "$CFG" edr
   ```

   Read the fields it prints, the new image among them. The signature is
   what vouches for the new code: the quarantine compares text, not
   behaviour.

5. Wait for the next discovery, within one `quarantine.refresh_interval`.
   `serve`'s log says `backend is live` for `edr`.

6. As the service account, review what the new image changed:

   ```sh
   sudo -u mcpgw mcp-gateway tool review -config "$CFG" -server edr
   ```

   - A tool whose definition is byte-identical stays approved and does not
     appear here.
   - A tool whose name, description or schema differs is `changed`, shown
     with a diff, and not served until approved.
   - A tool the new image adds is `pending`.

   Approve what you read, as a set or one at a time
   ([Review and approve tools](review-and-approve-tools.md)). If it says
   nothing on `edr` is waiting for review, every tool came through
   unchanged.

7. If you started maintenance in step 1, end it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream maintenance off -config "$CFG" edr
   ```

## What happens to approvals

| After the new image's first discovery | Status | Served |
|---|---|---|
| definition byte-identical to the approved one | `approved` | yes |
| name, description or schema differs | `changed` | no, until you approve the new fingerprint |
| a tool the old image did not have | `pending` | no, until you approve it |

Grants in `config.toml` are unchanged: a tool that stays approved keeps
reaching the roles that grant it, and a new tool reaches only the roles
that already grant it by name or by `["*"]` once approved.

## Check it worked

- `sudo -u mcpgw mcp-gateway upstream list -config "$CFG"` shows the new
  digest and `yes` in `SIGNED`.
- `sudo -u mcpgw mcp-gateway tool list -config "$CFG" -server edr` shows no
  `changed` or `pending` tool you meant to serve.
- `sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool "(upstream update)"`
  shows the row with both images.
