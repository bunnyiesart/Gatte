# Respond to an incident

This page is for operators when an analyst's account, laptop or token may
be in the wrong hands, or when a backend behind Gatte may be compromised.
It covers cutting one analyst off, reading and handing over what they did,
checking the trail against the SIEM, and taking a backend out.

You need: a shell on the gateway host, and `sudo` to run commands as the
service account `mcpgw`. The examples use
`CFG=/usr/local/etc/mcp-gateway/config.toml`. Each step also exists in the
web console (**Access**, **Audit**, **Backends**), with the same checks and
the same audit rows.

## Cut off one analyst now

An incident needs two actions: a block at the gateway, which takes effect
on the next request, and a revoke at the identity provider, which Gatte
cannot do for you (`design/adr/0031`).

1. Find the analyst's subject, the token's `sub`. On **People**, **Seen on
   the gateway** lists each subject with the name the IdP gave. On the
   host, `audit` shows the subject in the ANALYST column and the name in
   NAME:

   ```sh
   sudo -u mcpgw mcp-gateway audit -config "$CFG" -limit 200
   ```

   The name is for reading only: block by the subject.

2. Block the subject. Flags go before it. Put who is acting in `-reason`,
   because the row can only name the login account that ran the command:

   ```sh
   sudo -u mcpgw mcp-gateway access block -config "$CFG" \
     -reason "INC-0421: laptop reported stolen; blocked by the on-call operator" SUBJECT
   ```

   The running gateway refuses that subject from its next request, whatever
   token it carries, with no restart. If no request from the subject is on
   the trail, the command warns (usually a typo) and blocks anyway.

   For a block that ends by itself, add `-until` with a duration from now
   (`8h`, `90m`) or an RFC 3339 time (`2026-10-01T08:00:00Z`). The gateway
   stops refusing the subject at that instant and writes an
   `(access block expired)` row at its next maintenance round. A subject
   already blocked keeps its block and its end: to change the end, run
   `access unblock`, then block again.

3. Revoke the analyst's sessions and tokens at the IdP, with its own tools.
   The block does not touch the IdP: a token stays valid there until it
   expires, for every other application behind it. If the person is
   leaving, use **Offboard** in the console instead of step 2: it blocks
   and disables the account in one call
   ([Add and remove people](add-and-remove-people.md#when-someone-leaves-offboard)).

Check it worked:

```sh
sudo -u mcpgw mcp-gateway access list -config "$CFG"
sudo -u mcpgw mcp-gateway audit -config "$CFG" -subject SUBJECT -outcome denied -limit 10
```

The subject is listed, and each request it makes from now on is a `denied`
row with the reason `subject blocked`. The analyst gets a `403` whose body
says "Gatte refuses requests from this account. Signing in again will not
change that: ask the SOC operator."; Claude Code shows it as "Needs
authentication".

The block's row says where the operator name came from: `[cli]` when the
kernel said it (on Linux, the loginuid, which survives `sudo`), `[cli env]`
when it was `SUDO_USER` or `USER`, `[ui]` from the console.

To lift the block:

```sh
sudo -u mcpgw mcp-gateway access unblock -config "$CFG" -reason "INC-0421 closed" SUBJECT
```

## Read what they did

`audit` prints the most recent matching rows, newest first. Filters match
exactly and combine with AND; `-since` is inclusive and `-until` exclusive,
both RFC 3339.

- Everything one analyst did in a window:

  ```sh
  sudo -u mcpgw mcp-gateway audit -config "$CFG" -subject SUBJECT \
    -since 2026-09-30T08:00:00Z -until 2026-09-30T16:00:00Z -limit 0
  ```

- Who called one tool, or anything on one backend:

  ```sh
  sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool casemgmt.list_cases -since 2026-09-30T08:00:00Z -limit 0
  sudo -u mcpgw mcp-gateway audit -config "$CFG" -server casemgmt -since 2026-09-30T08:00:00Z -limit 0
  ```

- Refusals only: add `-outcome denied`. Requests that never authenticated
  are attributed to `(unauthenticated)`: `-subject "(unauthenticated)"`.
  Their rows are rate-limited per source address (`design/adr/0027`), so
  they are a sample of a flood, not a count.

`-limit 0` prints every match; the default is 50. `audit` exits 1 when
nothing matched.

When you read the rows:

- SOURCE is where the call came from, as the reverse proxy saw it. One
  subject arriving from two addresses is what a stolen token looks like.
- A call that ran and then failed leaves two rows, an `allowed` one and a
  `failed` one. Count `allowed` rows for attempts.
- The trail records who called which tool on which backend, when, with
  which outcome and reason. It never holds a tool's arguments or results.

## Hand the trail over

1. In the console, open **Audit** and set the filters (analyst, outcome,
   tool, backend, source, from, to). Times are UTC.
2. Choose **CSV** or **JSON Lines**. The file holds the filtered rows,
   newest first, up to 50 000. If the export stopped there, the file name
   says `-first50000`: narrow the window and export again.

In the CSV, hidden characters are written as `\u{XXXX}` and a cell a
spreadsheet would run as a formula starts with an apostrophe. On the host,
the same rows come out of `audit ... -limit 0 -json`.

## Check the trail was not edited

The trail is hash-chained, but the chain has no key: someone who can write
the database can rewrite rows and re-chain them. What they cannot keep is
the chain head, so compare the head against the copy your SIEM received
(`design/adr/0015`, `0017`).

You need `[audit.siem]` configured and a shipper forwarding the file.

1. Take the head from the SIEM: among the chain's record lines
   (`chain:"NAME"`, not `type:heartbeat`), the head is the `hash` that no
   other line names as its `prev_hash`. It is not the newest message: two
   records written in one tick arrive in either order.
   `deploy/gatte-anchor-verify.sh` does this for Graylog and runs the next
   step for you.
2. Compare it with the local trail:

   ```sh
   sudo -u mcpgw mcp-gateway audit -verify -config "$CFG" -expect-head HASH
   ```

3. Read the result. Exit 0 with `chain intact` means the local trail ends
   where the SIEM's copy ends. Exit 1 with `TRUNCATED OR REWRITTEN: head
   does not match the expected value.` means it does not. Before you call
   it tampering, rule out a shipper that is behind or stopped; the
   script's report tells the cases apart
   ([`deploy/freebsd-jail.md`](../../deploy/freebsd-jail.md), "Getting
   `-expect-head` right").

The limit, stated plainly: whoever controls the gateway host also controls
what the shipper sends, and can forge lines that agree with a shortened
trail. The comparison catches a lost, rolled-back or carelessly edited
trail, not an attacker who also forged the shipped lines. In the console,
the same check is **Audit**, **Verify the trail**, with **Expected head**.

## If a backend is compromised

1. Stop its calls now. Maintenance answers every call to that backend with
   your message and does not send it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream maintenance on -config "$CFG" casemgmt \
     -message "casemgmt is unavailable while the SOC investigates"
   ```

   It takes effect on the next call. The message reaches analysts and
   their models: keep incident details out of it. Maintenance does not stop
   the backend's process, which keeps running with its credentials, and the
   gateway keeps re-dialling it.

2. Remove it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream deregister -config "$CFG" casemgmt
   ```

   Within one `quarantine.refresh_interval` (default 5 minutes) the running
   gateway retires it: the connection closes and its tools are no longer
   listed. `serve` writes a `(backend health)` row with the reason
   `backend removed: no longer servable per the registry`. Deregistering
   also forgets the backend's signature, tool approvals, maintenance and
   health, so registering it again starts the review from nothing.
   `upstream deregister` writes no operator row of its own: note who ran
   it in the incident ticket.

   To withdraw one tool instead of the whole backend, revoke its approval;
   it takes effect on the next call:

   ```sh
   sudo -u mcpgw mcp-gateway tool revoke -config "$CFG" casemgmt TOOL
   ```

3. Rotate every credential the backend was given, at the provider first
   and then in the vault ([Rotate credentials and keys](rotate-credentials-and-keys.md)).
   Gatte does not limit where a backend sends data: a compromised backend
   could have sent its credential anywhere its network reaches
   (`design/adr/0033`).

Check it worked: `upstream list` no longer shows the backend, and
`audit -server casemgmt -since TIME` lists every call it was sent.

For what Gatte does and does not defend against, see the
[Security model](../explanation/security-model.md).
