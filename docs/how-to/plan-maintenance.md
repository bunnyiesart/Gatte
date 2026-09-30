# Plan maintenance

This page is for operators taking one backend out for planned work,
announcing maintenance of the whole gateway, and stopping `serve` itself
for an upgrade or a host reboot. It says what analysts see at each step
(`design/adr/0041`).

You need: a shell on the gateway host and `sudo` to run commands as the
service account `mcpgw`. The examples use
`CFG=/usr/local/etc/mcp-gateway/config.toml`. The same actions are on the
console's **Backends** page, under **Planned maintenance**.

No step here needs a restart: each takes effect on the running gateway's
next call.

## Take one backend out

1. Start the maintenance, with a message and, if you know it, the expected
   end:

   ```sh
   sudo -u mcpgw mcp-gateway upstream maintenance on -config "$CFG" casemgmt \
     -message "casemgmt upgrade to 4.2; back in about an hour" -until 2h
   ```

   - `-message` is what analysts and their models read: 1 to 200
     characters on one line, with no control or hidden characters.
   - `-until` is a duration from now (`2h`, `90m`) or an RFC 3339 time
     (`2026-10-01T15:00:00Z`), at most 90 days ahead. Durations take `h`,
     `m` and `s`, not days: write `72h`. The end is a forecast, not a
     deadline: the maintenance lasts until you run `off`.

2. Do the work. The backend's tools stay listed, and each call to one is
   answered with your message instead of being sent to it. The backend's
   process is not stopped: the gateway keeps re-dialling it as usual, and a
   restart you cause shows as `(backend health)` rows. If you restarted
   its container, `upstream redial casemgmt` picks it up at once.

3. End it:

   ```sh
   sudo -u mcpgw mcp-gateway upstream maintenance off -config "$CFG" casemgmt
   ```

Check it worked:

```sh
sudo -u mcpgw mcp-gateway maintenance list -config "$CFG"
```

While it runs, the backend is listed with its message and end; after `off`
it is not. Each `on` and `off` is a `(maintenance on)` or
`(maintenance off)` row. `off` of a backend that is not in maintenance
changes nothing and exits 1.

## Change the message or the expected end

Run `on` again. It keeps the time the maintenance started.

- A new `-message` replaces the message.
- With `-until`, the end changes; without it, the end already announced is
  kept (and dropped, with a note, if it has passed).
- `-until none` takes the announced end back.

```sh
sudo -u mcpgw mcp-gateway upstream maintenance on -config "$CFG" casemgmt \
  -message "casemgmt upgrade to 4.2 is slower than planned" -until none
```

Running `on` with the same message and end changes nothing and exits 0.

## Announce maintenance of the whole gateway

Maintenance of the whole gateway is a notice, not a block: every call is
still served.

```sh
sudo -u mcpgw mcp-gateway maintenance on -config "$CFG" \
  -message "Gatte restarts at 15:00 UTC for an upgrade; back by 15:20" -until 2026-10-01T15:20:00Z
```

End it with:

```sh
sudo -u mcpgw mcp-gateway maintenance off -config "$CFG"
```

`-message` and `-until` follow the same rules as for one backend.

## What analysts see

Only an analyst who is granted and approved for a tool on the backend is
told anything about it; to everyone else the backend's tools answer as they
did before.

- **A backend in maintenance.** A call to one of its tools is answered with
  a result that starts "Gatte: the backend "casemgmt" is in planned
  maintenance since ...", gives the expected end, quotes your message, and
  tells the model not to change the request. `gatte.status` shows the
  backend as `maintenance`, with your message. Once `-until` has passed,
  the text says "that time has passed; the maintenance has not been ended
  yet".
- **The whole gateway in maintenance.** Text results, and Gatte's own
  answers, end with a block that starts "Gatte notice: the Gatte gateway is
  in planned maintenance since ...", with your message. `gatte.status`
  carries it too. A result that has `structuredContent` does not carry the
  notice, because Claude Code hands the model only the structured object;
  `gatte.status` is where it always arrives.
- **Never shown to analysts:** who set the maintenance, and when it last
  changed.

The texts are listed in full in
[What the analyst is told](../reference/analyst-messages.md).

## Stop serve itself

For an upgrade, follow [Upgrading Gatte, and rolling back](../upgrade.md),
which adds a backup and two `check` runs to these steps.

1. Announce it, with the expected end:

   ```sh
   sudo -u mcpgw mcp-gateway maintenance on -config "$CFG" \
     -message "Gatte restarts for a host reboot; back in about 20 minutes" -until 20m
   ```

2. Wait a few minutes, so open sessions read the notice on their next
   call.
3. Stop `serve`, and the management API if the work touches the binary or
   the database:

   ```sh
   sudo systemctl stop mcp-gateway                      # FreeBSD: sudo service mcp_gateway stop
   sudo systemctl stop mcp-gateway-admin.socket mcp-gateway-admin.service
   ```

4. Do the work. While `serve` is stopped nothing answers inside MCP: Claude
   Code shows the server as failed, and the analyst's `gatte-status` exits
   3 ("Gatte, or the proxy in front of it, is not serving"). If your
   reverse proxy is set to answer `503` with a one-line maintenance
   sentence while its upstream is down, that sentence reaches Claude Code
   and `gatte-status`; Gatte does not ship such a proxy rule.
5. Start it again:

   ```sh
   sudo systemctl start mcp-gateway                     # FreeBSD: sudo service mcp_gateway start
   sudo systemctl start mcp-gateway-admin.socket        # if you stopped it
   ```

6. End the maintenance:

   ```sh
   sudo -u mcpgw mcp-gateway maintenance off -config "$CFG"
   ```

The maintenance is stored in the database, so it is still on after the
restart until you end it. Check the restart: the first row of the new boot
is `(boot)`, naming the build and the database schema:

```sh
sudo -u mcpgw mcp-gateway audit -config "$CFG" -tool "(boot)" -limit 1
```

Outside planned work, the service manager restarts `serve` when it fails
(`Restart=on-failure` in `examples/systemd/mcp-gateway.service`).
