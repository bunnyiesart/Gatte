// Dashboard behaviour for jailmap.
//
// This lives in its own file, and not inline in index.html, for a
// specific reason: serve.go sends
//   Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; ...
// which grants 'unsafe-inline' to STYLES only. Scripts fall through to
// default-src 'self', and 'self' does not permit an inline <script>. So an
// inline block is silently refused by the browser: the page renders, the
// CSS applies, and not one line of this ever runs -- the status text sits
// on "connecting" forever with no error anywhere except the console.
//
// That is exactly what happened, and curl could not reveal it because curl
// does not enforce CSP. Served as a file, 'self' covers it and the policy
// stays strict. Do not move this back inline.
(function () {
  "use strict";

  var el = function (id) { return document.getElementById(id); };

  function text(tag, value, cls) {
    var n = document.createElement(tag);
    n.textContent = value == null ? "" : String(value);
    if (cls) n.className = cls;
    return n;
  }

  function badge(label, cls) { return text("span", label, "badge " + cls); }

  function kindBadge(kind) {
    if (kind === "vnet") return badge("vnet", "b-ok");
    if (kind === "classic") return badge("classic", "b-warn");
    return badge("host", "b-neutral");
  }

  var EXPOSURE = {
    local:      { label: "loopback only",  cls: "b-ok" },
    encrypted:  { label: "routable / tls", cls: "b-neutral" },
    plaintext:  { label: "plaintext",      cls: "b-alert" },
    rewritten:  { label: "rewritten",      cls: "b-alert" }
  };

  // Exposure is about the bind; reachability is about the firewall in front
  // of it. They are shown as two badges rather than one verdict because
  // they are two facts, and collapsing them is how the old display managed
  // to shout PLAINTEXT at ports pf was already dropping.
  var REACH = {
    filtered: { label: "pf default-deny in", cls: "b-neutral" },
    unknown:  { label: "reachability unknown", cls: "b-warn" }
  };

  function fmtAge(sec) {
    if (sec < 1) return "now";
    if (sec < 60) return Math.round(sec) + "s";
    if (sec < 3600) return Math.round(sec / 60) + "m";
    return (sec / 3600).toFixed(1) + "h";
  }

  function fmtDur(sec) {
    if (sec < 60) return sec + "s";
    if (sec % 3600 === 0) return (sec / 3600) + "h";
    if (sec % 60 === 0) return (sec / 60) + "m";
    return Math.round(sec) + "s";
  }

  // Age is shown as a bar as well as a number so a stale edge left over in
  // the window is distinguishable from a live one at a glance, which is the
  // whole risk of showing a window rather than an instant.
  function ageCell(ageSec, windowSec) {
    var wrap = document.createElement("div");
    wrap.className = "agewrap";
    var bar = document.createElement("div");
    var frac = Math.max(0, Math.min(1, 1 - ageSec / Math.max(1, windowSec)));
    bar.className = "agebar" + (ageSec > windowSec * 0.5 ? " old" : (ageSec > 3 ? " mid" : ""));
    var fill = document.createElement("i");
    fill.style.width = (frac * 100).toFixed(1) + "%";
    bar.appendChild(fill);
    wrap.appendChild(bar);
    wrap.appendChild(text("span", fmtAge(ageSec), "age"));
    return wrap;
  }

  function endpointCell(r) {
    var td = document.createElement("td");
    if (r.unknown) {
      td.appendChild(text("span", r.addr + ":" + r.port, "addr"));
      td.appendChild(document.createTextNode(" "));
      td.appendChild(badge("unknown", "b-neutral"));
      return td;
    }
    var line = document.createElement("div");
    line.appendChild(text("span", r.name, "name"));
    td.appendChild(line);
    var addr = document.createElement("div");
    addr.appendChild(text("span", r.addr + ":" + r.port, "addr"));
    addr.style.color = "var(--ink-dim)";
    td.appendChild(addr);
    return td;
  }

  function renderParticipants(list) {
    var box = el("participants");
    box.textContent = "";
    list.forEach(function (p) {
      var card = document.createElement("div");
      card.className = "card";
      var h = text("h3", p.name);
      h.appendChild(document.createTextNode(" "));
      h.appendChild(kindBadge(p.kind));
      card.appendChild(h);
      card.appendChild(text("div", "jid " + p.jid + (p.hostname && p.hostname !== p.name ? "  " + p.hostname : ""), "sub"));

      var ul = document.createElement("ul");
      (p.addrs || []).forEach(function (a) {
        var li = document.createElement("li");
        li.appendChild(document.createTextNode(a.addr));
        if (a.iface) {
          li.appendChild(document.createTextNode(" "));
          li.appendChild(text("span", a.iface, "if"));
        }
        if (a.loopback) {
          li.appendChild(document.createTextNode(" "));
          li.appendChild(badge("loopback", "b-neutral"));
        }
        ul.appendChild(li);
      });
      if (!(p.addrs || []).length) {
        ul.appendChild(text("li", "no addresses reported"));
      }
      card.appendChild(ul);
      (p.notes || []).forEach(function (n) { card.appendChild(text("p", n, "note")); });
      box.appendChild(card);
    });
  }

  function renderListeners(list, windowSec) {
    var tb = el("listeners").tBodies[0];
    tb.textContent = "";
    el("listeners-empty").hidden = list.length > 0;

    // Grouped by owner so the reading order is "this jail, and everything
    // it opens" rather than a flat port list.
    var order = [], groups = {};
    list.forEach(function (l) {
      if (!groups[l.owner]) { groups[l.owner] = []; order.push(l.owner); }
      groups[l.owner].push(l);
    });

    order.forEach(function (owner) {
      var head = document.createElement("tr");
      head.className = "rowgroup";
      var td = document.createElement("td");
      td.colSpan = 7;
      td.appendChild(document.createTextNode(owner));
      var clear = groups[owner].filter(function (l) {
        return l.exposure === "plaintext" || l.exposure === "rewritten";
      });
      // Split by what pf does, so the count that reads as an alarm is only
      // the one that is one.
      var exposed = clear.filter(function (l) { return l.reachability !== "filtered"; }).length;
      var shielded = clear.length - exposed;
      if (exposed) {
        td.appendChild(document.createTextNode(" "));
        td.appendChild(badge(exposed + " in the clear on a routable address", "b-alert"));
      }
      if (shielded) {
        td.appendChild(document.createTextNode(" "));
        td.appendChild(badge(shielded + " plaintext bind" + (shielded > 1 ? "s" : "") + " behind pf", "b-neutral"));
      }
      head.appendChild(td);
      tb.appendChild(head);

      groups[owner].forEach(function (l) {
        var tr = document.createElement("tr");
        if (l.age > 10) tr.className = "stale";
        tr.appendChild(text("td", l.owner));

        var addrTd = document.createElement("td");
        addrTd.appendChild(text("span", l.addr + ":" + l.port, "addr"));
        if (l.service) {
          addrTd.appendChild(document.createTextNode(" "));
          addrTd.appendChild(text("span", l.service, "proc"));
        }
        tr.appendChild(addrTd);

        tr.appendChild(text("td", l.proto, "addr"));
        tr.appendChild(text("td", l.command, "proc"));
        tr.appendChild(text("td", l.user, "proc"));

        var e = EXPOSURE[l.exposure] || { label: l.exposure, cls: "b-neutral" };
        var expTd = document.createElement("td");
        // A plaintext bind behind a default-deny pf is a true statement
        // about the bind and a false alarm about the exposure. Keep the
        // fact, drop the alarm colour, and say which it is on hover.
        var reach = REACH[l.reachability];
        if (reach && e.cls === "b-alert") e = { label: e.label, cls: reach.cls };
        var b = badge(e.label, e.cls);
        if (l.reachability_note) b.title = l.reachability_note;
        expTd.appendChild(b);
        if (reach) {
          expTd.appendChild(document.createTextNode(" "));
          var rb = badge(reach.label, reach.cls);
          if (l.reachability_note) rb.title = l.reachability_note;
          expTd.appendChild(rb);
        }
        if (l.wildcard) {
          expTd.appendChild(document.createTextNode(" "));
          expTd.appendChild(badge("wildcard", "b-warn"));
        }
        tr.appendChild(expTd);

        var ageTd = document.createElement("td");
        ageTd.appendChild(ageCell(l.age, windowSec));
        tr.appendChild(ageTd);
        tb.appendChild(tr);
      });
    });
  }

  // The MCP topology. It gets its own section and its own shape because it
  // is not made of network edges: the gateway speaks to each upstream over
  // a pipe, which has no address, no port and nothing for sockstat to see.
  // Rendering it in the connection table would be inventing connections.
  function renderGateways(list, seenAgeSec, everRead) {
    var box = el("gateways");
    box.textContent = "";
    var empty = el("gateways-empty");
    empty.hidden = list.length > 0;
    if (!list.length) {
      empty.textContent = everRead
        ? "No gateway process is running; nothing spawns MCP upstreams here."
        : "The process table has not been read yet.";
      return;
    }

    list.forEach(function (g) {
      var d = document.createElement("div");
      d.className = "gw";

      var head = document.createElement("div");
      head.className = "gw-head";
      head.appendChild(text("span", g.owner, "name"));
      head.appendChild(kindBadge(g.kind));
      head.appendChild(badge("pid " + g.pid, "b-neutral"));
      head.appendChild(badge("up " + fmtUptime(g.uptime_seconds), "b-neutral"));
      // Independent confirmation, from a different command, that this
      // process really is the gateway and not something sharing its name.
      if ((g.listens_on || []).length) {
        head.appendChild(badge("listening on " + g.listens_on.join(", "), "b-ok"));
      } else {
        head.appendChild(badge("no listening socket on this pid", "b-warn"));
      }
      d.appendChild(head);
      d.appendChild(text("div", g.command, "gw-meta"));

      var kids = document.createElement("ul");
      kids.className = "kids";
      if (!(g.upstreams || []).length) {
        kids.appendChild(text("li", "No child processes: this gateway has spawned no stdio upstreams.", "none"));
      }
      (g.upstreams || []).forEach(function (u) {
        var li = document.createElement("li");
        li.appendChild(text("span", u.name, "up"));
        li.appendChild(document.createTextNode(" "));
        li.appendChild(text("span", "pid " + u.pid + "  up " + fmtUptime(u.uptime_seconds) + "  " + u.user, "dim"));
        var cmd = text("div", u.command, "dim");
        li.appendChild(cmd);
        if (u.descendants) {
          li.appendChild(text("div", "+" + u.descendants + " further descendants", "dim"));
        }
        kids.appendChild(li);
      });
      d.appendChild(kids);
      d.appendChild(text("div", "process table read " + (seenAgeSec < 1 ? "just now" : fmtAge(seenAgeSec) + " ago"), "gw-meta"));
      box.appendChild(d);
    });
  }

  function fmtUptime(sec) {
    if (!sec || sec <= 0) return "?";
    var s = Math.floor(sec);
    var d = Math.floor(s / 86400); s -= d * 86400;
    var h = Math.floor(s / 3600);  s -= h * 3600;
    var m = Math.floor(s / 60);    s -= m * 60;
    var pad = function (n) { return (n < 10 ? "0" : "") + n; };
    if (d) return d + "d" + pad(h) + "h";
    if (h) return h + "h" + pad(m) + "m";
    if (m) return m + "m" + pad(s) + "s";
    return s + "s";
  }

  function renderFirewall(fw) {
    var p = el("fwline");
    p.textContent = "";
    fw = fw || {};
    var lead = fw.default_deny_in ? "pf filtered" : (fw.known && !fw.enabled ? "pf off" : "pf");
    p.appendChild(text("b", lead + ": "));
    p.appendChild(document.createTextNode(fw.summary || "firewall state unknown"));
  }

  var SCOPES = [
    ["in-jail",  "In-jail loopback", "both ends inside one jail's own network stack"],
    ["internal", "On this host",     "between the host and its jails, over routable addresses"],
    ["external", "External",         "one end is not in the address book"]
  ];

  // The aggregate view: a hundred ephemeral source ports against one nginx
  // is one fact, and this is where it reads as one.
  function renderEdges(list, windowSec) {
    var tb = el("edges").tBodies[0];
    tb.textContent = "";
    el("edges-empty").hidden = list.length > 0;

    SCOPES.forEach(function (spec) {
      var rows = list.filter(function (e) { return e.scope === spec[0]; });
      if (!rows.length) return;

      var head = document.createElement("tr");
      head.className = "rowgroup";
      var td = document.createElement("td");
      td.colSpan = 7;
      td.appendChild(document.createTextNode(spec[1]));
      td.appendChild(document.createTextNode("  "));
      td.appendChild(text("span", spec[2], "hint"));
      head.appendChild(td);
      tb.appendChild(head);

      rows.forEach(function (e) {
        var tr = document.createElement("tr");
        if (e.age > windowSec * 0.5) tr.className = "stale";
        tr.appendChild(text("td", e.client, e.client.indexOf(".") >= 0 ? "addr" : "name"));
        tr.appendChild(text("td", "→", "arrow"));

        var srv = document.createElement("td");
        srv.appendChild(text("div", e.server, "name"));
        var line = document.createElement("div");
        line.appendChild(text("span", e.server_addr + ":" + e.server_port, "addr"));
        line.style.color = "var(--ink-dim)";
        srv.appendChild(line);
        tr.appendChild(srv);

        tr.appendChild(text("td", e.proto, "addr"));
        tr.appendChild(text("td", e.process || "??", "proc"));
        tr.appendChild(text("td", e.connections, "addr"));

        var ageTd = document.createElement("td");
        ageTd.appendChild(ageCell(e.age, windowSec));
        tr.appendChild(ageTd);
        tb.appendChild(tr);
      });
    });
  }

  function renderFlows(list, windowSec) {
    var tb = el("flows").tBodies[0];
    tb.textContent = "";
    el("flows-empty").hidden = list.length > 0;

    SCOPES.forEach(function (spec) {
      var rows = list.filter(function (f) { return f.scope === spec[0]; });
      if (!rows.length) return;

      var head = document.createElement("tr");
      head.className = "rowgroup";
      var td = document.createElement("td");
      td.colSpan = 7;
      td.appendChild(document.createTextNode(spec[1] + " (" + rows.length + ")"));
      td.appendChild(document.createTextNode("  "));
      td.appendChild(text("span", spec[2], "hint"));
      head.appendChild(td);
      tb.appendChild(head);

      rows.forEach(function (f) {
        var tr = document.createElement("tr");
        if (f.age > windowSec * 0.5) tr.className = "stale";
        tr.appendChild(endpointCell(f.client));
        tr.appendChild(text("td", "→", "arrow"));
        tr.appendChild(endpointCell(f.server));
        tr.appendChild(text("td", f.proto, "addr"));

        var procTd = document.createElement("td");
        var proc = f.server_proc || f.client_proc;
        procTd.appendChild(text("span", proc || "??", "proc"));
        if (f.direction_inferred) {
          procTd.appendChild(document.createTextNode(" "));
          procTd.appendChild(badge("direction inferred", "b-warn"));
        }
        tr.appendChild(procTd);

        var ageTd = document.createElement("td");
        ageTd.appendChild(ageCell(f.age, windowSec));
        tr.appendChild(ageTd);
        tr.appendChild(text("td", f.samples + "x", "proc"));
        tb.appendChild(tr);
      });
    });
  }

  function renderWarnings(list) {
    var box = el("warnbox"), ul = el("warnings");
    ul.textContent = "";
    box.hidden = !list || !list.length;
    (list || []).forEach(function (w) { ul.appendChild(text("li", w)); });
  }

  var failures = 0;

  function tick() {
    // A timeout is not a nicety here. fetch() has none by default, so a
    // connection that opens and then stalls -- a half-dead SSH tunnel is
    // the way this actually happens, since jailmap is always reached
    // through one -- leaves the promise pending forever. Neither .then nor
    // .catch runs, the status text stays on its initial "connecting", and
    // the page gives the reader no way to tell "still starting up" from
    // "the tunnel died ten minutes ago". Observed exactly that.
    //
    // 4s against a 1s poll: long enough that a slow sample is not reported
    // as a failure, short enough that a dead link is named while the
    // reader is still looking at the screen.
    var ctl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, 4000) : null;

    fetch("/api/snapshot", { cache: "no-store", signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        if (timer) { clearTimeout(timer); timer = null; }
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (s) {
        failures = 0;
        var now = Date.parse(s.generated) / 1000;
        var age = function (t) { return Math.max(0, now - Date.parse(t) / 1000); };
        (s.listeners || []).forEach(function (l) { l.age = age(l.last_seen); });
        (s.flows || []).forEach(function (f) { f.age = age(f.last_seen); });
        (s.edges || []).forEach(function (e) { e.age = age(e.last_seen); });

        el("win").textContent = fmtDur(s.window_seconds);
        el("int").textContent = s.interval_ms + "ms";
        el("samples").textContent = s.samples;
        el("live").textContent = "sampling";
        el("pulse").className = "pulse";

        renderParticipants(s.participants || []);
        renderGateways(s.gateways || [], s.gateways_age_seconds || 0,
                       !!(s.gateways_seen && Date.parse(s.gateways_seen) > 0));
        renderFirewall(s.firewall);
        renderListeners(s.listeners || [], s.window_seconds);
        renderEdges(s.edges || [], s.window_seconds);
        // Capped: under load this list runs to thousands of rows, and a
        // page that stops repainting is not a live dashboard. The aggregate
        // above stays complete.
        var flows = s.flows || [];
        renderFlows(flows.slice(0, 400), s.window_seconds);
        el("flowhint").textContent = flows.length > 400
          ? "one row per source port, newest first -- showing 400 of " + flows.length
          : "one row per source port, newest first";
        renderWarnings(s.warnings);
      })
      .catch(function (e) {
        if (timer) { clearTimeout(timer); timer = null; }
        failures++;
        // An abort and a refusal are different problems with different
        // fixes, and "no answer" for both sends the reader looking in the
        // wrong place. A stalled request almost always means the tunnel
        // this page is reached through has died; a refusal means jailmap
        // itself is not answering.
        var why = (e && e.name === "AbortError")
          ? "no reply within 4s -- the SSH tunnel has probably dropped"
          : "no answer from jailmap (" + (e && e.message ? e.message : e) + ")";
        el("live").textContent = why;
        el("pulse").className = failures > 3 ? "pulse dead" : "pulse stale";
      });
  }

  tick();
  setInterval(tick, 1000);
})();
