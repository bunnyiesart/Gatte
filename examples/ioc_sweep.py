#!/usr/bin/env python3
"""Minimal MCP stdio server for examples/byo-script.toml. Standard library only.

Framing: newline-delimited JSON-RPC 2.0, one message per line on stdin and
stdout, which is what the gateway's stdio dialer speaks. Nothing else may
be written to stdout; use stderr for logs.

It advertises one tool, sweep_iocs. The "sweep" is a placeholder: it
echoes the indicators back and reports whether IOC_SWEEP_API_KEY arrived
from the vault, never its value, plus the NAMES of the environment
variables the process received -- which shows what the gateway passes on
(PATH, HOME and the declared -env names) and that nothing else is inherited.
The list also shows LC_CTYPE: Python 3.7 and later adds it to its own
environment when no locale is set (PEP 538), so it is not from the gateway.
Replace the body of sweep() with the call to your own API.
"""
import json
import os
import sys

TOOLS = [
    {
        "name": "sweep_iocs",
        "description": "Sweep a list of indicators of compromise (example).",
        "inputSchema": {
            "type": "object",
            "properties": {"iocs": {"type": "array", "items": {"type": "string"}}},
            "required": ["iocs"],
        },
    },
]


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def reply(msg_id, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": msg_id}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    send(msg)


def sweep(iocs):
    key_present = bool(os.environ.get("IOC_SWEEP_API_KEY"))
    return "swept %d ioc(s): %s; key_present=%s; env_names=%s" % (
        len(iocs), ",".join(iocs), str(key_present).lower(), ",".join(sorted(os.environ)))


def handle(req):
    method = req.get("method")
    msg_id = req.get("id")
    if msg_id is None:
        return  # a notification, such as notifications/initialized
    if method == "initialize":
        reply(msg_id, {
            "protocolVersion": req.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "ioc-sweep", "version": "0.1.0"},
        })
    elif method == "ping":
        reply(msg_id, {})
    elif method == "tools/list":
        reply(msg_id, {"tools": TOOLS})
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") != "sweep_iocs":
            reply(msg_id, error={"code": -32602, "message": "unknown tool"})
            return
        iocs = params.get("arguments", {}).get("iocs", [])
        reply(msg_id, {"content": [{"type": "text", "text": sweep(iocs)}], "isError": False})
    else:
        reply(msg_id, error={"code": -32601, "message": "method not found"})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            reply(None, error={"code": -32700, "message": "parse error"})
            continue
        handle(req)


if __name__ == "__main__":
    main()
