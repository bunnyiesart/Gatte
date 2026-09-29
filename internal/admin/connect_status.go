package admin

// gatte-status (design/adr/0041 item 8a): the command the connect script
// installs on an analyst's machine for the one case nothing in-band can
// help with -- Gatte itself not answering. It tells "the network does not
// reach Gatte" (VPN, DNS, route) from "TLS" from "Gatte, or the proxy in
// front of it, is not serving" from "Gatte is up and Claude Code is not
// signed in", using only what anyone who reaches the host already sees:
// the protected-resource metadata and the MCP endpoint's 401 challenge.
// No new public endpoint exists for it, and it reads no token.
//
// It is rendered from the same validated values as the connect script
// (URL, server name, whether a CA is installed) and nothing else, so every
// value is safe inside single quotes in sh and PowerShell.

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/bunnyiesart/Gatte/pkg/adminapi"
)

var statusSh = template.Must(template.New("status-sh").Parse(`#!/bin/sh
# gatte-status: can this machine reach Gatte, the team's MCP gateway, and is
# Claude Code signed in to it? Installed by connect-gatte ({{.Date}}).
# Contains no secret, reads no token and keeps nothing.
#
#   gatte-status            check the network, Gatte and Claude Code
#   gatte-status -backends  also ask Claude Code to call gatte.status
#
# Exit: 0 Gatte answers and Claude Code connects (backends are checked
# only with -backends); 1 network (VPN, DNS, route); 2 TLS; 3 Gatte, or the
# proxy in front of it, is not serving; 4 Gatte is up but Claude Code is not
# signed in or not set up; 5 unexpected.

GATTE_URL='{{.URL}}'
GATTE_META='{{.MetaURL}}'
GATTE_SERVER='{{.Server}}'
# The name Claude Code gives the gatte.status tool: it shows "." as "_".
GATTE_TOOL='mcp__{{.Server}}__gatte_status'
{{- if .CAPEM}}
GATTE_CA="$HOME/.config/gatte/ca.pem"
{{- end}}

say() { printf '%s\n' "$*"; }
# One line, no control characters, at most 300 positions: what a server or
# Claude Code says is shown, never interpreted by the terminal.
clean() { tr -d '\000-\037\177' | cut -c1-300; }

backends=no
for arg in "$@"; do
  case "$arg" in
    -backends|--backends) backends=yes ;;
    -h|-help|--help) sed -n '2,12p' "$0" | cut -c3-; exit 0 ;;
    *) say "gatte-status: unknown argument $arg (try -h)"; exit 5 ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  say "gatte-status needs curl, which is not installed on this machine."
  exit 5
fi
tmp=$(mktemp -d 2>/dev/null) || { say "gatte-status: cannot create a temporary directory."; exit 5; }
trap 'rm -rf "$tmp"' EXIT

say "Gatte: $GATTE_URL"

# 1. Does Gatte answer? Its protected-resource metadata is public.
code=$(curl -sS -o "$tmp/body" -w '%{http_code}' --max-time 10{{if .CAPEM}} --cacert "$GATTE_CA"{{end}} "$GATTE_META" 2>"$tmp/err")
rc=$?
case $rc in
  0) ;;
  6)
    say "✘ The name of Gatte's host does not resolve. Are you on the VPN? Is DNS working?"
    exit 1 ;;
  28)
    say "✘ Gatte's host did not answer within 10 seconds: VPN, firewall or route. Are you on the VPN?"
    exit 1 ;;
  7)
    if grep -qiE 'No route to host|Network is unreachable' "$tmp/err"; then
      say "✘ The network does not reach Gatte's host. Are you on the VPN?"
      exit 1
    fi
    say "✘ Gatte's host answers, but nothing is listening on Gatte's port: Gatte, or the proxy in front of it, is stopped."
    say "  This is not your network. Tell the Gatte operator."
    exit 3 ;;
  35|51|58|60|77)
    say "✘ The TLS connection to Gatte failed: $(clean < "$tmp/err")"
    say "  Run connect-gatte again to reinstall the team's certificate authority; if it persists, tell the Gatte operator."
    exit 2 ;;
  *)
    say "✘ Unexpected error reaching Gatte (curl exit $rc): $(clean < "$tmp/err")"
    exit 5 ;;
esac
case "$code" in
  200) say "✓ Gatte answers." ;;
  502|503|504)
    say "✘ The proxy in front of Gatte answers, but Gatte does not (HTTP $code): it is stopped or in maintenance."
    say "  It says: $(clean < "$tmp/body")"
    say "  Retry later, or tell the Gatte operator."
    exit 3 ;;
  *)
    say "✘ Gatte's address answered HTTP $code where Gatte answers 200: something in front of it is not Gatte. Tell the Gatte operator."
    exit 5 ;;
esac

# 2. Is the MCP endpoint Gatte's? Without a token it must ask for sign-in.
code=$(curl -sS -o /dev/null -D "$tmp/head" -w '%{http_code}' --max-time 10{{if .CAPEM}} --cacert "$GATTE_CA"{{end}} -X POST -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data '{"jsonrpc":"2.0","id":1,"method":"ping"}' "$GATTE_URL" 2>"$tmp/err")
rc=$?
if [ "$rc" -ne 0 ]; then
  say "✘ Gatte's MCP endpoint did not answer (curl exit $rc): $(clean < "$tmp/err")"
  exit 5
fi
case "$code" in
  401)
    if grep -qi '^www-authenticate:.*resource_metadata' "$tmp/head"; then
      say "✓ Gatte's MCP endpoint asks for sign-in, as it should."
    else
      say "✘ The MCP endpoint refused without Gatte's sign-in challenge: something in front of it is not Gatte. Tell the Gatte operator."
      exit 5
    fi ;;
  502|503|504)
    say "✘ The proxy in front of Gatte answers, but Gatte's MCP endpoint does not (HTTP $code). Retry later, or tell the Gatte operator."
    exit 3 ;;
  *)
    say "✘ The MCP endpoint answered HTTP $code without asking for sign-in: something in front of it is not Gatte. Tell the Gatte operator."
    exit 5 ;;
esac

# 3. Is Claude Code signed in? claude mcp get exits 0 whatever the state,
# so only its Status: and Issue: lines are read. Claude Code always runs
# from the script's own temporary directory: where the analyst stands may
# be a checkout whose project settings, hooks or .mcp.json would load with it.
if ! command -v claude >/dev/null 2>&1; then
  say "✘ Claude Code is not installed on this machine (no claude command). Install it, then run connect-gatte."
  exit 4
fi
(cd "$tmp" && claude mcp get "$GATTE_SERVER") >"$tmp/get" 2>&1
status=$(grep -m 1 'Status:' "$tmp/get" | clean)
issue=$(grep -m 1 'Issue:' "$tmp/get" | sed 's/^[[:space:]]*Issue:[[:space:]]*//' | clean)
case "$status" in
  *"Needs authentication"*)
    say "✘ Gatte is up, but Claude Code is not signed in to it."
    say "  Open claude, type /mcp, choose $GATTE_SERVER and authenticate."
    exit 4 ;;
  *"Failed to connect"*)
    case "$issue" in
      "HTTP 5"*)
        say "✘ Gatte answers but is not serving tools right now. Claude Code says:"
        say "  $issue"
        say "  Retry in a few minutes, or tell the Gatte operator."
        exit 3 ;;
      *)
        say "✘ Claude Code could not connect to Gatte, for a reason this check does not know:"
        say "  $issue"
        say "  Tell the Gatte operator."
        exit 5 ;;
    esac ;;
  *Connected*)
    say "✓ Claude Code connects to Gatte as $GATTE_SERVER: Gatte itself is fine."
    say "  If your open claude session shows $GATTE_SERVER as failed or disconnected, type /mcp there, choose $GATTE_SERVER and reconnect."
    if [ "$backends" != yes ]; then
      say "  The backends behind Gatte were not checked. If a tool keeps failing, run gatte-status -backends"
      say "  (one model request), or ask Claude to call gatte.status."
    fi ;;
  *)
    say "✘ Claude Code has no server named $GATTE_SERVER. Run connect-gatte again."
    exit 4 ;;
esac

# 4. Optional: the backends, as gatte.status tells Claude Code. It costs a
# model request, and what prints is the model's answer, not Gatte's.
if [ "$backends" = yes ]; then
  say ""
  say "Asking Claude Code to call gatte.status (one model request)."
  say "The model's answer, not Gatte's own output:"
  # The prompt comes first: --allowedTools takes every argument after it.
  # Only the analyst's own settings load, never a project's.
  (cd "$tmp" && claude -p "Call the $GATTE_TOOL tool once and repeat its result literally, adding nothing." --setting-sources user --allowedTools "$GATTE_TOOL") || {
    say "✘ claude -p failed."
    exit 5
  }
fi
exit 0
`))

var statusPS1 = template.Must(template.New("status-ps1").Parse(`# gatte-status: can this machine reach Gatte, the team's MCP gateway, and is
# Claude Code signed in to it? Installed by connect-gatte ({{.Date}}).
# Contains no secret, reads no token and keeps nothing.
#
#   gatte-status            check the network, Gatte and Claude Code
#   gatte-status -backends  also ask Claude Code to call gatte.status
#
# Exit: 0 Gatte answers and Claude Code connects (backends are checked
# only with -backends); 1 network (VPN, DNS, route); 2 TLS; 3 Gatte, or the
# proxy in front of it, is not serving; 4 Gatte is up but Claude Code is not
# signed in or not set up; 5 unexpected.
param([switch]$Backends)
$ErrorActionPreference = 'Stop'

$GatteUrl = '{{.URL}}'
$GatteMeta = '{{.MetaURL}}'
$GatteServer = '{{.Server}}'
# The name Claude Code gives the gatte.status tool: it shows "." as "_".
$GatteTool = 'mcp__{{.Server}}__gatte_status'

# One line, no control characters, at most 300 characters.
function Clean([string]$s) {
  $t = $s -replace '[\x00-\x1F\x7F]', ''
  if ($t.Length -gt 300) { $t = $t.Substring(0, 300) }
  return $t
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
{{if .CAPEM}}
# The gateway's certificate comes from the team's certificate authority.
# The host name is still checked, and the chain must end at that CA and at
# no other root: AllowUnknownCertificateAuthority alone would accept any.
$GatteCa = Join-Path $env:USERPROFILE '.gatte\ca.pem'
Add-Type -TypeDefinition @"
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class GatteTls {
  public static X509Certificate2Collection Team = new X509Certificate2Collection();
  public static RemoteCertificateValidationCallback Callback = new RemoteCertificateValidationCallback(Check);
  public static bool Check(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
    if (cert == null) return false;
    if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0) return false;
    if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
    X509Chain c = new X509Chain();
    c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
    c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
    c.ChainPolicy.ExtraStore.AddRange(Team);
    if (!c.Build(new X509Certificate2(cert))) return false;
    X509Certificate2 root = c.ChainElements[c.ChainElements.Count - 1].Certificate;
    foreach (X509Certificate2 t in Team) {
      if (string.Equals(t.Thumbprint, root.Thumbprint, StringComparison.OrdinalIgnoreCase)) return true;
    }
    return false;
  }
}
"@
foreach ($block in ([IO.File]::ReadAllText($GatteCa) -split '-----END CERTIFICATE-----')) {
  $b64 = ($block -replace '-----BEGIN CERTIFICATE-----', '') -replace '\s', ''
  if ($b64) { [void][GatteTls]::Team.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($b64)))) }
}
{{end}}
# Probe sends one request and returns its code, body and challenge, or the
# exception when no HTTP answer came.
function Probe([string]$Method, [string]$Uri) {
  $resp = $null
  try {
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = $Method
    $req.Timeout = 10000
    $req.AllowAutoRedirect = $false
{{- if .CAPEM}}
    $req.ServerCertificateValidationCallback = [GatteTls]::Callback
{{- end}}
    if ($Method -eq 'POST') {
      $req.ContentType = 'application/json'
      $req.Accept = 'application/json, text/event-stream'
      $bytes = [Text.Encoding]::UTF8.GetBytes('{"jsonrpc":"2.0","id":1,"method":"ping"}')
      $req.ContentLength = $bytes.Length
      $stream = $req.GetRequestStream()
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Close()
    }
    $resp = $req.GetResponse()
  } catch {
    $ex = $_.Exception
    while ($ex -and -not ($ex -is [System.Net.WebException])) { $ex = $ex.InnerException }
    if ($ex -and $ex.Response) { $resp = $ex.Response }
    elseif ($ex) { return @{ Error = $ex } }
    else { return @{ Error = $_.Exception } }
  }
  $body = ''
  try { $reader = New-Object IO.StreamReader($resp.GetResponseStream()); $body = $reader.ReadToEnd(); $reader.Close() } catch { }
  $out = @{ Code = [int]$resp.StatusCode; Body = $body; Challenge = [string]$resp.Headers['WWW-Authenticate'] }
  $resp.Close()
  return $out
}

# Explain maps a failed connection onto the exit codes.
function Explain($err) {
  $status = ''
  $sock = ''
  if ($err -is [System.Net.WebException]) { $status = [string]$err.Status }
  $e = $err
  while ($e) {
    if ($e -is [System.Net.Sockets.SocketException]) { $sock = [string]$e.SocketErrorCode; break }
    $e = $e.InnerException
  }
  if ($status -eq 'NameResolutionFailure' -or $sock -eq 'HostNotFound') {
    Write-Host "X The name of Gatte's host does not resolve. Are you on the VPN? Is DNS working?"; exit 1
  }
  if ($sock -eq 'ConnectionRefused') {
    Write-Host "X Gatte's host answers, but nothing is listening on Gatte's port: Gatte, or the proxy in front of it, is stopped."
    Write-Host "  This is not your network. Tell the Gatte operator."; exit 3
  }
  if ($status -eq 'Timeout' -or $sock -eq 'TimedOut' -or $sock -eq 'HostUnreachable' -or $sock -eq 'NetworkUnreachable') {
    Write-Host "X The network does not reach Gatte's host: VPN, firewall or route. Are you on the VPN?"; exit 1
  }
  if ($status -eq 'TrustFailure' -or $status -eq 'SecureChannelFailure') {
    Write-Host ("X The TLS connection to Gatte failed: " + (Clean $err.Message))
    Write-Host "  Run connect-gatte again to reinstall the team's certificate authority; if it persists, tell the Gatte operator."; exit 2
  }
  Write-Host ("X Unexpected error reaching Gatte: " + (Clean $err.Message)); exit 5
}

Write-Host "Gatte: $GatteUrl"

# 1. Does Gatte answer? Its protected-resource metadata is public.
$r = Probe 'GET' $GatteMeta
if ($r.Error) { Explain $r.Error }
if ($r.Code -eq 502 -or $r.Code -eq 503 -or $r.Code -eq 504) {
  Write-Host "X The proxy in front of Gatte answers, but Gatte does not (HTTP $($r.Code)): it is stopped or in maintenance."
  Write-Host ("  It says: " + (Clean $r.Body))
  Write-Host "  Retry later, or tell the Gatte operator."; exit 3
}
if ($r.Code -ne 200) {
  Write-Host "X Gatte's address answered HTTP $($r.Code) where Gatte answers 200: something in front of it is not Gatte. Tell the Gatte operator."; exit 5
}
Write-Host "OK Gatte answers."

# 2. Is the MCP endpoint Gatte's? Without a token it must ask for sign-in.
$r = Probe 'POST' $GatteUrl
if ($r.Error) { Write-Host ("X Gatte's MCP endpoint did not answer: " + (Clean $r.Error.Message)); exit 5 }
if ($r.Code -eq 502 -or $r.Code -eq 503 -or $r.Code -eq 504) {
  Write-Host "X The proxy in front of Gatte answers, but Gatte's MCP endpoint does not (HTTP $($r.Code)). Retry later, or tell the Gatte operator."; exit 3
}
if ($r.Code -ne 401 -or $r.Challenge -notmatch 'resource_metadata') {
  Write-Host "X The MCP endpoint answered HTTP $($r.Code) without Gatte's sign-in challenge: something in front of it is not Gatte. Tell the Gatte operator."; exit 5
}
Write-Host "OK Gatte's MCP endpoint asks for sign-in, as it should."

# 3. Is Claude Code signed in? claude mcp get exits 0 whatever the state,
# so only its Status: and Issue: lines are read. Claude Code always runs
# from the script's own empty directory: where the analyst stands may be a
# checkout whose project settings, hooks or .mcp.json would load with it.
# And never under 'Stop': Windows PowerShell 5.1 turns each line a native
# command writes to stderr into a terminating error there.
if (-not (Get-Command claude -ErrorAction SilentlyContinue)) {
  Write-Host "X Claude Code is not installed on this machine (no claude command). Install it, then run connect-gatte."; exit 4
}
$Work = Join-Path ([IO.Path]::GetTempPath()) ('gatte-status-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($Work)
function DropWork { try { [IO.Directory]::Delete($Work, $true) } catch { } }
Push-Location $Work
$ErrorActionPreference = 'Continue'
$get = (& claude mcp get $GatteServer 2>&1 | ForEach-Object { [string]$_ } | Out-String) -split "\r?\n"
$ErrorActionPreference = 'Stop'
Pop-Location
DropWork
$status = Clean ([string]($get | Where-Object { $_ -match 'Status:' } | Select-Object -First 1))
$issue = Clean (([string]($get | Where-Object { $_ -match 'Issue:' } | Select-Object -First 1)) -replace '^\s*Issue:\s*', '')
if ($status -match 'Needs authentication') {
  Write-Host "X Gatte is up, but Claude Code is not signed in to it."
  Write-Host "  Open claude, type /mcp, choose $GatteServer and authenticate."; exit 4
} elseif ($status -match 'Failed to connect') {
  if ($issue -match '^HTTP 5') {
    Write-Host "X Gatte answers but is not serving tools right now. Claude Code says:"
    Write-Host "  $issue"
    Write-Host "  Retry in a few minutes, or tell the Gatte operator."; exit 3
  }
  Write-Host "X Claude Code could not connect to Gatte, for a reason this check does not know:"
  Write-Host "  $issue"
  Write-Host "  Tell the Gatte operator."; exit 5
} elseif ($status -cmatch 'Connected') {
  Write-Host "OK Claude Code connects to Gatte as $($GatteServer): Gatte itself is fine."
  Write-Host "  If your open claude session shows $GatteServer as failed or disconnected, type /mcp there, choose $GatteServer and reconnect."
  if (-not $Backends) {
    Write-Host "  The backends behind Gatte were not checked. If a tool keeps failing, run gatte-status -backends"
    Write-Host "  (one model request), or ask Claude to call gatte.status."
  }
} else {
  Write-Host "X Claude Code has no server named $GatteServer. Run connect-gatte again."; exit 4
}

# 4. Optional: the backends, as gatte.status tells Claude Code. It costs a
# model request, and what prints is the model's answer, not Gatte's.
if ($Backends) {
  Write-Host ""
  Write-Host "Asking Claude Code to call gatte.status (one model request)."
  Write-Host "The model's answer, not Gatte's own output:"
  # The prompt comes first: --allowedTools takes every argument after it.
  # Only the analyst's own settings load, never a project's.
  [void][IO.Directory]::CreateDirectory($Work)
  Push-Location $Work
  $ErrorActionPreference = 'Continue'
  & claude -p "Call the $GatteTool tool once and repeat its result literally, adding nothing." --setting-sources user --allowedTools $GatteTool
  $rc = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  Pop-Location
  DropWork
  if ($rc -ne 0) { Write-Host "X claude -p failed."; exit 5 }
}
exit 0
`))

// RenderStatusScript renders gatte-status for one system and names its
// file: gatte-status (sh) or gatte-status.ps1.
func RenderStatusScript(c ConnectInfo, system string) (string, string, error) {
	var b bytes.Buffer
	switch system {
	case adminapi.OSMacOS, adminapi.OSLinux:
		if err := statusSh.Execute(&b, c); err != nil {
			return "", "", err
		}
		return b.String(), "gatte-status", nil
	case adminapi.OSWindows:
		if err := statusPS1.Execute(&b, c); err != nil {
			return "", "", err
		}
		return strings.ReplaceAll(b.String(), "\n", "\r\n"), "gatte-status.ps1", nil
	}
	return "", "", fmt.Errorf("unknown system %q", system)
}
