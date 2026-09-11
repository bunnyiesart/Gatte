// Package main -- jailmap parsers.
//
// STRICTLY READ-ONLY. Everything in this file is a pure function over text
// that some enumeration command already printed. Nothing here executes
// anything, and nothing anywhere in jailmap changes the state of the host
// or of any jail -- see the contract at the top of main.go.
package main

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

// JailRecord is one row of `jls -h jid name path host.hostname ip4.addr vnet`.
type JailRecord struct {
	JID      int
	Name     string
	Path     string
	Hostname string
	IP4      []string
	VNET     bool
	// VNETKnown is false when the kernel has no `vnet` jail parameter (no
	// VIMAGE), in which case every jail is classic and saying so is honest
	// rather than a guess.
	VNETKnown bool
}

// parseJLS parses the header-driven output of `jls -h ...`.
//
// It reads the header rather than assuming column order, because the caller
// may have asked for fewer parameters (the vnet fallback path does exactly
// that on a kernel without VIMAGE). A row whose field count does not match
// the header is skipped and reported, not guessed at.
func parseJLS(out string) ([]JailRecord, []string) {
	var (
		recs  []JailRecord
		warns []string
	)
	lines := nonEmptyLines(out)
	if len(lines) == 0 {
		return nil, nil
	}
	header := strings.Fields(lines[0])
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	if _, ok := idx["jid"]; !ok {
		return nil, []string{"jls: output has no jid column; cannot read the jail list"}
	}
	_, vnetAsked := idx["vnet"]

	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) != len(header) {
			warns = append(warns, fmt.Sprintf("jls: skipped unparseable row %q", strings.TrimSpace(line)))
			continue
		}
		get := func(k string) string {
			i, ok := idx[k]
			if !ok {
				return ""
			}
			return f[i]
		}
		jid, err := strconv.Atoi(get("jid"))
		if err != nil {
			warns = append(warns, fmt.Sprintf("jls: skipped row with non-numeric jid %q", get("jid")))
			continue
		}
		rec := JailRecord{
			JID:       jid,
			Name:      get("name"),
			Path:      get("path"),
			Hostname:  get("host.hostname"),
			IP4:       splitAddrList(get("ip4.addr")),
			VNETKnown: vnetAsked,
		}
		// jls prints the vnet parameter as inherit / new / disable.
		// "new" is the only value that means an independent network stack.
		rec.VNET = vnetAsked && get("vnet") == "new"
		if rec.Name == "" {
			rec.Name = strconv.Itoa(jid)
		}
		recs = append(recs, rec)
	}
	return recs, warns
}

// splitAddrList turns jls's ip4.addr field into addresses. The field is
// comma-separated, "-" when the jail has none (a VNET jail always does),
// and each entry may carry an interface prefix or a prefix length.
func splitAddrList(s string) []string {
	if s == "" || s == "-" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "-" {
			continue
		}
		// "lo0|127.0.1.10" -> "127.0.1.10"
		if i := strings.LastIndex(part, "|"); i >= 0 {
			part = part[i+1:]
		}
		// "10.17.89.20/32" -> "10.17.89.20"
		if i := strings.Index(part, "/"); i >= 0 {
			part = part[:i]
		}
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// Endpoint is one side of a socket as sockstat printed it. Addr is "*" for
// a wildcard bind and Port is "*" for the foreign side of a listener.
type Endpoint struct {
	Addr string
	Port string
}

func (e Endpoint) String() string {
	if e.Addr == "" && e.Port == "" {
		return ""
	}
	return e.Addr + ":" + e.Port
}

// Socket is one row of sockstat -4l / -4c output.
type Socket struct {
	User    string
	Command string
	PID     string // "??" when sockstat could not attribute the socket
	FD      string
	Proto   string // tcp4, udp4
	Local   Endpoint
	Foreign Endpoint
}

// Attributed reports whether sockstat could name the process. TIME_WAIT and
// other detached sockets come through as "??" in every process column; they
// are still real observations of a connection and are kept, just unnamed.
func (s Socket) Attributed() bool { return s.PID != "" && s.PID != "??" }

// parseSockstat parses `sockstat -4l -j N` and `sockstat -4c -j N`.
//
// Columns are read from the right (PROTO, LOCAL, FOREIGN are always the last
// three) so a command name containing spaces cannot shift the fields that
// matter. Rows that are too short are reported rather than half-parsed.
func parseSockstat(out string) ([]Socket, []string) {
	var (
		socks []Socket
		warns []string
	)
	for _, line := range nonEmptyLines(out) {
		f := strings.Fields(line)
		if len(f) < 7 {
			// The header, and anything unexpected.
			if len(f) > 0 && f[0] != "USER" {
				warns = append(warns, fmt.Sprintf("sockstat: skipped short row %q", strings.TrimSpace(line)))
			}
			continue
		}
		if f[0] == "USER" {
			continue
		}
		n := len(f)
		s := Socket{
			User:    f[0],
			Command: strings.Join(f[1:n-5], " "),
			PID:     f[n-5],
			FD:      f[n-4],
			Proto:   f[n-3],
			Local:   splitEndpoint(f[n-2]),
			Foreign: splitEndpoint(f[n-1]),
		}
		socks = append(socks, s)
	}
	return socks, warns
}

// splitEndpoint splits "10.17.90.10:443", "*:1194" and "*:*" on the last
// colon, which is also correct for the bracketed IPv6 form sockstat prints.
func splitEndpoint(s string) Endpoint {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return Endpoint{Addr: s}
	}
	addr := strings.TrimSuffix(strings.TrimPrefix(s[:i], "["), "]")
	return Endpoint{Addr: addr, Port: s[i+1:]}
}

// IfAddr is one inet address found in ifconfig output.
type IfAddr struct {
	Iface    string
	Addr     string
	Loopback bool // the interface carries the LOOPBACK flag
}

// parseIfconfig extracts IPv4 addresses and remembers whether the interface
// they sit on is a loopback clone.
//
// The loopback flag matters here and is not cosmetic: bastille0 is a
// loopback clone carrying classic-jail addresses as /32 aliases, so
// "is on a loopback interface" is emphatically not the same question as
// "is unreachable from elsewhere".
func parseIfconfig(out string) []IfAddr {
	var (
		addrs    []IfAddr
		iface    string
		loopback bool
	)
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			// "vtnet0: flags=1008843<UP,BROADCAST,...> metric 0 mtu 1500"
			name, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			iface = strings.TrimSpace(name)
			loopback = strings.Contains(rest, "LOOPBACK")
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "inet" {
			continue
		}
		addr := f[1]
		if i := strings.Index(addr, "/"); i >= 0 {
			addr = addr[:i]
		}
		addrs = append(addrs, IfAddr{Iface: iface, Addr: addr, Loopback: loopback})
	}
	return addrs
}

// ProcRow is one row of `ps -axo pid,ppid,jid,user,etime,command`.
//
// This exists because the most interesting thing on this host has no socket
// at all. The gateway's MCP upstreams are stdio subprocesses: it spawns them
// and speaks to them over pipes, so sockstat cannot see them and the
// connection graph is empty while four of them are busy serving. A process
// is the only evidence there is.
type ProcRow struct {
	PID     int
	PPID    int
	JID     int
	User    string
	Etime   string // exactly as ps printed it
	Elapsed time.Duration
	// ElapsedKnown is false when ps printed an etime this parser does not
	// recognise. The row is still kept; only the age is missing.
	ElapsedKnown bool
	Command      string
}

// psFormat is the -o list jailmap asks for, and the only one it asks for.
const psFormat = "pid,ppid,jid,user,etime,command"

// parsePS parses `ps -axo pid,ppid,jid,user,etime,command`.
//
// Header-driven, like parseJLS, so the column order is read rather than
// assumed. COMMAND must be last: it is the one column that contains spaces,
// and everything before it is a single token, so the command is "the rest of
// the line from the COMMAND column onwards". A header without it is refused
// rather than half-parsed, because guessing where a command starts is how a
// process list turns into fiction.
func parsePS(out string) ([]ProcRow, []string) {
	var (
		rows  []ProcRow
		warns []string
	)
	lines := nonEmptyLines(out)
	if len(lines) == 0 {
		return nil, nil
	}
	header := strings.Fields(lines[0])
	idx := map[string]int{}
	for i, h := range header {
		idx[h] = i
	}
	cmdAt, ok := idx["COMMAND"]
	if !ok || cmdAt != len(header)-1 {
		return nil, []string{"ps: output has no trailing COMMAND column; cannot read the process list"}
	}
	// ps prints etime under the heading ELAPSED.
	for _, want := range []string{"PID", "PPID", "JID"} {
		if _, ok := idx[want]; !ok {
			return nil, []string{"ps: output has no " + want + " column; cannot read the process tree"}
		}
	}

	for _, line := range lines[1:] {
		f := strings.Fields(line)
		if len(f) <= cmdAt {
			warns = append(warns, fmt.Sprintf("ps: skipped short row %q", strings.TrimSpace(line)))
			continue
		}
		num := func(k string) (int, bool) {
			i, ok := idx[k]
			if !ok {
				return 0, false
			}
			n, err := strconv.Atoi(f[i])
			return n, err == nil
		}
		str := func(k string) string {
			i, ok := idx[k]
			if !ok {
				return ""
			}
			return f[i]
		}
		pid, okPID := num("PID")
		ppid, _ := num("PPID")
		jid, okJID := num("JID")
		if !okPID || !okJID {
			warns = append(warns, fmt.Sprintf("ps: skipped row with non-numeric pid/jid %q", strings.TrimSpace(line)))
			continue
		}
		r := ProcRow{
			PID:     pid,
			PPID:    ppid,
			JID:     jid,
			User:    str("USER"),
			Etime:   str("ELAPSED"),
			Command: strings.Join(f[cmdAt:], " "),
		}
		r.Elapsed, r.ElapsedKnown = parseEtime(r.Etime)
		rows = append(rows, r)
	}
	return rows, warns
}

// parseEtime reads ps's elapsed-time column: [[dd-]hh:]mm:ss.
func parseEtime(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	days := 0
	if i := strings.Index(s, "-"); i >= 0 {
		d, err := strconv.Atoi(s[:i])
		if err != nil || d < 0 {
			return 0, false
		}
		days = d
		s = s[i+1:]
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	var hours int
	if len(parts) == 3 {
		h, err := strconv.Atoi(parts[0])
		if err != nil || h < 0 {
			return 0, false
		}
		hours = h
		parts = parts[1:]
	}
	mins, err := strconv.Atoi(parts[0])
	if err != nil || mins < 0 {
		return 0, false
	}
	secs, err := strconv.Atoi(parts[1])
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(days)*24*time.Hour +
		time.Duration(hours)*time.Hour +
		time.Duration(mins)*time.Minute +
		time.Duration(secs)*time.Second, true
}

// procName is the executable name of a process, from ps's COMMAND column.
//
// ps prints argv, so the first token is the path the process was executed
// with. Kernel threads print as "[kernel]" and a few daemons rewrite argv
// into a label ending in a colon ("daemon: /usr/local/bin/mcp-gateway[63090]
// (daemon)"), and neither is a path -- which is exactly why matching the
// first token's basename does not confuse daemon(8) with the program it is
// supervising.
func procName(command string) string {
	tok, _, _ := strings.Cut(strings.TrimSpace(command), " ")
	if tok == "" {
		return ""
	}
	if strings.HasSuffix(tok, ":") || strings.HasPrefix(tok, "[") {
		return tok
	}
	return path.Base(tok)
}

// PFStatus is what `pfctl -s info` and `pfctl -s rules` say about the host
// packet filter.
//
// Deliberately shallow. jailmap does not evaluate a pf ruleset and must not
// pretend to: it reads whether pf is running and whether the ruleset opens
// by blocking all inbound traffic, and says "unknown" for everything else.
type PFStatus struct {
	// StatusKnown is false when pfctl could not be read at all.
	StatusKnown bool
	Enabled     bool
	// RulesKnown is false when `pfctl -s rules` failed; it distinguishes
	// "an empty ruleset" from "we could not look", which are opposite
	// answers to the only question being asked.
	RulesKnown bool
	Rules      int
	// DefaultDenyIn is true when the ruleset contains an unqualified
	// "block ... in ... all": any inbound packet not matched by a later pass
	// rule is dropped.
	DefaultDenyIn bool
	DenyRule      string
}

// parsePFInfo reads the Status line of `pfctl -s info`.
func parsePFInfo(out string) (enabled bool, ok bool) {
	for _, line := range nonEmptyLines(out) {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "Status:" {
			continue
		}
		switch f[1] {
		case "Enabled":
			return true, true
		case "Disabled":
			return false, true
		}
		return false, false
	}
	return false, false
}

// pfDenyDecorations are the words that may appear in a default-deny rule
// without changing what it does to unmatched inbound traffic. Anything else
// -- an interface, a protocol, an address -- makes the rule conditional, and
// a conditional rule is not a default policy.
var pfDenyDecorations = map[string]bool{
	"drop":   true,
	"return": true,
	"log":    true,
	"quick":  true,
}

// parsePFRules counts the loaded rules and looks for a default-deny inbound
// policy.
//
// The test is narrow on purpose: an unqualified `block ... in ... all`. pf is
// last-match-wins, so that rule is the fallback for every inbound packet no
// later pass rule claims, which is precisely the idiom this is looking for.
// Anything more elaborate is reported as "not recognised" rather than
// interpreted, because a real reachability analysis of a pf ruleset is not
// something a map of listening sockets should be attempting.
func parsePFRules(out string) (rules int, denyIn bool, denyRule string) {
	for _, line := range nonEmptyLines(out) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		rules++
		if denyIn {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "block" || f[len(f)-1] != "all" {
			continue
		}
		sawIn := false
		plain := true
		for _, w := range f[1 : len(f)-1] {
			switch {
			case w == "in":
				sawIn = true
			case pfDenyDecorations[w]:
			default:
				plain = false
			}
		}
		if sawIn && plain {
			denyIn = true
			denyRule = line
		}
	}
	return rules, denyIn, denyRule
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
