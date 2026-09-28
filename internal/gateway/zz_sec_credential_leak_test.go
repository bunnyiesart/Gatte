package gateway

// Credential-leak lens, ported from the internal tree's security pass of
// 24 Sep 2026: redact, scrubResult and stdio's scrubDialError used to
// replace resolved values one at a time and only as their raw bytes. Two
// ways that slipped -- a short value inside a longer one, and a value
// rendered escaped (%q, %+q, JSON) -- are pinned here for every path that
// masks, now that all three share maskCredentials.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestSecSecretWithJSONNewlineUnicodeIsRedactedVerbatim: a value full of
// characters that tend to break naive handling -- quotes, backslashes,
// newlines, JSON, non-ASCII -- is still removed when it appears verbatim.
func TestSecSecretWithJSONNewlineUnicodeIsRedactedVerbatim(t *testing.T) {
	secret := "{\"k\":\"v\\\\\"}\nline2\tçãø-€-\U0001F511-END"
	h := newHarness(t)
	h.register("leaky", "WEIRD")
	h.vault.values["WEIRD"] = secret
	h.dialer.dialErr["leaky"] = fmt.Errorf("spawn failed; env WEIRD=%s", secret)

	err := h.connect()
	if err == nil {
		t.Fatal("Connect: want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("LEAK: verbatim value survived redaction: %q", err)
	}
}

// TestSecRedactCoversEscapedForms: an adapter error that rendered the
// value the way Go and JSON routinely render strings -- %q, %+q, or a
// json.Marshal'd payload quoted into an error -- kept the credential fully
// recoverable (strconv.Unquote / json.Unmarshal) in the Connect error and
// the ERROR log.
func TestSecRedactCoversEscapedForms(t *testing.T) {
	secret := "sec-esc\n\"pw\"<&>-TAIL-51f0-ç"
	quoted := strconv.Quote(secret)
	ascii := strconv.QuoteToASCII(secret)
	jsonEnc, _ := json.Marshal(map[string]string{"TOKEN": secret})

	var leaks []string
	for name, dialErr := range map[string]error{
		"%q":   fmt.Errorf("spawn failed with env TOKEN=%q", secret),
		"%+q":  fmt.Errorf("spawn failed with env TOKEN=%+q", secret),
		"json": fmt.Errorf("upstream rejected handshake: %s", jsonEnc),
	} {
		h := newHarness(t)
		h.register("leaky", "TOKEN")
		h.vault.values["TOKEN"] = secret
		h.dialer.dialErr["leaky"] = dialErr
		err := h.connect()
		if err == nil {
			t.Fatal("Connect: want an error")
		}
		msg := err.Error()
		escapedJSON := strings.Trim(string(mustJSON(secret)), `"`)
		for _, form := range []string{quoted[1 : len(quoted)-1], ascii[1 : len(ascii)-1], escapedJSON} {
			if strings.Contains(msg, form) {
				leaks = append(leaks, fmt.Sprintf("%s form -> %s", name, msg))
				break
			}
		}
	}
	if len(leaks) > 0 {
		t.Fatalf("LEAK: escaped credential survived redaction:\n%s", strings.Join(leaks, "\n"))
	}
}

func mustJSON(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}

// TestSecRedactOverlappingValuesLeaksNoTail: redact used to walk the env
// map in Go's randomised order, so when one resolved value was a substring
// of another, replacing the short one first split the long one and printed
// its remainder in clear. The loop gives the map order enough draws.
func TestSecRedactOverlappingValuesLeaksNoTail(t *testing.T) {
	const short = "sec-ovl-shared"
	const long = short + "-LONG-TAIL-e3b0c442"
	const tail = "-LONG-TAIL-e3b0c442"

	for i := 0; i < 200; i++ {
		h := newHarness(t)
		h.register("leaky", "A_SHORT", "B_LONG")
		h.vault.values["A_SHORT"] = short
		h.vault.values["B_LONG"] = long
		h.dialer.dialErr["leaky"] = fmt.Errorf("auth failed with token %s", long)
		err := h.connect()
		if err == nil {
			t.Fatal("Connect: want an error")
		}
		if strings.Contains(err.Error(), tail) {
			t.Fatalf("LEAK on iteration %d: %s", i, err)
		}
	}
}

// TestSecScrubResultOverlappingValuesLeaksNoTail is the same overlap
// defect on the tool-result path (Dispatch step 7): scrubJSON replaced
// value by value in map order, so a short credential inside a longer one
// could split it and forward the tail to the client.
func TestSecScrubResultOverlappingValuesLeaksNoTail(t *testing.T) {
	const short = "sec-res-shared"
	const long = short + "-RESULT-TAIL-9f2a"
	const tail = "-RESULT-TAIL-9f2a"

	h := newHarness(t, "threatintel.lookup_ip")
	h.register("threatintel", "A_SHORT", "B_LONG")
	h.vault.values["A_SHORT"] = short
	h.vault.values["B_LONG"] = long
	h.serve("threatintel", def("lookup_ip", "look up an ip"))
	h.mustConnect()
	h.approve("threatintel", "lookup_ip")
	h.respond("threatintel", Result{
		Content: json.RawMessage(`[{"type":"text","text":"401: key ` + long + ` rejected"}]`),
		IsError: true,
	})
	for i := 0; i < 200; i++ {
		res, err := h.gw.Dispatch(context.Background(), fromAnalyst, "threatintel.lookup_ip", json.RawMessage(`{}`))
		if err != nil {
			t.Fatalf("Dispatch: %v", err)
		}
		if strings.Contains(string(res.Content), tail) {
			t.Fatalf("LEAK on iteration %d: %s", i, res.Content)
		}
	}
}

// TestSecScrubJSONCoversQuotedRenderings: a backend that formats its
// error with %q (or embeds a JSON payload) puts the value inside the
// result text escaped once by that rendering and again by the JSON
// encoder. json.Unmarshal of the result followed by strconv.Unquote gave
// the credential straight back.
func TestSecScrubJSONCoversQuotedRenderings(t *testing.T) {
	secret := "sec-res-esc\n\"pw\"<&>-TAIL-77c1"
	for name, text := range map[string]string{
		"%q":   fmt.Sprintf("401: key %q rejected", secret),
		"%+q":  fmt.Sprintf("401: key %+q rejected", secret),
		"json": fmt.Sprintf("401: body %s", mustJSON(secret)),
	} {
		raw, _ := json.Marshal(map[string]string{"text": text})
		var hit []string
		out, err := scrubJSON(raw, map[string]string{"K": secret}, &hit)
		if err != nil {
			t.Fatalf("%s: scrubJSON: %v", name, err)
		}
		var back map[string]string
		if err := json.Unmarshal(out, &back); err != nil {
			t.Fatalf("%s: scrubbed output is not JSON: %s", name, out)
		}
		q, a := strconv.Quote(secret), strconv.QuoteToASCII(secret)
		for _, form := range []string{secret, q[1 : len(q)-1], a[1 : len(a)-1], strings.Trim(string(mustJSON(secret)), `"`)} {
			if strings.Contains(back["text"], form) {
				t.Errorf("LEAK (%s): a rendering of the credential survived: %q", name, back["text"])
				break
			}
		}
		if len(hit) != 1 {
			t.Errorf("%s: hit = %v, want [K]", name, hit)
		}
	}
}
