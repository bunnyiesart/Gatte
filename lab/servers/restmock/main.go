// Command restmock is the lab's fake REST API (lab/README.md): the backend
// an `upstream register -transport http` entry points at, shaped so that
// the four claims ADR-0047/ADR-0048 make about an http upstream can be
// proven end to end by the REST probe (internal/gateway/resthttp,
// TestLabProbeREST, `make lab-probe-rest`) without a real API or a real
// key.
//
// Unlike the four stdio mocks it is not an MCP server at all. It is a plain
// HTTP server, stdlib only, that:
//
//   - serves its own OpenAPI 3.0 document at GET /openapi.json, with no
//     key, the way a public API does -- the probe fetches it through the
//     adapter's guarded client and ingests it, so the tools the gateway
//     serves come from this document and nowhere else;
//   - demands the credential on every operation, in the X-API-Key header,
//     and answers 401 without it. The value it demands is MOCK_SECRET from
//     its environment and the credcheck baseline is MOCK_EXPECT, the same
//     two variables every lab mock reads (lab/mockutil), so the probe
//     spawns it exactly as it spawns the others;
//   - reports, in the JSON of GET /check/{ip} and on its own stdout, whether
//     the key it received is the expected one plus a fingerprint -- the
//     <name>_credcheck discipline, never the value (mockutil.Check);
//   - reflects the credential back on GET /echo, in a Location header, a
//     Set-Cookie header and the JSON body at once. A real API does this by
//     accident (a 401 page quoting the key, a redirect that re-encodes the
//     query, a session cookie minted from the key) and ADR-0048 Decisão 7
//     says the gateway masks every one of those; this handler is how the
//     claim is checked rather than asserted.
//
// The document's servers[0].url names a host that does not exist and a base
// path (/api/v1) under which the operations are actually served. That is on
// purpose: ADR-0047 §6 says the registered -url is the authority and only
// the base path of servers[] is folded in, and a mock whose document agreed
// with its address could not tell whether that fold happens.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/bunnyiesart/Gatte/lab/mockutil"
)

// basePath is where the operations live, and what the document's
// servers[0].url ends in. The two are the same constant so that the fold
// the probe asserts on is the fold the server needs.
const basePath = "/api/v1"

// keyHeader is the header the API demands its credential in and the name
// the document's apiKey security scheme declares, so the ingestion can
// derive the auth descriptor (header X-API-Key) from the document alone.
const keyHeader = "X-API-Key"

// specJSON is the OpenAPI 3.0.3 document GET /openapi.json serves. Three
// operations: one safe GET with a parameter in each of path, query and
// header; one sensitive POST with a oneOf body resolved through $ref; and
// the reflecting GET. One apiKey scheme, in the header above, applied
// document-wide. The responses declare no content, so no OutputSchema is
// derived and nothing is validated against one (ADR-0014) -- the probe is
// about the credential, not the response contract.
const specJSON = `{
  "openapi": "3.0.3",
  "info": {"title": "restmock", "version": "lab", "description": "The lab's fake REST API (synthetic data, no real backend)."},
  "servers": [{"url": "http://restmock.invalid` + basePath + `"}],
  "security": [{"apiKey": []}],
  "components": {
    "securitySchemes": {
      "apiKey": {"type": "apiKey", "in": "header", "name": "` + keyHeader + `"}
    },
    "schemas": {
      "IPReport": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "ip"],
        "properties": {
          "kind": {"type": "string", "enum": ["ip"]},
          "ip": {"type": "string"}
        }
      },
      "DomainReport": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "domain"],
        "properties": {
          "kind": {"type": "string", "enum": ["domain"]},
          "domain": {"type": "string"}
        }
      }
    }
  },
  "paths": {
    "/check/{ip}": {
      "parameters": [
        {"name": "ip", "in": "path", "required": true, "schema": {"type": "string"}, "description": "The address to look up"}
      ],
      "get": {
        "operationId": "check_ip",
        "summary": "Looks up fake reputation data for an IP address (synthetic, not a real backend).",
        "parameters": [
          {"name": "verbose", "in": "query", "schema": {"type": "boolean"}, "description": "Include the fake per-source detail"},
          {"name": "X-Request-Id", "in": "header", "schema": {"type": "string"}, "description": "Echoed back as request_id"}
        ],
        "responses": {"200": {"description": "The fake reputation, plus the credcheck of the key this request carried."}}
      }
    },
    "/report": {
      "post": {
        "operationId": "report",
        "summary": "Files a fake abuse report for an IP or a domain (synthetic; nothing is stored).",
        "requestBody": {
          "required": true,
          "content": {"application/json": {"schema": {"oneOf": [
            {"$ref": "#/components/schemas/IPReport"},
            {"$ref": "#/components/schemas/DomainReport"}
          ]}}}
        },
        "responses": {"201": {"description": "Accepted."}}
      }
    },
    "/echo": {
      "get": {
        "operationId": "echo",
        "summary": "Reflects the credential it received in a Location header, a Set-Cookie header and the body (the credential-reflection scenario).",
        "responses": {"302": {"description": "A redirect to itself, carrying the key three ways."}}
      }
    }
  }
}`

// requestEvent is one line of the mock's stdout: what arrived and whether
// it carried the expected key. The credcheck fields come from
// mockutil.Check, so the value itself is not representable here. Path is
// r.URL.Path only -- never the query, which on a followed /echo redirect
// carries the reflected key.
type requestEvent struct {
	Event  string `json:"event"`
	Method string `json:"method"`
	Path   string `json:"path"`
	mockutil.CredCheckResult
	Authorized bool `json:"authorized"`
}

// listeningEvent is the first line of stdout: where the server is. The
// probe reads it to learn the port the kernel chose.
type listeningEvent struct {
	Event string `json:"event"`
	URL   string `json:"url"`
}

// eventLog serialises stdout lines from concurrent handlers.
type eventLog struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newEventLog(w io.Writer) *eventLog {
	return &eventLog{enc: json.NewEncoder(w)}
}

func (l *eventLog) emit(v any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.enc.Encode(v); err != nil {
		// stdout is the probe's pipe; losing it means the probe is gone and
		// there is nobody left to report to.
		log.Printf("restmock: write event: %v", err)
	}
}

// api is the mock's state: the key it demands and the log it writes to.
// There is no other state; nothing a request sends is kept.
type api struct {
	secret string
	events *eventLog
}

// newHandler builds the mock's routes. GET /openapi.json is public; every
// path under basePath goes through requireKey first.
func newHandler(secret string, events *eventLog) http.Handler {
	a := &api{secret: secret, events: events}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /openapi.json", a.openAPI)
	mux.HandleFunc("GET "+basePath+"/check/{ip}", a.requireKey(a.check))
	mux.HandleFunc("POST "+basePath+"/report", a.requireKey(a.report))
	mux.HandleFunc("GET "+basePath+"/echo", a.requireKey(a.echo))
	return mux
}

// requireKey is the API's one access control: X-API-Key must equal the
// secret. Every request is logged with its credcheck before it is judged,
// so the probe can see a refused request as well as a served one -- and so
// a POST the gateway was supposed to refuse shows up by its absence.
func (a *api) requireKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		received := r.Header.Get(keyHeader)
		authorized := received != "" && received == a.secret
		a.events.emit(requestEvent{
			Event:           "request",
			Method:          r.Method,
			Path:            r.URL.Path,
			CredCheckResult: mockutil.Check(received),
			Authorized:      authorized,
		})
		if !authorized {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "missing or wrong " + keyHeader,
			})
			return
		}
		next(w, r)
	}
}

func (a *api) openAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, specJSON)
}

// check is GET /check/{ip}: canned reputation (the threatintel mock's rule,
// so the two mocks agree about an address), the two optional parameters
// echoed so the probe can see they arrived in the right place, and the
// credcheck of this request's key -- the REST counterpart of the stdio
// mocks' <name>_credcheck tool.
func (a *api) check(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	verbose := r.URL.Query().Get("verbose") == "true"
	body := map[string]any{
		"ip":                 ip,
		"reputation_score":   reputationFor(ip),
		"is_known_malicious": reputationFor(ip) > 90,
		"verbose":            verbose,
		"request_id":         r.Header.Get("X-Request-Id"),
		"credcheck":          mockutil.Check(r.Header.Get(keyHeader)),
	}
	if verbose {
		body["sources"] = map[string]any{
			"virustotal": map[string]int{"malicious_count": 3, "total_engines": 72},
			"abuseipdb":  map[string]int{"abuse_confidence_score": 17},
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// reputationFor is the threatintel mock's fake rule: ".1" looks clean,
// "666" looks malicious, everything else is middling.
func reputationFor(ip string) int {
	switch {
	case strings.HasSuffix(ip, ".1"):
		return 5
	case strings.Contains(ip, "666"):
		return 97
	default:
		return 42
	}
}

// report is POST /report: the sensitive operation. It accepts either
// branch of the document's oneOf and stores nothing. Its purpose in the
// probe is to be refused -- for a read role, and for an acting role until
// the tool is cleared -- so what matters is that a served call is
// unmistakable (201, "accepted": true) and a refused one leaves no request
// line on stdout.
func (a *api) report(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind   string `json:"kind"`
		IP     string `json:"ip"`
		Domain string `json:"domain"`
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || json.Unmarshal(data, &in) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "body must be a JSON object"})
		return
	}
	var subject string
	switch in.Kind {
	case "ip":
		subject = in.IP
	case "domain":
		subject = in.Domain
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "kind must be \"ip\" or \"domain\""})
		return
	}
	if subject == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the " + in.Kind + " is required"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"accepted": true, "kind": in.Kind, "subject": subject})
}

// echo is GET /echo: the credential-reflection scenario, all three forms in
// one response. It answers 302 to ITSELF with the key in the Location's
// query, a Set-Cookie minted from the key, and a JSON body quoting it. The
// adapter's client follows a same-origin redirect only up to its limit and
// then hands the last 3xx back as the response (resthttp.checkRedirect), so
// the envelope the gateway builds carries all three headers and the body --
// and the probe checks that every one of them comes back masked.
func (a *api) echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", basePath+"/echo?k="+a.secret)
	w.Header().Set("Set-Cookie", "session="+a.secret+"; Path=/; HttpOnly")
	writeJSON(w, http.StatusFound, map[string]any{
		"echo": a.secret,
		"note": "this body, the Location and the Set-Cookie all quote the key the request carried",
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("restmock: write response: %v", err)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "address to listen on; port 0 lets the kernel choose and the first stdout line says which")
	flag.Parse()

	// A mock that accepts any key proves nothing, so an empty MOCK_SECRET is
	// a misconfiguration, not a mode.
	secret := os.Getenv("MOCK_SECRET")
	if secret == "" {
		log.Fatal("restmock: MOCK_SECRET is empty; set it to the key the API should demand (and MOCK_EXPECT to the same value for the credcheck)")
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("restmock: listen %s: %v", *listen, err)
	}
	events := newEventLog(os.Stdout)
	events.emit(listeningEvent{Event: "listening", URL: "http://" + ln.Addr().String()})

	srv := &http.Server{Handler: newHandler(secret, events)}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "restmock: serve: %v\n", err)
		os.Exit(1)
	}
}
