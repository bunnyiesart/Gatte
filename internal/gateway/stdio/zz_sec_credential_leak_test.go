package stdio

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// TestSecScrubDialErrorOverlapAndEscapedForms: scrubDialError replaced
// value by value in map order and only as raw bytes, so a short value
// inside a longer one split the long one and left its tail in clear, and a
// value the child's handshake error rendered with %q or JSON escaping was
// not recognised at all. It now shares gateway.MaskCredentials with the
// gateway's own redact.
func TestSecScrubDialErrorOverlapAndEscapedForms(t *testing.T) {
	const short = "sec-dial-shared"
	const long = short + "-DIAL-TAIL-40c9"
	for i := 0; i < 200; i++ {
		env := map[string]string{"A_SHORT": short, "B_LONG": long}
		got := scrubDialError(fmt.Errorf("handshake: bad key %s", long), env).Error()
		if strings.Contains(got, "-DIAL-TAIL-40c9") {
			t.Fatalf("LEAK on iteration %d: %s", i, got)
		}
	}

	secret := "sec-dial-esc\n\"pw\"<&>-ç-TAIL"
	q, a := strconv.Quote(secret), strconv.QuoteToASCII(secret)
	j := `"sec-dial-esc\n\"pw\"\u003c\u0026\u003e-ç-TAIL"`
	for _, rendered := range []string{q, a, j} {
		err := scrubDialError(errors.New("initialize: "+rendered), map[string]string{"K": secret})
		if msg := err.Error(); strings.Contains(msg, rendered[1:len(rendered)-1]) || !strings.Contains(msg, "[redacted]") {
			t.Errorf("LEAK: escaped rendering survived: %s", msg)
		}
	}
}
