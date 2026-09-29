package registry

import (
	"errors"
	"testing"
)

// TestValidate_RefusesTheReservedNameGatte: the namespace gatte belongs to
// the gateway's built-in gatte.status (design/adr/0041 item 5), so no
// registered upstream may take it, in any case.
func TestValidate_RefusesTheReservedNameGatte(t *testing.T) {
	for _, name := range []string{"gatte", "Gatte", "GATTE", "gAtTe"} {
		s := UpstreamServer{Name: name, Transport: TransportStdio, Command: "/usr/local/bin/x"}
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("Validate(%q) = %v, want ErrInvalid: the name is reserved", name, err)
		}
	}
	for _, name := range []string{"gatte2", "gatte-lab", "mygatte"} {
		s := UpstreamServer{Name: name, Transport: TransportStdio, Command: "/usr/local/bin/x"}
		if err := s.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil: only the exact name is reserved", name, err)
		}
	}
}
