package access

import (
	"errors"
	"testing"
)

// TestValidateSubject_RefusesWhatAnOperatorCouldNotHaveMeant: a subject an
// operator pastes is refused, not stored, when it carries something that
// makes the block silently miss -- padding, a control character, or an
// invisible format character (U+200B and friends, Unicode category Cf) that
// a copy from a chat window or a PDF brings along and the terminal does not
// show (design/adr/0031 §4).
func TestValidateSubject_RefusesWhatAnOperatorCouldNotHaveMeant(t *testing.T) {
	for _, sub := range []string{
		"", " sub-analyst-1", "sub-analyst-1\n", "sub\x1banalyst",
		"sub-analyst-1\u200b", "\xef\xbb\xbfsub-analyst-1", "sub-\u202eanalyst",
		string(make([]byte, maxBlockText+1)),
	} {
		if err := ValidateSubject(sub); !errors.Is(err, ErrInvalidBlock) {
			t.Errorf("ValidateSubject(%q) = %v, want ErrInvalidBlock", sub, err)
		}
	}
	for _, sub := range []string{"sub-analyst-1", "7c9e6679-7425-40de-944b-e07fc1f90ae7", "ana@example.org", "análise"} {
		if err := ValidateSubject(sub); err != nil {
			t.Errorf("ValidateSubject(%q) = %v, want nil", sub, err)
		}
	}
}
