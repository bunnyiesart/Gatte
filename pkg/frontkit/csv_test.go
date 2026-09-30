package frontkit

import "testing"

// TestCSVCell_GuardsFormulasAndMakesHiddenTextVisible is design/adr/0046
// item 1.
func TestCSVCell_GuardsFormulasAndMakesHiddenTextVisible(t *testing.T) {
	cases := map[string]string{
		"casemgmt.list_cases":                 "casemgmt.list_cases",
		"=HYPERLINK(\"http://x.test\",\"a\")": "'=HYPERLINK(\"http://x.test\",\"a\")",
		"+1":                                  "'+1",
		"-2+3":                                "'-2+3",
		"@SUM(A1)":                            "'@SUM(A1)",
		"\tcmd":                               "'\\u{0009}cmd",
		"\rcmd":                               "'\\u{000D}cmd",
		"ana\u202egnp.exe":                    "ana\\u{202E}gnp.exe",
		"line one\nline two":                  "line one\\u{000A}line two",
		"":                                    "",
		"a=b":                                 "a=b",
		"  =1+1":                              "'  =1+1",
		" @SUM(A1)":                           "' @SUM(A1)",
		" plain":                              " plain",
		"(operator:alice)":                    "(operator:alice)",
	}
	for in, want := range cases {
		if got := CSVCell(in); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}
