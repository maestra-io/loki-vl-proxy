package translator

import (
	"strings"
	"testing"
)

// CodeRabbit 3984724029: the `bool` modifier must be read off the SELECTED
// top-level operator, not scanned for across the whole query — `bool` inside a
// label matcher is data, and a nested comparison owns its own modifier.
func TestTryTranslateBinaryMetricExpr_BoolBelongsToItsOwnOperator(t *testing.T) {
	for _, tc := range []struct {
		name   string
		logql  string
		wantOp string
	}{
		{"bare comparison", `rate({app="a"}[5m]) > rate({app="b"}[5m])`, ">"},
		{"bool comparison", `rate({app="a"}[5m]) > bool rate({app="b"}[5m])`, "> bool"},
		{"bool inside a matcher", `rate({msg="a bool b"}[5m]) > rate({app="b"}[5m])`, ">"},
		{"bool inside the right-hand matcher", `rate({app="a"}[5m]) > rate({msg="x bool y"}[5m])`, ">"},
		{"bool modifier before a scalar", `rate({app="a"}[5m]) > bool 0.5`, "> bool"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, ok := tryTranslateBinaryMetricExpr(tc.logql, nil)
			if !ok {
				t.Fatalf("expected %q to translate as a binary metric expression", tc.logql)
			}
			encoded := strings.TrimPrefix(out, BinaryMetricPrefix)
			sep := strings.Index(encoded, ":")
			if sep < 0 {
				t.Fatalf("malformed binary marker %q", out)
			}
			if gotOp := encoded[:sep]; gotOp != tc.wantOp {
				t.Fatalf("operator = %q, want %q (full: %s)", gotOp, tc.wantOp, out)
			}
			if strings.Contains(out, `a  b`) {
				t.Fatalf("the matcher text was mangled by bool stripping: %s", out)
			}
		})
	}
}
