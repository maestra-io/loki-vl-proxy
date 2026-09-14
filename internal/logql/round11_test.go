package logql

import "testing"

// Round 11, defect 6: a label_format whose template is one field reference is
// a LogsQL `| format "<field>" as dst` and stays pushed down; anything else —
// a function, a conditional, or a reference to a label the same stage writes
// (Loki evaluates all assignments against the pre-stage labels) — still needs
// the proxy-side evaluator.
func TestHasTemplateStage_PureFieldAliasIsNotATemplate(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  bool
	}{
		{"{a=\"b\"} | json | label_format lf=`{{ .level }}`", false},
		{`{a="b"} | json | label_format lf="{{.level}}", svc="{{ .service.name }}"`, false},
		{"{a=\"b\"} | json | label_format lf=`{{ .level | upper }}`", true},
		{"{a=\"b\"} | json | label_format lf=`{{ if .level }}{{ .level }}{{ else }}none{{ end }}`", true},
		{"{a=\"b\"} | json | label_format a=`{{ .b }}`, b=`{{ .a }}`", true},
		{`{a="b"} | line_format "{{.x}}"`, true},
	} {
		expr, err := Parse(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.query, err)
		}
		lq := expr.(*LogQuery)
		if got := HasTemplateStage(lq.Pipeline); got != tc.want {
			t.Errorf("%s: HasTemplateStage = %v, want %v", tc.query, got, tc.want)
		}
	}
}
