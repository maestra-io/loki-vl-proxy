package logql

import "testing"

// Round 12 (b): a parenthesised label-filter stage parses, inside a metric
// call too (its own `)` must not close the call).
func TestParse_ParenthesisedLabelFilterStage(t *testing.T) {
	for _, q := range []string{
		`{a="b"} | json | (x="1" or y="2")`,
		`sum(count_over_time({a="b"} | json | (x="1" or y="2") and z!="3" [1h]))`,
	} {
		expr, err := Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for {
			if v, ok := expr.(*VectorAggregation); ok {
				expr = v.Inner
				continue
			}
			if r, ok := expr.(*RangeAggregation); ok {
				expr = r.Inner
				continue
			}
			break
		}
		lq, ok := expr.(*LogQuery)
		if !ok {
			t.Fatalf("%s: no log query, got %T", q, expr)
		}
		stages := lq.Pipeline
		last, ok := stages[len(stages)-1].(*LabelFilterStage)
		if !ok || last.Raw[0] != '(' {
			t.Fatalf("%s: last stage %#v, want a label filter opening with (", q, stages[len(stages)-1])
		}
		if _, err := parseLabelFilter(last.Raw); err != nil {
			t.Fatalf("%s: %q does not evaluate: %v", q, last.Raw, err)
		}
	}
}
