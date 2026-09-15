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

// `| ip("…")` is an OPERAND of a line or label filter, never a stage of its
// own: Loki answers "syntax error: unexpected IP". Round 12 taught the stage
// scanner to keep its own parentheses, which turned this into a silent 200.
func TestParse_BareIPCallStageIsRejected(t *testing.T) {
	for _, q := range []string{
		`{app="api-gateway"} | json | ip("not-a-valid-cidr")`,
		`{app="api-gateway"} | ip("10.0.0.0/8")`,
	} {
		if _, err := Parse(q); err == nil {
			t.Errorf("%s: must not parse", q)
		}
	}
	for _, q := range []string{
		`{app="api-gateway"} | json | addr = ip("10.0.0.0/8")`,
		`{app="api-gateway"} |= ip("10.0.0.0/8")`,
	} {
		if _, err := Parse(q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}
