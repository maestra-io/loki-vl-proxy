package proxy

import "strings"

// LogQL — like PromQL — gives a BARE comparison filtering semantics: `expr > 5`
// keeps the samples whose value satisfies the comparison, WITH THEIR OWN VALUE,
// and drops the rest; a series left with no samples disappears entirely. Only
// the `bool` modifier (`expr > bool 5`) scores every sample 1 or 0.
//
// The proxy used to strip `bool` in the translator and score every comparison
// 1/0, so `sum(...) > 1000` drew a flat line of 1s and `... > 100000` drew seven
// zeros where Loki returns no series at all.
//
// The modifier travels as a suffix on the operator string, which is what every
// binary path already passes around.
const boolModifierSuffix = " bool"

// withBoolModifier tags an operator as carrying LogQL's `bool`.
func withBoolModifier(op string, returnBool bool) string {
	if !returnBool || strings.HasSuffix(op, boolModifierSuffix) {
		return op
	}
	return op + boolModifierSuffix
}

// splitBoolModifier separates an operator from its `bool` modifier.
func splitBoolModifier(op string) (bare string, returnBool bool) {
	if trimmed, found := strings.CutSuffix(op, boolModifierSuffix); found {
		return strings.TrimSpace(trimmed), true
	}
	return op, false
}

// isComparisonOp reports whether op compares rather than computes.
func isComparisonOp(op string) bool {
	switch op {
	case "==", "!=", ">", "<", ">=", "<=":
		return true
	}
	return false
}

func compareValues(a, b float64, op string) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case ">":
		return a > b
	case "<":
		return a < b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	}
	return false
}

// evalBinarySample applies one binary operation to one sample pair. keep=false
// means the sample is FILTERED OUT — a bare comparison the sample does not
// satisfy.
func evalBinarySample(a, b float64, op string) (value float64, keep bool) {
	bare, returnBool := splitBoolModifier(op)
	if isComparisonOp(bare) {
		match := compareValues(a, b, bare)
		if returnBool {
			if match {
				return 1, true
			}
			return 0, true
		}
		return a, match
	}
	return applyOp(a, b, bare), true
}

// dropEmptySeries removes series a comparison filtered down to nothing, the way
// LogQL drops a series with no remaining samples.
func dropEmptySeries(results []interface{}) []interface{} {
	kept := make([]interface{}, 0, len(results))
	for _, raw := range results {
		series, _ := raw.(map[string]interface{})
		if series == nil {
			continue
		}
		if values, ok := series["values"].([]interface{}); ok {
			if len(values) == 0 {
				continue
			}
		} else if _, ok := series["value"].([]interface{}); !ok {
			continue
		}
		kept = append(kept, raw)
	}
	return kept
}
