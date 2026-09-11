package proxy

import (
	"fmt"
	"sort"
	"strings"
)

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

// isSetOp reports whether op is one of LogQL's set operations, which select
// series and samples instead of computing a value.
func isSetOp(op string) bool {
	switch strings.TrimSpace(op) {
	case "and", "or", "unless":
		return true
	}
	return false
}

// combineSetOperation applies `and` / `or` / `unless` between two matrix or
// vector result sets, per LogQL:
//
//   - `and`    keeps a LEFT sample when the right has one with the same label
//     set at the same timestamp;
//   - `unless` keeps a LEFT sample when the right does NOT;
//   - `or`     keeps every left sample and adds the right's samples wherever the
//     left has none — including whole series the left does not have at all.
//
// Emptied series are dropped. The previous code ran these through the
// arithmetic path, which since the comparison fix dropped every left series
// without a right-hand match — turning `or` and `unless` into empty results.
func combineSetOperation(leftResults, rightResults []interface{}, rightIndex map[string]map[string]float64, op string) []interface{} {
	op = strings.TrimSpace(op)
	kept := make([]interface{}, 0, len(leftResults)+len(rightResults))
	leftKeys := make(map[string]map[string]interface{}, len(leftResults))

	for _, raw := range leftResults {
		series, _ := raw.(map[string]interface{})
		if series == nil {
			continue
		}
		metric, _ := series["metric"].(map[string]interface{})
		key := metricKey(metric)
		leftKeys[key] = series
		if op != "or" {
			filterSamplesByRight(series, rightIndex[key], op == "and")
		}
		kept = append(kept, raw)
	}
	kept = dropEmptySeries(kept)

	if op != "or" {
		return kept
	}
	// `or` fills what the left does not cover.
	for _, raw := range rightResults {
		series, _ := raw.(map[string]interface{})
		if series == nil {
			continue
		}
		metric, _ := series["metric"].(map[string]interface{})
		key := metricKey(metric)
		left, exists := leftKeys[key]
		if !exists {
			kept = append(kept, raw)
			continue
		}
		mergeMissingSamples(left, series)
	}
	return dropEmptySeries(kept)
}

// filterSamplesByRight keeps (keepMatched) or removes the samples the right-hand
// side has at the same timestamp.
func filterSamplesByRight(series map[string]interface{}, rightIdx map[string]float64, keepMatched bool) {
	if values, ok := series["values"].([]interface{}); ok {
		kept := make([]interface{}, 0, len(values))
		for _, raw := range values {
			point, _ := raw.([]interface{})
			if len(point) < 2 {
				continue
			}
			_, matched := rightIdx[fmt.Sprintf("%v", point[0])]
			if matched == keepMatched {
				kept = append(kept, raw)
			}
		}
		series["values"] = kept
	}
	if value, ok := series["value"].([]interface{}); ok && len(value) >= 2 {
		_, matched := rightIdx[fmt.Sprintf("%v", value[0])]
		if matched != keepMatched {
			delete(series, "value")
		}
	}
}

// mergeMissingSamples adds the right series' samples at timestamps the left
// series does not have — `or`'s per-sample fill.
func mergeMissingSamples(left, right map[string]interface{}) {
	leftValues, ok := left["values"].([]interface{})
	if !ok {
		return
	}
	have := make(map[string]struct{}, len(leftValues))
	for _, raw := range leftValues {
		if point, _ := raw.([]interface{}); len(point) >= 1 {
			have[fmt.Sprintf("%v", point[0])] = struct{}{}
		}
	}
	rightValues, _ := right["values"].([]interface{})
	added := false
	for _, raw := range rightValues {
		point, _ := raw.([]interface{})
		if len(point) < 2 {
			continue
		}
		if _, seen := have[fmt.Sprintf("%v", point[0])]; seen {
			continue
		}
		leftValues = append(leftValues, raw)
		added = true
	}
	if !added {
		return
	}
	sort.Slice(leftValues, func(i, j int) bool {
		a, _ := leftValues[i].([]interface{})
		b, _ := leftValues[j].([]interface{})
		if len(a) < 1 || len(b) < 1 {
			return false
		}
		return parsePointValue(a[0]) < parsePointValue(b[0])
	})
	left["values"] = leftValues
}
