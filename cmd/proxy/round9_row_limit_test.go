package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The manual range-metric scan's cap moved proxy-side in round 8 and its built-in
// default rose to 1,000,000 — but the FLAG still defaulted to 10,000, so the
// built-in never applied to a real deployment and the panels that change was
// meant to answer went on returning 400: `sum(rate(…))` without `by()`, a
// `label_format` grouping on a busy namespace, `count_over_time(…)` at a fine
// step, `[$__rate_interval]`.
//
// The flag reads the built-in default now (0 = "use it"), and this pins that:
// a 10,000 literal on this flag is the defect coming back.
func TestManualRangeMetricRowLimitFlagUsesTheBuiltInDefault(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	re := regexp.MustCompile(`fs\.Int\("manual-range-metric-row-limit",\s*([0-9_]+)\s*,`)
	m := re.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("the manual-range-metric-row-limit flag is gone — update this test with it")
	}
	if got := strings.ReplaceAll(m[1], "_", ""); got != "0" {
		t.Fatalf("flag default = %s, want 0 so the built-in cap applies; a literal here "+
			"silently overrides it for every deployment", got)
	}
}
