package logql

import "testing"

// Grafana emits a COMPOUND duration for `$__range` on any non-round dashboard
// window. The scanner read one value+unit pair and stopped, so `[4h30m]` failed
// with `expected ], got DURATION ("30m")` — three Trow Registry stat panels 400ed
// on every such range while Loki answered 200.
func TestScanner_CompoundDurations(t *testing.T) {
	for _, q := range []string{
		`sum(count_over_time({app="a"}[4h30m]))`,
		`sum(count_over_time({app="a"}[1h30m]))`,
		`sum(count_over_time({app="a"}[1m30s]))`,
		`sum(count_over_time({app="a"}[1d12h]))`,
		`sum(count_over_time({app="a"}[1h30m15s]))`,
		`sum(count_over_time({app="a"}[270m]))`,
		`sum(count_over_time({app="a"}[4h]))`,
	} {
		if msg := ValidateLogQL(q); msg != "" {
			t.Errorf("%s rejected: %s", q, msg)
		}
	}
	// A bare number is still a number, not a duration.
	if got := ValidateLogQL(`topk(5, sum(rate({app="a"}[1m])))`); got != "" {
		t.Errorf("plain number broke: %s", got)
	}
}

// LogQL allows an OR-list in a line filter; the parser stopped at the first value
// and reported `unexpected token RAWSTRING`.
func TestParser_LineFilterOrList(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  string
	}{
		{"{ns=\"x\"} |= `a` or `b`", `{ns="x"} |= "a" or "b"`},
		{`{ns="x"} != "a" or "b"`, `{ns="x"} != "a" or "b"`},
		{`{ns="x"} |~ "a" or "b" or "c"`, `{ns="x"} |~ "a" or "b" or "c"`},
	} {
		e, err := Parse(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.query, err)
		}
		if got := e.String(); got != tc.want {
			t.Errorf("%s -> %s, want %s", tc.query, got, tc.want)
		}
	}
	// `or` between two metric expressions is still the binary set operator.
	if _, err := Parse(`sum(rate({a="b"}[1m])) or sum(rate({c="d"}[1m]))`); err != nil {
		t.Fatalf("binary or broke: %v", err)
	}
}

// The OR-list shares its stage's single operator: a positive filter keeps a line
// matching ANY alternative, a negative one drops a line matching any of them.
func TestMatchLineFilter_OrList(t *testing.T) {
	contains := &LineFilterStage{Op: LineFilterContains, Value: "alpha", Or: []string{"beta"}}
	excludes := &LineFilterStage{Op: LineFilterExcludes, Value: "alpha", Or: []string{"beta"}}
	for _, tc := range []struct {
		line            string
		wantIn, wantOut bool
	}{
		{"has alpha here", true, false},
		{"has beta here", true, false},
		{"has neither", false, true},
	} {
		if got := matchLineFilter(contains, tc.line); got != tc.wantIn {
			t.Errorf("|= on %q = %v, want %v", tc.line, got, tc.wantIn)
		}
		if got := matchLineFilter(excludes, tc.line); got != tc.wantOut {
			t.Errorf("!= on %q = %v, want %v", tc.line, got, tc.wantOut)
		}
	}
}
