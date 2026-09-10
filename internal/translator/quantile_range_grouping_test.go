package translator

import (
	"strings"
	"testing"
)

// TestQuantileOverTimeRangeGroupingIsHonoured locks the fix for the instant/range
// grouping defect: quantile_over_time is intercepted by its own two-argument
// translator (tryTranslateQuantileOverTimeM) before the generic metric-function
// loop, and that interceptor used to drop the trailing `by (...)` modifier.
//
// With the clause dropped, unwrapInnerGrouping fell through to its
// parser-pipeline default of "_stream, _msg", so
//
//	quantile_over_time(0.95, {ns=~"app.+"} | json | unwrap D [10m]) by (namespace)
//
// grouped by full stream identity PLUS the raw log line — one series per pod on
// the instant path and one series per log entry on the range path, instead of
// one series per namespace.
//
// The expectations below are exactly what the generic loop already produced for
// the single-argument siblings (max_over_time / avg_over_time), which is the
// invariant worth locking: quantile_over_time must not be a special case.
func TestQuantileOverTimeRangeGroupingIsHonoured(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "by labels with parser pipeline",
			in:   `quantile_over_time(0.95, {namespace="a"} | json | unwrap D [5m]) by (namespace)`,
			want: `namespace:="a" | unpack_json | stats by (namespace) quantile(0.95, D)`,
		},
		{
			name: "by multiple labels",
			in:   `quantile_over_time(0.5, {namespace="a"} | json | unwrap D [5m]) by (namespace, app)`,
			want: `namespace:="a" | unpack_json | stats by (namespace, app) quantile(0.5, D)`,
		},
		{
			// No parser pipeline: the old code produced a bare "| stats quantile(...)"
			// with no grouping at all, collapsing every namespace into one series.
			name: "by labels without parser pipeline",
			in:   `quantile_over_time(0.95, {namespace="a"} | unwrap D [5m]) by (namespace)`,
			want: `namespace:="a" | stats by (namespace) quantile(0.95, D)`,
		},
		{
			name: "explicit empty by collapses to one series",
			in:   `quantile_over_time(0.95, {namespace="a"} | json | unwrap D [5m]) by ()`,
			want: `namespace:="a" | unpack_json | stats by () quantile(0.95, D)`,
		},
		{
			// No grouping modifier at all keeps the per-stream default. This case
			// was already correct and must stay that way.
			name: "no grouping keeps stream identity default",
			in:   `quantile_over_time(0.95, {namespace="a"} | json | unwrap D [5m])`,
			want: `namespace:="a" | unpack_json | stats by (_stream, _msg) quantile(0.95, D)`,
		},
		{
			// An outer aggregation wrapping a range-grouped inner expression must
			// aggregate over the grouped series, not over per-line series.
			name: "outer sum over range-grouped inner",
			in:   `sum(quantile_over_time(0.95, {namespace="a"} | json | unwrap D [5m]) by (namespace))`,
			want: `namespace:="a" | unpack_json | stats by (namespace) quantile(0.95, D) as __lvp_inner | stats sum(__lvp_inner)`,
		},
		{
			// Outer "sum by (...)" was always honoured; kept so a future refactor
			// cannot fix the range clause by breaking the outer one.
			name: "outer sum by over ungrouped inner",
			in:   `sum by (namespace) (quantile_over_time(0.95, {namespace="a"} | json | unwrap D [5m]))`,
			want: `namespace:="a" | unpack_json | stats by (namespace) quantile(0.95, D)`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TranslateLogQL(tc.in)
			if err != nil {
				t.Fatalf("TranslateLogQL(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("TranslateLogQL(%q)\n got: %s\nwant: %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestRangeGroupingParityAcrossUnwrapFuncs asserts quantile_over_time now emits
// the same grouping clause as every other unwrapped range aggregation for the
// same input shape. A divergence here is the defect re-appearing.
func TestRangeGroupingParityAcrossUnwrapFuncs(t *testing.T) {
	for _, fn := range []string{"max_over_time", "min_over_time", "avg_over_time", "sum_over_time"} {
		t.Run(fn, func(t *testing.T) {
			in := fn + `({namespace="a"} | json | unwrap D [5m]) by (namespace)`
			got, err := TranslateLogQL(in)
			if err != nil {
				t.Fatalf("TranslateLogQL(%q): %v", in, err)
			}
			// Every sibling must carry the requested grouping — not "_stream, _msg".
			if want := "| stats by (namespace) "; !strings.Contains(got, want) {
				t.Errorf("TranslateLogQL(%q) = %s, want it to contain %q", in, got, want)
			}
		})
	}

	// And the function under fix agrees with them.
	got, err := TranslateLogQL(`quantile_over_time(0.9, {namespace="a"} | json | unwrap D [5m]) by (namespace)`)
	if err != nil {
		t.Fatalf("quantile_over_time: %v", err)
	}
	if want := "| stats by (namespace) "; !strings.Contains(got, want) {
		t.Errorf("quantile_over_time got %s, want it to contain %q", got, want)
	}
}
