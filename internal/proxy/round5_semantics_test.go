package proxy

import (
	"encoding/json"
	"strings"
	"testing"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
)

// A parser must not overwrite a label the row already carried: LogQL keeps the
// stream label and exposes the parsed value as `<name>_extracted`. Measured on
// Loki 3.7.1 with a body carrying `namespace`/`app` fields under a stream
// labelled namespace=shd, app=svc-shd.
func TestPipeline_ParsedLabelDoesNotShadowStreamLabel(t *testing.T) {
	pipeline, err := logqlpkg.NewPipeline([]logqlpkg.Stage{
		&logqlpkg.ParserStage{Type: logqlpkg.ParserJSON},
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	e := logqlpkg.Entry{
		Line:   `{"namespace":"target-0","app":"body-app","message":"hi"}`,
		Labels: map[string]string{"namespace": "shd", "app": "svc-shd"},
	}
	if !pipeline.Process(&e) {
		t.Fatal("entry dropped")
	}
	for k, want := range map[string]string{
		"namespace":           "shd",
		"app":                 "svc-shd",
		"namespace_extracted": "target-0",
		"app_extracted":       "body-app",
		"message":             "hi",
	} {
		if got := e.Labels[k]; got != want {
			t.Fatalf("label %q = %q, want %q (all: %v)", k, got, want, e.Labels)
		}
	}
}

// The same rule inside the pushed-down query: the grouped label is snapshotted
// before the parser and restored after it, so a body field of the same name
// cannot fan `sum by (namespace)` out over the body's values.
func TestGuardExtractedLabelShadowing_RestoresGroupedLabel(t *testing.T) {
	p := &Proxy{}
	got := p.guardExtractedLabelShadowing(
		`"kubernetes.pod_namespace":="shd" | unpack_json | stats by (kubernetes.pod_namespace, namespace) count()`)
	for _, want := range []string{
		`| format "<namespace>" as __lvp_pre_namespace | unpack_json`,
		`| format if (__lvp_pre_namespace:*) "<__lvp_pre_namespace>" as namespace`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("guarded query %q does not contain %q", got, want)
		}
	}
	// A query with no parser stage is left alone.
	plain := `"kubernetes.pod_namespace":="shd" | stats by (namespace) count()`
	if out := p.guardExtractedLabelShadowing(plain); out != plain {
		t.Fatalf("query without a parser stage was rewritten: %q", out)
	}
}

// LogQL evaluates a range aggregation PER LABEL SET and applies the outer
// aggregation to those results. Pooling every row into one series answers a
// different question for an order statistic — the T5 panel came back 13.4%
// below Loki (p95 of everything instead of the max of the per-series p95s).
func TestOuterAggregationOverSeries_OnlyForOrderStatistics(t *testing.T) {
	for _, tc := range []struct {
		logql, manualFunc, wantAgg string
	}{
		{`max(quantile_over_time(0.95, {a="b"} | json | unwrap d [5m]))`, "quantile", "max"},
		{`sum by (ns) (min_over_time({a="b"} | json | unwrap d [5m]))`, "min", "sum"},
		// Additive: pooling IS the sum, and it is the cheaper path.
		{`sum(count_over_time({a="b"} | json [5m]))`, "count_over_time", ""},
		{`sum(rate({a="b"} | json [5m]))`, "rate", ""},
		// No outer aggregation at all.
		{`quantile_over_time(0.95, {a="b"} | json | unwrap d [5m])`, "quantile", ""},
	} {
		agg, _, ok := outerAggregationOverSeries(tc.logql, tc.manualFunc)
		if !ok {
			agg = ""
		}
		if agg != tc.wantAgg {
			t.Fatalf("%s → %q, want %q", tc.logql, agg, tc.wantAgg)
		}
	}
}

// The reducer applies the outer aggregation across series at each timestamp.
func TestReduceLokiSeriesAcrossSeries_MaxPerTimestamp(t *testing.T) {
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"ns":"a","id":"1"},"values":[[100,"3"],[160,"9"]]},` +
		`{"metric":{"ns":"a","id":"2"},"values":[[100,"7"],[160,"1"]]}]}}`)
	out := reduceLokiSeriesAcrossSeries(body, "max", []string{"ns"})

	var resp struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][]interface{}   `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Result) != 1 || resp.Data.Result[0].Metric["ns"] != "a" ||
		len(resp.Data.Result[0].Metric) != 1 {
		t.Fatalf("expected one series grouped by ns, got %s", out)
	}
	want := []string{"7", "9"}
	for i, pt := range resp.Data.Result[0].Values {
		if got := pt[1]; got != want[i] {
			t.Fatalf("point %d = %v, want %s: %s", i, got, want[i], out)
		}
	}
}
