package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// Every outer-aggregation keyword is also the prefix of a RANGE aggregation, so
// `min_over_time(...)` read as an outer `min` and sent the query through a
// reduction that does not belong to it.
func TestOuterAggregationOverSeries_IgnoresBareRangeAggregation(t *testing.T) {
	for _, q := range []string{
		`min_over_time({a="b"} | json | unwrap d [5m])`,
		`max_over_time({a="b"} | json | unwrap d [5m]) by (ns)`,
		`avg_over_time({a="b"} | json | unwrap d [5m])`,
		`quantile_over_time(0.95, {a="b"} | json | unwrap d [5m])`,
	} {
		if agg, _, ok := outerAggregationOverSeries(q, "min"); ok {
			t.Fatalf("%s: read as outer aggregation %q", q, agg)
		}
	}
	// The real outer aggregation is still recognised.
	if _, _, ok := outerAggregationOverSeries(`max(min_over_time({a="b"} | unwrap d [5m]))`, "min"); !ok {
		t.Fatal("max(min_over_time(...)) not recognised as an outer aggregation")
	}
}

// The decomposition switches POOLING off; it must not drop the grouping labels,
// which the raw-row collector needs to keep parser-derived dimensions in the
// series key (and which the reduction below groups by).
func TestApplyLokiSeriesDecomposition_KeepsGroupingLabels(t *testing.T) {
	spec := statsCompatSpec{GroupBy: []string{"ns"}, OrigGroupBy: []string{"namespace"}, ByExplicit: true}
	applyLokiSeriesDecomposition(&spec, `sum by (namespace) (min_over_time({a="b"} | json | unwrap d [5m]))`, "min")

	if spec.OuterAggAcrossSeries != "sum" {
		t.Fatalf("outer aggregation = %q, want sum", spec.OuterAggAcrossSeries)
	}
	if len(spec.GroupBy) != 1 || spec.GroupBy[0] != "ns" ||
		len(spec.OrigGroupBy) != 1 || spec.OrigGroupBy[0] != "namespace" {
		t.Fatalf("grouping labels were dropped: %+v", spec)
	}
	if spec.ByExplicit {
		t.Fatal("pooling is still on")
	}
}

// One series is not a no-op for the reduction: the decomposition leaves the full
// label set on it and the outer aggregation still has to trim it.
func TestReduceLokiSeriesAcrossSeries_TrimsLabelsOfASingleSeries(t *testing.T) {
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"ns":"a","pod":"p-1"},"values":[[100,"3"],[160,"9"]]}]}}`)
	out := reduceLokiSeriesAcrossSeries(body, "max", nil)

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
	if len(resp.Data.Result) != 1 || len(resp.Data.Result[0].Metric) != 0 {
		t.Fatalf("expected one unlabelled series, got %s", out)
	}
	if len(resp.Data.Result[0].Values) != 2 {
		t.Fatalf("expected both points, got %s", out)
	}
}

// A quantile is computed here for exactness, but the raw-row scan it needs has a
// cap. Hitting the cap must hand the query back to VictoriaLogs' own quantile —
// a small numeric difference beats failing the panel with a 400.
func TestQuantileFallsBackToBackend(t *testing.T) {
	truncated := &rawRowScanTruncatedError{limit: 10000}
	if !quantileFallsBackToBackend("quantile", truncated) {
		t.Fatal("a truncated quantile scan must fall back to the backend")
	}
	if quantileFallsBackToBackend("count_over_time", truncated) {
		t.Fatal("only a quantile falls back")
	}
	if quantileFallsBackToBackend("quantile", errors.New("backend returned 500")) {
		t.Fatal("only a TRUNCATED scan falls back")
	}
}

// `now`/`now±d` resolve against time.Now() on every parse, so the request and
// the response filter were built from two different instants — and the filter,
// being later, dropped the first point the request had gone back to fetch.
func TestFreezeRelativeRangeBound(t *testing.T) {
	frozen := freezeRelativeRangeBound("now-1h")
	if frozen == "now-1h" {
		t.Fatal("a relative bound must resolve to an absolute timestamp")
	}
	first, ok := parseLokiTimeToUnixNano(frozen)
	if !ok {
		t.Fatalf("frozen bound %q does not parse", frozen)
	}
	time.Sleep(2 * time.Millisecond)
	second, _ := parseLokiTimeToUnixNano(frozen)
	if first != second {
		t.Fatalf("frozen bound still moves: %d vs %d", first, second)
	}
	// Absolute bounds are untouched.
	if got := freezeRelativeRangeBound("1700000040"); got != "1700000040" {
		t.Fatalf("absolute bound rewritten to %q", got)
	}
}

// Measured on Loki 3.7.1: a stream carrying BOTH `foo` and `foo_extracted`,
// parsed with `| json` over a body holding `foo`, answers
// foo=<stream>, foo_extracted=<body>. Loki overwrites the existing
// `_extracted` label rather than chaining another suffix onto it.
func TestPipeline_ParsedLabelOverwritesExistingExtractedLabel(t *testing.T) {
	pipeline, err := logqlpkg.NewPipeline([]logqlpkg.Stage{
		&logqlpkg.ParserStage{Type: logqlpkg.ParserJSON},
	})
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	e := logqlpkg.Entry{
		Line:   `{"foo":"body-foo","bar":"body-bar"}`,
		Labels: map[string]string{"foo": "stream-foo", "foo_extracted": "stream-foo-ext"},
	}
	if !pipeline.Process(&e) {
		t.Fatal("entry dropped")
	}
	for k, want := range map[string]string{
		"foo":           "stream-foo",
		"foo_extracted": "body-foo",
		"bar":           "body-bar",
	} {
		if got := e.Labels[k]; got != want {
			t.Fatalf("label %q = %q, want %q (all: %v)", k, got, want, e.Labels)
		}
	}
}

// The aggregation reads a field by name too, and LogQL gives the stream label
// priority there just as it does for a grouping label.
func TestGuardExtractedLabelShadowing_ProtectsTheAggregationField(t *testing.T) {
	p := &Proxy{}
	got := p.guardExtractedLabelShadowing(
		`app:="x" | unpack_json | stats by (app) quantile(0.95, duration_ms)`)
	for _, want := range []string{
		`| format "<duration_ms>" as __lvp_pre_duration_ms`,
		`| format if (__lvp_pre_duration_ms:*) "<__lvp_pre_duration_ms>" as duration_ms`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("guarded query does not protect the aggregation field (%q):\n%s", want, got)
		}
	}
}

// A pipeline can carry several parsers; restoring after the FIRST one lets the
// next re-shadow the label.
func TestGuardExtractedLabelShadowing_RestoresAfterTheLastParser(t *testing.T) {
	p := &Proxy{}
	got := p.guardExtractedLabelShadowing(
		`app:="x" | unpack_json | unpack_logfmt | stats by (app) count()`)
	restore := strings.Index(got, `"<__lvp_pre_app>" as app`)
	lastParser := strings.LastIndex(got, "| unpack_logfmt")
	if restore < 0 || lastParser < 0 {
		t.Fatalf("unexpected guarded query:\n%s", got)
	}
	if restore < lastParser {
		t.Fatalf("the label is restored BEFORE the last parser stage:\n%s", got)
	}
}

// Both operands of a binary range expression must be fetched on the CLIENT's
// bucket grid. Without the offset VictoriaLogs answers on the epoch grid, and
// relabelling those buckets onto a `:05` grid only renames them — the operands
// then carry `:00–:60` contents under `:05` labels.
func TestQueryRange_BinaryOperandsUseTheLokiGrid(t *testing.T) {
	// The client asks from 25 minutes past the hour; Loki truncates that to the
	// step grid, so both operands must be built from the SAME aligned start —
	// which is what makes the offset identical on both of them.
	base := time.Unix(1700000700, 0).UTC()
	alignedBase := time.Unix(1700000700-1500, 0).UTC()
	const step = 3600

	// The binary path fetches both operands CONCURRENTLY, so the capture needs
	// its own lock.
	var mu sync.Mutex
	var gotOffsets, gotStarts []string
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotOffsets = append(gotOffsets, r.Form.Get("offset"))
		gotStarts = append(gotStarts, r.Form.Get("start"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"app":"a"},"values":[[%d,"2"],[%d,"4"]]}]}}`,
			alignedBase.Unix()-step, alignedBase.Unix())
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `sum(count_over_time({app="a"}[1h])) / sum(count_over_time({app="b"}[1h]))`)
	params.Set("start", strconv.FormatInt(base.Unix(), 10))
	params.Set("end", strconv.FormatInt(base.Unix()+2*step, 10))
	params.Set("step", strconv.Itoa(step))
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotOffsets) < 2 {
		t.Fatalf("expected both operands to be fetched, got %d upstream calls", len(gotOffsets))
	}
	// The aligned start IS a multiple of the step, so the only offset left is the
	// microsecond that makes the bucket right-closed — and every operand must
	// carry it.
	for i, off := range gotOffsets {
		if off != "-0.000001s" {
			t.Fatalf("operand %d fetched without the client-grid offset: offset=%q start=%q", i, off, gotStarts[i])
		}
	}
	// And both operands must open one step before the ALIGNED start.
	for i, start := range gotStarts {
		if want := strconv.FormatInt(alignedBase.Unix()-step, 10); start != want {
			t.Fatalf("operand %d start = %q, want %q", i, start, want)
		}
	}

	var resp struct {
		Data struct {
			Result []struct {
				Values [][]interface{} `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Result) != 1 {
		t.Fatalf("expected one combined series, got %s", rec.Body.String())
	}
	// The bucket labelled `alignedBase-step` is the point at `alignedBase`; the
	// one at `alignedBase` is the point at `alignedBase+step`.
	for i, pt := range resp.Data.Result[0].Values {
		ts := int64(pt[0].(float64))
		if want := alignedBase.Unix() + int64(i)*step; ts != want {
			t.Fatalf("point %d at %d, want %d (operands off the client grid?)", i, ts, want)
		}
	}
}
