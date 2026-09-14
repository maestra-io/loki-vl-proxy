package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fj "github.com/valyala/fastjson"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// statsMatrixBody renders a VictoriaLogs stats_query_range matrix: one series
// per metric, each with the given bucket-start timestamps (plus VL's epsilon).
func statsMatrixBody(metrics []string, bucketStarts ...int64) string {
	var series []string
	for _, m := range metrics {
		var pts []string
		for _, ts := range bucketStarts {
			pts = append(pts, fmt.Sprintf(`[%d.000001,"1"]`, ts))
		}
		series = append(series, `{"metric":`+m+`,"values":[`+strings.Join(pts, ",")+`]}`)
	}
	return `{"status":"success","data":{"resultType":"matrix","result":[` + strings.Join(series, ",") + `]}}`
}

func metricNames(t *testing.T, body []byte) []string {
	t.Helper()
	v, err := fj.ParseBytes(body)
	if err != nil {
		t.Fatalf("parse %.200s: %v", body, err)
	}
	var out []string
	for _, item := range v.GetArray("data", "result") {
		out = append(out, string(item.Get("metric").MarshalTo(nil)))
	}
	return out
}

// Round 12, N1: a whole-cluster `sum by (pod) (count_over_time(...))` at
// range == step from a plain client answered 183 of Loki's 939 pods — the
// Drilldown top-N two-phase selection (Phase 1 keeps 200 values) fired for
// every single-field count over 2h, HTTP 200, no warning. A non-Drilldown
// request takes the exact direct path, which serves every series up to the
// cap; a series whose only bucket starts AT `end` is not a phantom
// `"values":[]` entry.
func TestStatsRange_WideGroupingKeepsEverySeriesAtRangeEqualsStep(t *testing.T) {
	const start, end, step = int64(1700000000), int64(1700014400), int64(3600)
	var pods []string
	for i := 0; i < 600; i++ {
		pods = append(pods, fmt.Sprintf(`{"pod":"p%03d"}`, i))
	}
	full := statsMatrixBody(pods, start-step, start, start+step, start+2*step, start+3*step)
	// The bucket VictoriaLogs returns for `end` itself relabels to end+step.
	phantom := statsMatrixBody([]string{`{"pod":"after-end"}`}, end)
	full = strings.Replace(full, `]}}`, `,`+phantom[strings.Index(phantom, `[{"metric"`)+1:], 1)

	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, query string) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(query, "| sort by (_c desc)") {
			fmt.Fprint(w, statsMatrixBody([]string{`{"pod":"p000"}`}, start))
			return
		}
		fmt.Fprint(w, full)
	})
	target := "/loki/api/v1/query_range?query=" + url.QueryEscape(`sum by (pod) (count_over_time({namespace=~".+"}[1h]))`) +
		fmt.Sprintf("&start=%d&end=%d&step=%d", start, end, step)

	p := newGapTestProxy(t, vl.URL)
	p.maxStatsQuerySeries = 10000
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %.300s", rec.Code, rec.Body.String())
	}
	if n := countLokiMatrixSeries(rec.Body.Bytes()); n != 600 {
		t.Fatalf("want all 600 series, got %d", n)
	}
	if strings.Contains(rec.Body.String(), `"values":[]`) || strings.Contains(rec.Body.String(), "after-end") {
		t.Fatalf("phantom series in %.300s", rec.Body.String())
	}
	for _, q := range seen() {
		if strings.Contains(q, "| sort by (_c desc)") {
			t.Fatalf("a plain client must not take the top-N selection: %s", q)
		}
	}

	// A Drilldown page keeps the selection path (its charts want the busiest N).
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Query-Tags", "Source=grafana-lokiexplore-app")
	rec = httptest.NewRecorder()
	newGapTestProxy(t, vl.URL).handleQueryRange(rec, req)
	phase1 := false
	for _, q := range seen() {
		phase1 = phase1 || strings.Contains(q, "| sort by (_c desc)")
	}
	if rec.Code != http.StatusOK || !phase1 {
		t.Fatalf("drilldown: HTTP %d, phase-1 selection issued=%v", rec.Code, phase1)
	}
}

// Round 12, C: a `by (x)` over rows without x is `{x=""}` in VictoriaLogs and
// `{}` in Loki (an empty value is no label). Range and instant.
func TestStatsLabels_EmptyGroupValueIsNoLabel(t *testing.T) {
	const start, end, step = int64(1700000000), int64(1700007200), int64(3600)
	vl, _ := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/stats_query") {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"rid":""},"value":[1700007200,"7"]}]}}`)
			return
		}
		fmt.Fprint(w, statsMatrixBody([]string{`{"strimzi_io_cluster":""}`, `{"strimzi_io_cluster":"","x":"a"}`}, start, start+step))
	})
	p := newGapTestProxy(t, vl.URL)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`sum by (strimzi_io_cluster, x) (count_over_time({a="b"}[1h]))`)+
		fmt.Sprintf("&start=%d&end=%d&step=%d", start, end, step), nil))
	if got := metricNames(t, rec.Body.Bytes()); rec.Code != http.StatusOK || len(got) != 2 || got[0] != `{}` || got[1] != `{"x":"a"}` {
		t.Fatalf("range: HTTP %d metrics %v (%.300s)", rec.Code, got, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+
		url.QueryEscape(`sum by (rid) (count_over_time({a="b"}[1h]))`)+"&time=1700007200", nil))
	if got := metricNames(t, rec.Body.Bytes()); rec.Code != http.StatusOK || len(got) != 1 || got[0] != `{}` {
		t.Fatalf("instant: HTTP %d metrics %v (%.300s)", rec.Code, got, rec.Body.String())
	}
}

// Round 12 (c), grouping: `sum by (ExceptionDetails_Topic)` after `| json`
// groups by the dotted VictoriaLogs spelling too, and the response coalesces
// the pair into the Loki label.
func TestStatsRange_UnderscoreGroupingAfterParserGroupsByDottedToo(t *testing.T) {
	const start, end, step = int64(1700000000), int64(1700007200), int64(3600)
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, statsMatrixBody([]string{`{"ExceptionDetails_Topic":"","ExceptionDetails.Topic":"orders"}`}, start, start+step))
	})
	p, err := New(Config{BackendURL: vl.URL, Cache: cache.New(60, 100), LogLevel: "error", LabelStyle: LabelStyleUnderscores})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`sum by (ExceptionDetails_Topic) (count_over_time({a="b"} | json [1h]))`)+
		fmt.Sprintf("&start=%d&end=%d&step=%d", start, end, step), nil))
	if got := metricNames(t, rec.Body.Bytes()); rec.Code != http.StatusOK || len(got) != 1 || got[0] != `{"ExceptionDetails_Topic":"orders"}` {
		t.Fatalf("HTTP %d metrics %v (%.300s)", rec.Code, got, rec.Body.String())
	}
	grouped := false
	for _, q := range seen() {
		grouped = grouped || strings.Contains(q, "stats by (ExceptionDetails_Topic, `ExceptionDetails.Topic`)")
	}
	if !grouped {
		t.Fatalf("dotted grouping missing: %v", seen())
	}

	// The manual (raw-row) instant path groups by the same field: a row VL
	// unpacked as `ExceptionDetails.Topic` answers `by (ExceptionDetails_Topic)`.
	rows, _ := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		if strings.HasSuffix(r.URL.Path, "/query") {
			w.Header().Set("Content-Type", "application/x-ndjson")
			fmt.Fprint(w, `{"_time":"2023-11-14T22:13:30Z","_msg":"{\"ExceptionDetails\":{\"Topic\":\"orders\"}}","_stream":"{app=\"a\"}","app":"a","ExceptionDetails.Topic":"orders"}`+"\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	})
	p, err = New(Config{BackendURL: rows.URL, Cache: cache.New(60, 100), LogLevel: "error", LabelStyle: LabelStyleUnderscores, MetadataFieldMode: MetadataFieldModeHybrid})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+
		url.QueryEscape(`sum by (ExceptionDetails_Topic) (count_over_time({app="a"} | json | ExceptionDetails_Topic!="" [1h]))`)+"&time=1700000100", nil))
	if got := metricNames(t, rec.Body.Bytes()); rec.Code != http.StatusOK || len(got) != 1 || got[0] != `{"ExceptionDetails_Topic":"orders"}` {
		t.Fatalf("instant manual path: HTTP %d metrics %v (%.300s)", rec.Code, got, rec.Body.String())
	}
}
