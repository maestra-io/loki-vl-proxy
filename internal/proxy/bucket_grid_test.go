package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// Per-point bucket-grid contract. A LogQL range-metric sample at `t` covers
// (t-range, t] and is labelled `t`; a VictoriaLogs stats bucket labelled `b`
// covers [b, b+step). So VL bucket `b` is Loki's point `b+step`, and the proxy
// must reach one step further back so the point at `start` still has a bucket.
//
// Every step here carries a DISTINCT count, so a one-step shift changes the
// per-point values. A test that compared the sum would pass either way — that
// is exactly how this bug survived.
func TestQueryRange_BucketsAreLabelledByEndOnLokiGrid(t *testing.T) {
	base := time.Unix(1700000040, 0).UTC() // 60s-aligned
	const step = 60

	var gotStart, gotEnd string
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/stats_query_range" {
			t.Errorf("unexpected backend path %s", r.URL.Path)
			return
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			return
		}
		gotStart, gotEnd = r.Form.Get("start"), r.Form.Get("end")

		// Buckets base+0 .. base+300 carry counts 1..6.
		pts := make([]string, 0, 6)
		for k := 0; k < 6; k++ {
			pts = append(pts, fmt.Sprintf(`[%d,"%d"]`, base.Unix()+int64(k*step), k+1))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"app":"nginx"},"values":[%s]}]}}`,
			strings.Join(pts, ","))
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `count_over_time({app="nginx"}[60s])`)
	params.Set("start", strconv.FormatInt(base.Unix()+step, 10))
	params.Set("end", strconv.FormatInt(base.Unix()+5*step, 10))
	params.Set("step", strconv.Itoa(step))
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// The upstream window opens one step BEFORE the client's start, so the
	// point at `start` has a bucket feeding it.
	if want := strconv.FormatInt(base.Unix(), 10); gotStart != want {
		t.Fatalf("upstream start = %q, want %q (client start minus one step)", gotStart, want)
	}
	// `end` keeps its legacy one-step extension; the extra bucket now maps
	// past `end` on the Loki grid and is clamped off below.
	if want := strconv.FormatInt(base.Unix()+6*step, 10); gotEnd != want {
		t.Fatalf("upstream end = %q, want %q", gotEnd, want)
	}

	var resp struct {
		Data struct {
			Result []struct {
				Values [][]interface{} `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Data.Result) != 1 {
		t.Fatalf("expected 1 series, got %d: %s", len(resp.Data.Result), rec.Body.String())
	}

	// Point base+k*step carries the count of bucket base+(k-1)*step, i.e. k.
	// The bucket at base+5*step would land at base+6*step, past `end`, and is
	// dropped.
	want := map[int64]string{}
	for k := 1; k <= 5; k++ {
		want[base.Unix()+int64(k*step)] = strconv.Itoa(k)
	}
	got := resp.Data.Result[0].Values
	if len(got) != len(want) {
		t.Fatalf("expected %d points, got %d: %v", len(want), len(got), got)
	}
	for _, pair := range got {
		ts := int64(pair[0].(float64))
		v := fmt.Sprintf("%v", pair[1])
		if w, ok := want[ts]; !ok {
			t.Fatalf("unexpected point at %d (offset %+ds from start): %v", ts, ts-base.Unix()-step, got)
		} else if v != w {
			t.Fatalf("point at base%+ds = %s, want %s (values are shifted by one step)", ts-base.Unix(), v, w)
		}
	}
}

// The pre-bucketed manual builder must select the same buckets as its sibling
// buildHitsRangeMetricMatrix: a VL bucket labelled `b` covers [b, b+step), so
// point `t` (LogQL window (t-window, t]) takes bucket starts in [t-window, t).
// The bucket AT `t` covers entries after `t` and belongs to the next point —
// counting it both over-counts the point and double-counts the bucket.
func TestManualRangeMetricMatrix_PreBucketedWindowExcludesBucketAtEvalTime(t *testing.T) {
	base := time.Unix(1700000040, 0).UTC()
	const step = 60 * time.Second
	window := 3 * step

	// Bucket base+k*step holds k+1 entries — every step distinct.
	samples := make([]rangeMetricSample, 0, 8)
	for k := 0; k < 8; k++ {
		samples = append(samples, rangeMetricSample{
			ts:    base.Add(time.Duration(k) * step).UnixNano(),
			value: float64(k + 1),
		})
	}
	series := map[string]manualSeriesSamples{
		`{app="nginx"}`: {Metric: map[string]string{"app": "nginx"}, Samples: samples},
	}

	start, end := base.Add(window), base.Add(6*step)
	out := buildManualRangeMetricMatrix("sum", 0, series, start, end, step, window, 0, true)

	var resp struct {
		Data struct {
			Result []struct {
				Values [][]interface{} `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Result) != 1 {
		t.Fatalf("expected 1 series, got %s", out)
	}

	for _, pair := range resp.Data.Result[0].Values {
		ts := int64(pair[0].(float64))
		k := (ts - base.Unix()) / int64(step/time.Second) // point index
		// Buckets k-3, k-2, k-1 → counts (k-2)+(k-1)+k.
		want := float64(3*k - 3)
		got, err := strconv.ParseFloat(fmt.Sprintf("%v", pair[1]), 64)
		if err != nil {
			t.Fatalf("value at base+%ds: %v", ts-base.Unix(), err)
		}
		if got != want {
			t.Fatalf("point base+%ds = %v, want %v (bucket at the eval time must not be counted)",
				ts-base.Unix(), got, want)
		}
	}
}

// A rate() panel routed through a high-cardinality Drilldown fast path must keep
// its `| math <count>/<window>` division. parseStatsCompatSpec reads the
// multi-stage rate pipeline as a plain `count`, so a path that rebuilds the query
// from that spec silently returns counts — rate × window seconds (measured ×300
// on topk(5, sum by (namespace) (rate({...}[5m]))) against Loki).
func TestQueryRange_RatePipelineIsNotServedByCountFastPath(t *testing.T) {
	if !isRateMathPipeline(`f:="x" | stats by (ns) count() as __lvp_inner | math __lvp_inner/300 as __lvp_rate | stats by (ns) sum(__lvp_rate)`) {
		t.Fatal("rate pipeline not recognised")
	}
	if isRateMathPipeline(`f:="x" | stats by (ns) count()`) {
		t.Fatal("plain count misread as a rate pipeline")
	}

	base := time.Unix(1700000040, 0).UTC()
	const step = 300
	var gotQueries []string
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotQueries = append(gotQueries, r.Form.Get("query"))
		w.Header().Set("Content-Type", "application/json")
		// One bucket, already divided by the window (VL evaluates the `| math`).
		_, _ = fmt.Fprintf(w,
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"namespace":"a"},"values":[[%d,"0.5"]]}]}}`,
			base.Unix())
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `topk(5, sum by (namespace) (rate({namespace=~".+"}[5m])))`)
	params.Set("start", strconv.FormatInt(base.Unix()+step, 10))
	params.Set("end", strconv.FormatInt(base.Unix()+6*3600, 10)) // > 2h: the high-card window path's floor
	params.Set("step", strconv.Itoa(step))
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil)
	req.Header.Set("X-Query-Tags", "Source=grafana-lokiexplore-app")
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, q := range gotQueries {
		if strings.Contains(q, "stats") && !strings.Contains(q, "| math ") {
			t.Fatalf("rate query lost its division — upstream query %q has no `| math` stage", q)
		}
	}
	if len(gotQueries) == 0 {
		t.Fatal("no upstream query issued")
	}
}

// An instant topk/bottomk over a regexp-extracted label must be served the same
// way its inner expression is served on its own. The compat layer reads the
// ORIGINAL LogQL off the request, so with the wrapper still in "query" it saw
// `topk` as the metric function: the query either came back 400 "unsupported
// instant aggregation target" or collapsed to a single unlabelled total.
func TestQueryInstant_TopKOverExtractedLabelKeepsGrouping(t *testing.T) {
	base := time.Unix(1700000040, 0).UTC()
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.URL.Path != "/select/logsql/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		// 1 line for repo "a", 2 for "b", 3 for "c" — distinct per group.
		for _, rep := range []string{"a", "b", "b", "c", "c", "c"} {
			// VL evaluates the `| extract_regexp` stage, so the rows come back
			// with the extracted field already on them.
			fmt.Fprintf(w, `{"_time":"%s","_msg":"path=/v2/%s/blobs/x","message":"path=/v2/%s/blobs/x","repo":"%s","_stream":"{app=\"trow\"}"}`+"\n",
				base.Add(30*time.Second).UTC().Format(time.RFC3339Nano), rep, rep, rep)
		}
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `topk(2, sum by (repo) (count_over_time({app="trow"} | json | line_format "{{ or .message __line__ }}" | regexp "/v2/(?P<repo>[^/]+)/blobs/" | repo != "" [5m])))`)
	params.Set("time", strconv.FormatInt(base.Add(5*time.Minute).Unix(), 10))
	rec := httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?"+params.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []interface{}     `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]string{}
	for _, s := range resp.Data.Result {
		got[s.Metric["repo"]] = fmt.Sprintf("%v", s.Value[1])
	}
	want := map[string]string{"b": "2", "c": "3"}
	if len(got) != len(want) {
		t.Fatalf("expected the top 2 repo series, got %v (%s)", got, rec.Body.String())
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("repo %q = %q, want %q (grouping lost under topk?): %v", k, got[k], v, got)
		}
	}
}

// `<expr> or vector(0)` is the Grafana idiom for "draw a zero instead of No
// data". The constant has no LogsQL equivalent, so the literal `vector(0)` was
// POSTed to VictoriaLogs as if it were a query and an empty left side came back
// as `result: []` — the panel showed "No data" where Loki draws a flat zero.
func TestQueryRange_OrVectorFillsEmptyResultWithConstant(t *testing.T) {
	base := time.Unix(1700000040, 0).UTC()
	const step = 60
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `sum(count_over_time({app="nginx"}[5m])) or vector(0)`)
	params.Set("start", strconv.FormatInt(base.Unix(), 10))
	params.Set("end", strconv.FormatInt(base.Unix()+3*step, 10))
	params.Set("step", strconv.Itoa(step))
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][]interface{}   `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Data.Result) != 1 || len(resp.Data.Result[0].Metric) != 0 {
		t.Fatalf("expected one unlabelled constant series, got %s", rec.Body.String())
	}
	if got := len(resp.Data.Result[0].Values); got != 4 {
		t.Fatalf("expected a zero at every one of the 4 steps, got %d: %s", got, rec.Body.String())
	}
	for _, pt := range resp.Data.Result[0].Values {
		if fmt.Sprintf("%v", pt[1]) != "0" {
			t.Fatalf("expected 0, got %v", pt[1])
		}
	}
}

// A failing upstream call must carry the translated LogsQL VERBATIM: a
// sha256 of the query cannot be pasted into VictoriaLogs, and reproducing a
// backend 400 was the slowest step of every field report. Successful calls stay
// quiet unless -log-translated-queries asks for them.
func TestUpstreamLog_CarriesFullLogsQLOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name          string
		status        int
		logTranslated bool
		wantQuery     bool
	}{
		{"backend 400", http.StatusBadRequest, false, true},
		{"backend 500", http.StatusInternalServerError, false, true},
		{"success, flag off", http.StatusOK, false, false},
		{"success, flag on", http.StatusOK, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			defer slog.SetDefault(orig)
			vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
			}))
			defer vlBackend.Close()

			p, err := New(Config{
				BackendURL:           vlBackend.URL,
				Cache:                cache.New(60*time.Second, 1000),
				LogLevel:             "debug",
				LogTranslatedQueries: tc.logTranslated,
			})
			if err != nil {
				t.Fatalf("create proxy: %v", err)
			}

			params := url.Values{}
			params.Set("query", `sum(count_over_time({app="nginx"}[5m]))`)
			params.Set("start", "1700000040")
			params.Set("end", "1700000340")
			params.Set("step", "60")
			p.handleQueryRange(httptest.NewRecorder(),
				httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))

			out := buf.String()
			if got := strings.Contains(out, "logsql.query=") && strings.Contains(out, "nginx"); got != tc.wantQuery {
				t.Fatalf("full LogsQL in the log = %v, want %v:\n%s", got, tc.wantQuery, out)
			}
			if strings.Contains(out, "logsql.query=sha256:") || strings.Contains(out, `"logsql.query":"sha256:`) {
				t.Fatalf("logsql.query is still a hash:\n%s", out)
			}
		})
	}
}

// The raw-row cap must be judged on what the query actually READS. A pipeline
// filter that VictoriaLogs can evaluate is pushed down with the selector, so a
// query whose filter matches nothing scans nothing — before this, only the
// leading line filters travelled and an EMPTY result came back as a 400.
func TestTemplatePipeline_PushesFiltersDownWithTheSelector(t *testing.T) {
	var gotQuery string
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotQuery = r.Form.Get("query")
		w.Header().Set("Content-Type", "application/x-ndjson")
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	params := url.Values{}
	params.Set("query", `{app="nginx"} | json | level=~"error|fatal" | line_format "{{.msg}}"`)
	params.Set("start", "1700000040000000000")
	params.Set("end", "1700000640000000000")
	params.Set("limit", "100")
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(gotQuery, "level") {
		t.Fatalf("the parser-stage filter was not pushed down: %q", gotQuery)
	}
}
