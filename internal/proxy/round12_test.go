package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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

	p := newSlidingTestProxy(t, vl.URL)
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
	newSlidingTestProxy(t, vl.URL).handleQueryRange(rec, req)
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
	p := newSlidingTestProxy(t, vl.URL)
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

// Round 12, class A, through the proxy: the pushed-down LogsQL reads the
// configured fields, and the template path's re-run of the filter keeps a row
// that VictoriaLogs matched in one of them.
func TestLineFilterFields_PushdownAndTemplatePath(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprint(w, `{"_time":"2023-11-14T22:13:30Z","_msg":"plain","_stream":"{app=\"a\"}","app":"a","Scopes":"[needle]"}`+"\n")
		fmt.Fprint(w, `{"_time":"2023-11-14T22:13:31Z","_msg":"plain","_stream":"{app=\"a\"}","app":"a","State.Foo":"needle"}`+"\n")
		fmt.Fprint(w, `{"_time":"2023-11-14T22:13:32Z","_msg":"plain","_stream":"{app=\"a\"}","app":"a","Category":"needle"}`+"\n")
	})
	p, err := New(Config{BackendURL: vl.URL, Cache: cache.New(60, 100), LogLevel: "error", LineFilterFields: []string{"_msg", "Scopes", "State.*"}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`{app="a"} |= "needle" | json | line_format "{{ or .x __line__ }}"`)+"&start=1700000000&end=1700000100&limit=10", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	want := `(~"needle" OR Scopes:~"needle" OR State.*:~"needle")`
	pushed := false
	for _, q := range seen() {
		pushed = pushed || strings.Contains(q, want)
	}
	if !pushed {
		t.Fatalf("pushdown must fan the filter out over the configured fields: %v", seen())
	}
	v, err := fj.ParseBytes(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	for _, s := range v.GetArray("data", "result") {
		lines += len(s.GetArray("values"))
	}
	if lines != 2 {
		t.Fatalf("the template path must keep the Scopes and State.Foo rows and drop the Category row, got %d lines: %s", lines, rec.Body.String())
	}
}

// Round 12, class B: a bare aggregation over no rows is an EMPTY vector in
// Loki; VictoriaLogs answers `{} 0` for count(), NaN for sum()/avg() and ""
// for min()/max()/quantile(). `or vector(0)` still yields its constant.
func TestInstant_EmptyAggregateIsEmptyVector(t *testing.T) {
	value := "0"
	vl, _ := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"count(*)"},"value":[1700007200,%q]}]}}`, value)
	})
	p := newSlidingTestProxy(t, vl.URL)
	run := func(logql string) string {
		rec := httptest.NewRecorder()
		p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+url.QueryEscape(logql)+"&time=1700007200", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", logql, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	if got := run(`sum(count_over_time({a="b"}[1h]))`); !strings.Contains(got, `"result":[]`) {
		t.Fatalf("count over no rows must be an empty vector, got %s", got)
	}
	if got := run(`sum(rate({a="b"}[1h]))`); !strings.Contains(got, `"result":[]`) {
		t.Fatalf("rate over no rows must be an empty vector, got %s", got)
	}
	if got := run(`sum(count_over_time({a="b"}[1h])) or vector(0)`); !strings.Contains(got, `"value":[1700007200,"0"]`) {
		t.Fatalf("or vector(0) must still answer its constant, got %s", got)
	}
	value = "NaN"
	if got := run(`sum(sum_over_time({a="b"} | unwrap x [1h]))`); !strings.Contains(got, `"result":[]`) {
		t.Fatalf("NaN over no rows must be an empty vector, got %s", got)
	}
	value = "0"
	if got := run(`sum(sum_over_time({a="b"} | unwrap x [1h]))`); !strings.Contains(got, `"value":[1700007200,"0"]`) {
		t.Fatalf("a sum of zeros over rows is a real 0, got %s", got)
	}
	value = "7"
	if got := run(`sum(count_over_time({a="b"}[1h]))`); !strings.Contains(got, `"value":[1700007200,"7"]`) {
		t.Fatalf("a real count must survive, got %s", got)
	}
}

// Round 12, class D: `[5m] offset 1h` at time t evaluates (t-1h-5m, t-1h] and
// is REPORTED at t. The proxy shifts the window before dispatch; the answer
// has to come back on the client's timestamps, not the shifted ones.
func TestOffset_ReportsAtClientTimestamps(t *testing.T) {
	// Step-grid-aligned bounds (Loki truncates a metric range query to the
	// step grid; 1700006400 is a multiple of 3600).
	const start, end, step = int64(1700006400), int64(1700013600), int64(3600)
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/stats_query") {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1700006400,"5"]}]}}`)
			return
		}
		fmt.Fprint(w, statsMatrixBody([]string{`{}`}, start-2*step, start-step, start, start+step))
	})
	p := newSlidingTestProxy(t, vl.URL)

	timestamps := func(logql string, s, e int64) []int64 {
		rec := httptest.NewRecorder()
		p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+url.QueryEscape(logql)+
			fmt.Sprintf("&start=%d&end=%d&step=%d", s, e, step), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d: %s", logql, rec.Code, rec.Body.String())
		}
		v, err := fj.ParseBytes(rec.Body.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, s := range v.GetArray("data", "result") {
			for _, pt := range s.GetArray("values") {
				out = append(out, int64(pt.GetFloat64("0")))
			}
		}
		return out
	}
	plain := timestamps(`sum(count_over_time({a="b"}[1h]))`, start-step, end-step)
	offset := timestamps(`sum(count_over_time({a="b"}[1h] offset 1h))`, start, end)
	if len(plain) == 0 || len(plain) != len(offset) {
		t.Fatalf("plain %v offset %v", plain, offset)
	}
	for i := range plain {
		if offset[i] != plain[i]+step {
			t.Fatalf("offset must report at t (plain window + 1h): plain %v offset %v", plain, offset)
		}
		if offset[i] < start || offset[i] > end {
			t.Fatalf("offset point %d outside the client's [%d, %d]", offset[i], start, end)
		}
	}
	// The local cache stores the CLIENT-time body: a hit is written before
	// the shifting writer exists.
	before := len(seen())
	if again := timestamps(`sum(count_over_time({a="b"}[1h] offset 1h))`, start, end); !reflect.DeepEqual(again, offset) {
		t.Fatalf("cached offset answer %v, first answer %v", again, offset)
	}
	if len(seen()) != before {
		t.Fatalf("second offset query reached VL (%d calls), expected a cache hit", len(seen())-before)
	}
	shiftedWindow := false
	for _, q := range seen() {
		shiftedWindow = shiftedWindow || strings.Contains(q, "stats_query_range")
	}
	if !shiftedWindow {
		t.Fatalf("no stats_query_range issued: %v", seen())
	}

	rec := httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+
		url.QueryEscape(`sum(count_over_time({a="b"}[1h] offset 1h))`)+"&time=1700010000", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"value":[1700010000,"5"]`) {
		t.Fatalf("instant: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

// Round 12, class C: a bare range aggregation over the template path keyed
// its series on every collector-unpacked field of the row (`Message`, the
// whole line, included), so each row was its own series, a per-series
// quantile was the sample itself and `max(quantile_over_time(0.5, …))` was the
// maximum. The identity is the stream labels plus what the LogQL pipeline
// produced: named parser fields, captures, label_format — minus drop/unwrap.
func TestBareRangeOverTemplate_IdentityIsWhatLokiProduces(t *testing.T) {
	vl, _ := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		for i, v := range []int{10, 20, 30} {
			fmt.Fprintf(w, `{"_time":"2023-11-14T22:13:%02dZ","_msg":"response sent duration_ms=%d","Message":"response sent duration_ms=%d","Category":"c%d","kubernetes.pod_labels.tier":"t","_stream":"{app=\"a\"}","app":"a"}`+"\n", 30+i, v, v, i)
		}
	})
	p := newSlidingTestProxy(t, vl.URL)
	q := `quantile_over_time(0.5, {app="a"} | json message="message" | line_format "{{ or .message __line__ }}" | drop message | regexp "duration_ms=(?P<duration_ms>\\d+)" | unwrap duration_ms [1m])`
	for _, tc := range []struct{ logql, want string }{
		{q, `{"metric":{"app":"a"},"value":[1700000060,"20"]}`},
		{"max(" + q + ")", `{"metric":{},"value":[1700000060,"20"]}`},
	} {
		rec := httptest.NewRecorder()
		p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+url.QueryEscape(tc.logql)+"&time=1700000060", nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), tc.want) {
			t.Fatalf("%s: HTTP %d %s\nwant %s", tc.logql, rec.Code, rec.Body.String(), tc.want)
		}
	}
	// A broad parser keeps the body fields, as Loki's `| json` would.
	rec := httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+
		url.QueryEscape(`quantile_over_time(0.5, {app="a"} | json | line_format "{{ or .message __line__ }}" | regexp "duration_ms=(?P<duration_ms>\\d+)" | unwrap duration_ms [1m])`)+"&time=1700000060", nil))
	if rec.Code != http.StatusOK || countLokiVectorSeries(rec.Body.Bytes()) != 3 {
		t.Fatalf("broad parser: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

func countLokiVectorSeries(body []byte) int {
	v, err := fj.ParseBytes(body)
	if err != nil {
		return -1
	}
	return len(v.GetArray("data", "result"))
}

// Round 12, class F: two Kubernetes pod labels that sanitise to the same Loki
// name (`airflow.spark-app-name` and `airflow_spark_app_name`) are ONE label
// to Loki's discovery. The inventory used to mark the alias ambiguous and the
// grouping went to a field that does not exist (one empty series for Loki's
// five); it is now a learned fallback chain, coalesced for the grouping.
func TestLearnedChain_CollidingLeafAliasesCoalesce(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/field_names"):
			fmt.Fprint(w, `{"values":[{"value":"_msg","hits":9},{"value":"kubernetes.pod_labels.airflow.spark-app-name","hits":3},{"value":"kubernetes.pod_labels.airflow_spark_app_name","hits":2}]}`)
		default:
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"airflow_spark_app_name":"build-site-metrics"},"value":[1700007200,"36"]}]}}`)
		}
	})
	p, err := New(Config{BackendURL: vl.URL, Cache: cache.New(60, 100), LogLevel: "error", LabelStyle: LabelStyleUnderscores})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+
		url.QueryEscape(`sum by (airflow_spark_app_name) (count_over_time({airflow_spark_app_name=~"build.*"}[1h]))`)+"&time=1700007200", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"airflow_spark_app_name":"build-site-metrics"}`) {
		t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
	}
	var logsql string
	for _, q := range seen() {
		if strings.Contains(q, "stats_query ") {
			logsql = q
		}
	}
	for _, want := range []string{
		`("kubernetes.pod_labels.airflow.spark-app-name":~"^(?:build.*)$" OR "kubernetes.pod_labels.airflow_spark_app_name":~"^(?:build.*)$")`,
		`| format if ("kubernetes.pod_labels.airflow_spark_app_name":*) "<kubernetes.pod_labels.airflow_spark_app_name>" as airflow_spark_app_name`,
		`| format if ("kubernetes.pod_labels.airflow.spark-app-name":*) "<kubernetes.pod_labels.airflow.spark-app-name>" as airflow_spark_app_name`,
		`| stats by (airflow_spark_app_name) count()`,
	} {
		if !strings.Contains(logsql, want) {
			t.Fatalf("LogsQL %q\nmust contain %s", logsql, want)
		}
	}
}

// A chain learned from one inventory is stale once a later inventory holds a
// single field for the alias: ToVLFields reads learnedChains first.
func TestLearnedChain_ForgottenWhenAliasBecomesSingleton(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	const alias = "airflow_spark_app_name"
	lt.LearnFieldAliases([]string{"kubernetes.pod_labels.airflow.spark-app-name", "kubernetes.pod_labels.airflow_spark_app_name"})
	if got := lt.ToVLFields(alias); len(got) != 2 {
		t.Fatalf("chain not learned: %v", got)
	}
	lt.LearnFieldAliases([]string{"kubernetes.pod_labels.airflow_spark_app_name"})
	if got := lt.ToVLFields(alias); got != nil {
		t.Fatalf("stale chain survived the singleton inventory: %v", got)
	}
	if got := lt.ToVL(alias); got != "kubernetes.pod_labels.airflow_spark_app_name" {
		t.Fatalf("ToVL = %q", got)
	}
}
