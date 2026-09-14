package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	fj "github.com/valyala/fastjson"
)

// Round 11, defect 4 — coprime range/step. The per-point fallback issues inner
// requests whose `start` is NOT on the step grid (start = t - range with t on
// the outer grid), and shiftStatsQRToLokiGrid subtracted the request offset a
// second time: VictoriaLogs already labels each bucket with its offset-shifted
// start (verified against v1.52.0: start=10:00:30, step=60s, offset=-30.000001s
// labels the bucket covering (09:59:30, 10:00:30] as 09:59:30.000001), so the
// point is L + step - epsilon regardless of alignment. With `start mod step`
// past half a step the round-to-grid snap then landed one full step early and
// the point carried the NEXT window's count — 115/224 wrong points on
// `[7m]`@97 (omicron flux-system, 11.09.2026), exactly the points with
// t mod 420 > 210.
func TestShiftStatsQRToLokiGrid_NonAlignedStart(t *testing.T) {
	const step = int64(420)
	for _, rem := range []int64{0, 97, 209, 211, 388, 419} {
		start := int64(1699999980) + rem // 1699999980 = 4047619*420, so start mod step == rem
		startRaw := fmt.Sprintf("%d", start)
		// What VictoriaLogs returns for buildLokiGridStatsParams(start, step): the
		// grid begins one step before start, every label is the real bucket start
		// plus the epsilon, and the value names the window the bucket covers.
		var buckets []string
		for k := int64(-1); k <= 2; k++ {
			label := start + k*step
			buckets = append(buckets, fmt.Sprintf(`[%d.000001,"w%d"]`, label, k+1))
		}
		body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[` +
			strings.Join(buckets, ",") + `]}]}}`)

		got := string(shiftStatsQRToLokiGrid(body, startRaw, "420s"))
		// The bucket labelled start-step+eps covers (start-step, start] and is the
		// point AT start; the next one is the point at start+step, and so on.
		for k := int64(0); k <= 3; k++ {
			want := fmt.Sprintf(`[%d,"w%d"]`, start+k*step, k)
			if !strings.Contains(got, want) {
				t.Errorf("rem=%d: point %s missing in %s", rem, want, got)
			}
		}
	}
}

// The evaluation timestamp is what the merge keys on, so the whole per-point
// contract in one number: with start ≡ rem (mod step) the point at start must
// be labelled start, never start-step.
func TestLokiGridOffsetNanos_IsNotAppliedTwice(t *testing.T) {
	start := time.Unix(1699999980+300, 0)
	off := lokiGridOffsetNanos(fmt.Sprintf("%d", start.Unix()), "420s")
	if off != 300*int64(time.Second)+lokiGridBucketEpsilonNanos {
		t.Fatalf("request offset = %d, want rem+epsilon", off)
	}
	label := start.Add(-420*time.Second).UnixNano() + lokiGridBucketEpsilonNanos
	body := []byte(fmt.Sprintf(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[%d.000001,"1"]]}]}}`,
		label/int64(time.Second)))
	got := string(shiftStatsQRToLokiGrid(body, fmt.Sprintf("%d", start.Unix()), "420s"))
	if !strings.Contains(got, fmt.Sprintf(`[%d,"1"]`, start.Unix())) {
		t.Fatalf("point relabelled to %s, want %d", got, start.Unix())
	}
}

// ─── defect 1: the template log path carries the request's own limit ────────

func newRecordingVL(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, query string)) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		q := r.FormValue("query")
		mu.Lock()
		queries = append(queries, r.URL.Path+" "+q)
		mu.Unlock()
		handler(w, r, q)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), queries...)
	}
}

func TestTemplateLogPath_PushesTheRequestLimit(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
	})
	p := newGapTestProxy(t, vl.URL)
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`{app="nginx"} | json | line_format "{{.x}}"`)+"&start=1700000000&end=1700003600&limit=37", nil)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	got := seen()
	if len(got) != 1 || !strings.Contains(got[0], "| sort by (_time desc) limit 37") || strings.Contains(got[0], "1000001") {
		t.Fatalf("the template log path must bound the sort to the request limit, got %q", got)
	}
}

// A proxy-side stage that DROPS entries cannot be answered from `limit` raw
// rows alone: the bound grows (×8, never past the raw-row cap) only while the
// page came back full and fewer than `limit` entries survived.
func TestTemplateLogPath_GrowsTheBoundOnlyWhenTheSuffixDropsRows(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, q string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		rows := 0
		if i := strings.LastIndex(q, "limit "); i >= 0 {
			rows, _ = strconv.Atoi(strings.TrimSpace(q[i+6:]))
		}
		if rows > 37 {
			rows = 3 // the second page is short: the match is exhausted
		}
		for i := 0; i < rows; i++ {
			fmt.Fprintf(w, `{"_time":"2023-11-14T22:13:%02dZ","_msg":"{\"level\":\"info\"}","_stream":"{app=\"a\"}","app":"a"}`+"\n", i%60)
		}
	})
	p := newGapTestProxy(t, vl.URL)
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`{app="a"} | json | line_format "{{.x}}" | level="error"`)+"&start=1700000000&end=1700003600&limit=37", nil)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	got := seen()
	if len(got) != 2 || !strings.HasSuffix(got[0], "limit 37") || !strings.HasSuffix(got[1], "limit 296") {
		t.Fatalf("want limit 37 then limit 296, got %q", got)
	}
}

// ─── defect 2: the series cap is an error, not a silent trim ───────────────

func statsQRWithSeries(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"status":"success","data":{"resultType":"matrix","result":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"metric":{"pod":"p%d"},"values":[[1700000060.000001,"%d"]]}`, i, i+1)
	}
	sb.WriteString(`]}}`)
	return []byte(sb.String())
}

func TestSeriesCap_RefusesInsteadOfTrimming(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
		step  string
	}{
		{"direct stats path", `sum by (pod) (count_over_time({app="a"}[60s]))`, "60"},
		{"sliding-window stats path", `sum by (pod) (count_over_time({app="a"}[5m]))`, "60"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vl, _ := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(statsQRWithSeries(501))
			})
			p := newGapTestProxy(t, vl.URL)
			// Distinct ranges per request: the response cache would otherwise
			// answer the later requests with the first one's body.
			target := "/loki/api/v1/query_range?query=" + url.QueryEscape(tc.query) + "&start=1700000000&end=1700000600&step=" + tc.step
			targetDrilldown := strings.Replace(target, "end=1700000600", "end=1700000660", 1)
			targetRaised := strings.Replace(target, "end=1700000600", "end=1700000720", 1)

			rec := httptest.NewRecorder()
			p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "maximum of series (500) reached for a single query") {
				t.Fatalf("501 series over a cap of 500 must be Loki's 400, got %d: %s", rec.Code, rec.Body.String())
			}

			// Drilldown gets the busiest N and a Warning header, as Loki does.
			req := httptest.NewRequest(http.MethodGet, targetDrilldown, nil)
			req.Header.Set("X-Query-Tags", "Source=grafana-lokiexplore-app")
			rec = httptest.NewRecorder()
			p.handleQueryRange(rec, req)
			if tc.name == "direct stats path" {
				if rec.Code != http.StatusOK || countLokiMatrixSeries(rec.Body.Bytes()) != 500 || !strings.Contains(rec.Header().Get("Warning"), "maximum of series") {
					t.Fatalf("drilldown: want 200 with 500 series and a Warning, got %d (%d series, Warning=%q)", rec.Code, countLokiMatrixSeries(rec.Body.Bytes()), rec.Header().Get("Warning"))
				}
			}

			// The cap is configurable per deployment.
			p.maxStatsQuerySeries = 1000
			rec = httptest.NewRecorder()
			p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, targetRaised, nil))
			if rec.Code != http.StatusOK || countLokiMatrixSeries(rec.Body.Bytes()) != 501 {
				t.Fatalf("with -max-stats-query-series=1000 all 501 series must come back, got %d (%d series)", rec.Code, countLokiMatrixSeries(rec.Body.Bytes()))
			}
		})
	}
}

// ─── defect 5: sum(rate()) over a sliding window pools into {} ─────────────

func TestSumRate_SlidingWindowPoolsIntoOneSeries(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{},"values":[[1700000060.000001,"6"],[1700000120.000001,"12"]]}]}}`))
	})
	p := newGapTestProxy(t, vl.URL)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`sum(rate({app="a"}[10m]))`)+"&start=1700000000&end=1700000600&step=60", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	v, err := fj.ParseBytes(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result := v.GetArray("data", "result")
	if len(result) != 1 || len(result[0].GetObject("metric").String()) > 2 {
		t.Fatalf("sum() without by() is ONE series with no labels, got %s", rec.Body.String())
	}
	for _, q := range seen() {
		if strings.Contains(q, "/select/logsql/query ") {
			t.Fatalf("a bare sum(rate()) must not fall into the raw-row scan: %s", q)
		}
		if strings.Contains(q, "by (_stream") {
			t.Fatalf("the translator's default inner grouping leaked into the backend query: %s", q)
		}
	}
}

// ─── defect 6: label_format with a pure field alias stays pushed down ───────

func TestLabelFormatAlias_IsPushedDownAsFormat(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{"lf":"info"},"values":[[1700003600.000001,"6"]]},{"metric":{},"values":[[1700003600.000001,"2"]]}]}}`))
	})
	p := newGapTestProxy(t, vl.URL)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape("sum by (lf) (count_over_time({app=\"a\"} | json | label_format lf=`{{ .level }}` [1h]))")+"&start=1700000000&end=1700007200&step=3600", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	got := seen()
	for _, q := range got {
		if strings.Contains(q, "/select/logsql/query ") {
			t.Fatalf("a pure field alias must not force the raw-row read: %q", got)
		}
	}
	if len(got) == 0 || !strings.Contains(got[0], `| format "<level>" as lf`) || !strings.Contains(got[0], "stats by (lf)") {
		t.Fatalf("want the alias as a LogsQL format pipe under stats by (lf), got %q", got)
	}
}

// The metric fold reads every row anyway and is order-insensitive, so it must
// not ask VictoriaLogs for a sort — `sort by (_time desc) limit 1000001` is a
// million-row top-N heap and the 400 "requires more than 1310MB".
func TestTemplateMetricPath_ReadsUnsorted(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
	})
	p := newGapTestProxy(t, vl.URL)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`sum by (x) (count_over_time({app="a"} | json | line_format "{{ or .x __line__ }}" | regexp "(?P<x>\\d+)" [1h]))`)+"&start=1700000000&end=1700007200&step=3600", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	got := seen()
	if len(got) == 0 {
		t.Fatal("no backend request")
	}
	for _, q := range got {
		if strings.Contains(q, "sort by") {
			t.Fatalf("metric fold must read unsorted: %s", q)
		}
	}
}

// ─── defect 7: a bare range aggregation over a template pipeline ────────────

func TestBareParserRoute_DeclinesTemplatePipelines(t *testing.T) {
	trow := `max_over_time({namespace="trow-system", container="trow"} |= "response sent" | json message="message" | line_format "{{ or .message __line__ }}" | drop __error__, __error_details__ | regexp "duration_ms.*?=\\x1b\\[0m(?P<duration_ms>\\d+)" | unwrap duration_ms [10m])`
	if _, ok := parseBareParserMetricCompatSpec(trow); ok {
		t.Fatal("a template pipeline must go to the template route, not the bare-parser stats route")
	}
	if _, ok := parseBareParserMetricCompatSpec(`max_over_time({a="b"} | json | unwrap x [10m])`); !ok {
		t.Fatal("a plain parser pipeline keeps the bare-parser route")
	}
}

func TestBareUnwrapOverTemplate_KeepsParsedLabelsDropsUnwrapField(t *testing.T) {
	vl, _ := newRecordingVL(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprint(w, `{"_time":"2023-11-14T22:13:30Z","_msg":"{\"message\":\"response sent duration_ms=12\",\"k\":\"v\"}","_stream":"{app=\"a\"}","app":"a"}`+"\n")
		fmt.Fprint(w, `{"_time":"2023-11-14T22:13:40Z","_msg":"{\"message\":\"response sent duration_ms=30\",\"k\":\"v\"}","_stream":"{app=\"a\"}","app":"a"}`+"\n")
	})
	p := newGapTestProxy(t, vl.URL)
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+
		url.QueryEscape(`max_over_time({app="a"} | json message="message" | line_format "{{ or .message __line__ }}" | regexp "duration_ms=(?P<duration_ms>\d+)" | unwrap duration_ms [1m])`)+
		"&start=1700000000&end=1700000120&step=60", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	v, err := fj.ParseBytes(rec.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	result := v.GetArray("data", "result")
	if len(result) != 2 {
		t.Fatalf("Loki keys a bare range aggregation by every parsed label (two distinct messages -> two series), got %s", rec.Body.String())
	}
	for _, s := range result {
		m := s.GetObject("metric")
		if m.Get("message") == nil {
			t.Fatalf("parsed labels missing from the identity: %s", m.String())
		}
		if m.Get("duration_ms") != nil {
			t.Fatalf("the unwrapped label must leave the identity: %s", m.String())
		}
	}
}
