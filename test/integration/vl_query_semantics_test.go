//go:build integration

// This file is the regression harness for the query-semantics defects found by
// running real Grafana dashboards through the deployed proxy. Every assertion
// here runs against a REAL VictoriaLogs with ingested fixtures whose correct
// answer is known by construction — unit tests over synthetic JSON passed while
// these same queries were wrong end to end, because the defects lived in which
// aggregation path the proxy selected and in what VL was actually asked.
//
// Requires a VictoriaLogs reachable at VL_URL (default http://localhost:9428):
//
//	docker run -d --name vl-test -p 9428:9428 victoriametrics/victoria-logs:v1.52.0
//	GOWORK=off go test -tags=integration ./test/integration/ -run TestVLQuerySemantics -count=1 -v
//
// The suite skips (does not fail) when no VL is reachable, so the tagged run
// stays usable on a machine without Docker.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// vlSemanticsFlags mirrors the flag set the Grafana datasource
// tp-us-omicron-lw-kube-common-loki runs against in us-omicron, so the paths
// under test are the deployed ones (derived level, computed job label, mapped
// kubernetes.* fields, _msg as the log line).
func vlSemanticsFlags() []string {
	return []string{
		"-label-style=underscores",
		"-translate-otel-attributes=false",
		"-metadata-field-mode=hybrid",
		"-line-field=_msg",
		`-computed-labels=[{"loki_label":"job","join":["namespace","app"],"sep":"/"}]`,
		"-derived-level-fields=loglevel,LogLevel,level,Level,severity,severity_text,lvl",
		"-derived-level-group-by=true",
		`-field-mapping=[` +
			`{"vl_field":"kubernetes.pod_namespace","loki_label":"namespace"},` +
			`{"vl_field":"kubernetes.container_name","loki_label":"container"},` +
			`{"vl_field":"kubernetes.pod_name","loki_label":"pod"},` +
			`{"vl_field":"kubernetes.pod_node_name","loki_label":"node_name"},` +
			`{"vl_fields":["kubernetes.pod_labels.app","kubernetes.pod_labels.app.kubernetes.io/name"],"loki_label":"app"},` +
			`{"vl_fields":["kubernetes.pod_labels.product","kubernetes.namespace_labels.product"],"loki_label":"product"}` +
			`]`,
		// Keep every request honest: no cached or coalesced answer can mask a
		// wrong aggregation path.
		"-cache-disabled",
		"-coalescer-disabled",
		"-compat-cache-enabled=false",
	}
}

func vlURL() string {
	if u := strings.TrimSpace(os.Getenv("VL_URL")); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:9428"
}

// requireVL skips the suite unless a VictoriaLogs answers /health.
func requireVL(t *testing.T) string {
	t.Helper()
	base := vlURL()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/health")
	if err != nil {
		t.Skipf("no VictoriaLogs at %s (%v); start one with: docker run -d -p 9428:9428 victoriametrics/victoria-logs:v1.52.0", base, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("VictoriaLogs at %s returned %d for /health", base, resp.StatusCode)
	}
	return base
}

// vlRecord is one VictoriaLogs entry shaped like the pod logs the us clusters
// ingest: kubernetes.* stream fields plus the application's own JSON in _msg.
type vlRecord struct {
	tsOffset  time.Duration // relative to the ingest instant, negative = in the past
	namespace string
	pod       string
	container string
	app       string
	msg       map[string]interface{} // marshalled into _msg
	extra     map[string]string      // additional top-level VL fields
}

func (r vlRecord) marshal(now time.Time) (string, error) {
	msgBytes, err := json.Marshal(r.msg)
	if err != nil {
		return "", err
	}
	rec := map[string]string{
		"_time":                     now.Add(r.tsOffset).UTC().Format(time.RFC3339Nano),
		"_msg":                      string(msgBytes),
		"kubernetes.pod_namespace":  r.namespace,
		"kubernetes.pod_name":       r.pod,
		"kubernetes.container_name": r.container,
		"kubernetes.pod_node_name":  "node-1",
		"kubernetes.pod_labels.app": r.app,

		"kubernetes.pod_labels.product": "prod",
	}
	// An empty app means "this pod carries no `app` pod-label at all" — the
	// record then only reaches the `app` Loki label through a later field in the
	// -field-mapping fallback chain, which is the case S6 is about.
	if r.app == "" {
		delete(rec, "kubernetes.pod_labels.app")
	}
	for k, v := range r.extra {
		rec[k] = v
	}
	out, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ingest pushes records into VL and waits until they are queryable.
//
// The Content-Type header is required: VictoriaLogs answers /insert/jsonline
// with 200 and silently ingests ZERO rows when it is absent, which is exactly
// the shape of a test that passes while asserting nothing.
func ingest(t *testing.T, base string, records []vlRecord, now time.Time) {
	t.Helper()

	var body strings.Builder
	for _, r := range records {
		line, err := r.marshal(now)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}

	params := url.Values{}
	params.Set("_time_field", "_time")
	params.Set("_msg_field", "_msg")
	params.Set("_stream_fields", "kubernetes.pod_namespace,kubernetes.pod_name,kubernetes.container_name")

	req, err := http.NewRequest(http.MethodPost,
		base+"/insert/jsonline?"+params.Encode(), strings.NewReader(body.String()))
	if err != nil {
		t.Fatalf("build insert request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("insert returned %d: %s", resp.StatusCode, respBody)
	}

	// VL makes freshly ingested data queryable asynchronously, and the two
	// endpoints the proxy uses do NOT become ready together: a time-bounded
	// `| stats count()` already returns the full count while the RAW-ROW
	// endpoint (/select/logsql/query, which the proxy's manual aggregation path
	// reads) still returns nothing. Polling on stats alone therefore declares
	// the data ready too early, and every manual-path query in the suite comes
	// back with zero series — or NaN for rate — with nothing wrong in the code.
	//
	// So poll BOTH endpoints, with the same time bounds the tests use, per
	// namespace, deriving the expected counts from the fixture so they cannot
	// drift from it.
	windowStart := now.Add(-readinessWindow)
	wantRows := rowsPerNamespaceInWindow(records, now, readinessWindow)
	wantLevel := levelRowsPerNamespaceInWindow(records, now, readinessWindow)

	deadline := time.Now().Add(30 * time.Second)
	for {
		ready := true
		for ns, want := range wantRows {
			sel := fmt.Sprintf(`"kubernetes.pod_namespace":=%q`, ns)
			if vlCountInWindow(t, base, sel, windowStart, now) < want {
				ready = false
				break
			}
			// The raw-row endpoint is the strict gate: it lags stats.
			if vlRawRowsInWindow(t, base, sel, windowStart, now) < want {
				ready = false
				break
			}
			// Rows carrying a loglevel field must also be reachable BY that
			// field before the derived-level paths can group on it.
			if n := wantLevel[ns]; n > 0 &&
				vlCountInWindow(t, base, sel+" loglevel:*", windowStart, now) < n {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		if time.Now().After(deadline) {
			var got []string
			for ns, want := range wantRows {
				sel := fmt.Sprintf(`"kubernetes.pod_namespace":=%q`, ns)
				got = append(got, fmt.Sprintf("%s: stats %d/%d, raw rows %d/%d, loglevel %d/%d",
					ns, vlCountInWindow(t, base, sel, windowStart, now), want,
					vlRawRowsInWindow(t, base, sel, windowStart, now), want,
					vlCountInWindow(t, base, sel+" loglevel:*", windowStart, now), wantLevel[ns]))
			}
			sort.Strings(got)
			t.Fatalf("ingest: data not queryable in [%s, %s] after 30s\n  %s",
				windowStart.Format(time.RFC3339), now.Format(time.RFC3339),
				strings.Join(got, "\n  "))
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// readinessWindow is the lookback the readiness poll (and every range window in
// the suite) uses. Fixture rows deliberately placed outside it are excluded
// from the expected counts.
const readinessWindow = time.Hour

func rowsPerNamespaceInWindow(records []vlRecord, now time.Time, window time.Duration) map[string]int {
	out := make(map[string]int)
	for _, r := range records {
		if r.tsOffset >= -window && r.tsOffset <= 0 {
			out[r.namespace]++
		} else {
			// Ensure out-of-window-only namespaces still appear with 0 so the
			// map key set matches the fixture.
			if _, ok := out[r.namespace]; !ok {
				out[r.namespace] = 0
			}
		}
	}
	return out
}

func levelRowsPerNamespaceInWindow(records []vlRecord, now time.Time, window time.Duration) map[string]int {
	out := make(map[string]int)
	for _, r := range records {
		if r.extra["loglevel"] != "" && r.tsOffset >= -window && r.tsOffset <= 0 {
			out[r.namespace]++
		}
	}
	return out
}

// vlRawRowsInWindow counts the rows VL returns from /select/logsql/query — the
// raw-row endpoint the proxy's manual aggregation path reads — for [start, end].
// This is the readiness signal that actually matters for those queries.
func vlRawRowsInWindow(t *testing.T, base, query string, start, end time.Time) int {
	t.Helper()
	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	params.Set("limit", "1000000")

	resp, err := http.PostForm(base+"/select/logsql/query", params)
	if err != nil {
		t.Fatalf("vl raw rows: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	n := 0
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// vlCountInWindow is vlCount constrained to [start, end], matching how the
// proxy queries VL for a range-window aggregation.
func vlCountInWindow(t *testing.T, base, query string, start, end time.Time) int {
	t.Helper()
	params := url.Values{}
	params.Set("query", query+" | stats count()")
	params.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	return vlCountWithParams(t, base, params)
}

// vlCount runs `<query> | stats count()` straight against VL, bypassing the
// proxy. This is the independent ground truth every proxy assertion is checked
// against — if it and the proxy disagree, the proxy is wrong.
func vlCount(t *testing.T, base, query string) int {
	t.Helper()
	params := url.Values{}
	params.Set("query", query+" | stats count()")
	return vlCountWithParams(t, base, params)
}

func vlCountWithParams(t *testing.T, base string, params url.Values) int {
	t.Helper()
	resp, err := http.PostForm(base+"/select/logsql/query", params)
	if err != nil {
		t.Fatalf("vl count: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	line := strings.TrimSpace(string(body))
	if line == "" {
		return 0
	}
	var row map[string]string
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		t.Fatalf("vl count: decode %q: %v", line, err)
	}
	n, err := strconv.Atoi(row["count(*)"])
	if err != nil {
		t.Fatalf("vl count: parse %q: %v", row["count(*)"], err)
	}
	return n
}

// lokiSeries is one decoded series of a Loki vector/matrix response.
type lokiSeries struct {
	Metric map[string]string `json:"metric"`
	Value  []interface{}     `json:"value"`
	Values [][]interface{}   `json:"values"`
}

type lokiResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string       `json:"resultType"`
		Result     []lokiSeries `json:"result"`
	} `json:"data"`
}

// queryInstant runs a LogQL instant query through the proxy.
func queryInstant(t *testing.T, p *proxyProc, logql string, at time.Time) lokiResponse {
	t.Helper()
	params := url.Values{}
	params.Set("query", logql)
	params.Set("time", strconv.FormatInt(at.Unix(), 10))
	return doLokiQuery(t, "http://"+p.listenAddr+"/loki/api/v1/query", params)
}

// queryRange runs a LogQL range query through the proxy with a single step
// covering the whole window, so one bucket per series makes the expected
// numbers unambiguous.
func queryRange(t *testing.T, p *proxyProc, logql string, start, end time.Time, step time.Duration) lokiResponse {
	t.Helper()
	params := url.Values{}
	params.Set("query", logql)
	params.Set("start", strconv.FormatInt(start.Unix(), 10))
	params.Set("end", strconv.FormatInt(end.Unix(), 10))
	params.Set("step", strconv.Itoa(int(step.Seconds())))
	return doLokiQuery(t, "http://"+p.listenAddr+"/loki/api/v1/query_range", params)
}

func doLokiQuery(t *testing.T, endpoint string, params url.Values) lokiResponse {
	t.Helper()
	resp, err := http.PostForm(endpoint, params)
	if err != nil {
		t.Fatalf("query %s: %v", params.Get("query"), err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	var out lokiResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("query %s: decode response: %v\nbody: %s", params.Get("query"), err, body)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query %s: HTTP %d: %s", params.Get("query"), resp.StatusCode, body)
	}
	if out.Status != "success" {
		t.Fatalf("query %s: status %q error %q\nbody: %s",
			params.Get("query"), out.Status, out.Error, body)
	}
	return out
}

// scalarByLabels reduces a vector response to {canonical label set -> value}.
func scalarByLabels(t *testing.T, resp lokiResponse) map[string]string {
	t.Helper()
	out := make(map[string]string, len(resp.Data.Result))
	for _, s := range resp.Data.Result {
		var val string
		switch {
		case len(s.Value) >= 2:
			val, _ = s.Value[1].(string)
		case len(s.Values) >= 1 && len(s.Values[len(s.Values)-1]) >= 2:
			// Range response: take the last bucket.
			val, _ = s.Values[len(s.Values)-1][1].(string)
		default:
			t.Fatalf("series %v carries no sample", s.Metric)
		}
		out[canonicalLabels(s.Metric)] = val
	}
	return out
}

// canonicalLabels renders a label set as a stable, comparable string.
func canonicalLabels(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// trowFixture reproduces the shape that produced wrong counts with a parser
// pipeline. 16 rows in one stream, with counts known by construction:
//
//	16 total in the stream
//	 6 match |= "response sent" AND |= "/v2/"
//	 4 of those 6 are non-2xx        <- the full pipeline's answer
//	10 of the 16 are non-2xx         <- answer with the |= filters removed
//
// Six extra rows sit 3 hours in the past and match the full pipeline too, so a
// query that fails to constrain VL to the [time-1h, time] window over-counts
// 4 -> 10 instead of quietly returning a plausible number.
func trowFixture(ns string) []vlRecord {
	rec := func(off time.Duration, message string, status int) vlRecord {
		return vlRecord{
			tsOffset:  off,
			namespace: ns,
			pod:       "trow-0",
			container: "trow",
			app:       "trow",
			msg: map[string]interface{}{
				"message":  message,
				"status":   status,
				"Duration": 10.0,
			},
		}
	}

	var out []vlRecord
	// In window: "response sent" + "/v2/", 2xx -> excluded by status !~ "2..".
	for i := 0; i < 2; i++ {
		out = append(out, rec(-10*time.Minute+time.Duration(i)*time.Second,
			"response sent for /v2/_catalog", 200))
	}
	// In window: "response sent" + "/v2/", non-2xx -> the 4 the query wants.
	for i, st := range []int{404, 500, 401, 403} {
		out = append(out, rec(-9*time.Minute+time.Duration(i)*time.Second,
			"response sent for /v2/blobs", st))
	}
	// In window: "response sent" only (no "/v2/"), 2xx.
	for i := 0; i < 4; i++ {
		out = append(out, rec(-8*time.Minute+time.Duration(i)*time.Second,
			"response sent for /healthz", 200))
	}
	// In window: "/v2/" only (no "response sent"), non-2xx.
	for i := 0; i < 3; i++ {
		out = append(out, rec(-7*time.Minute+time.Duration(i)*time.Second,
			"got request /v2/tags", 301))
	}
	// In window: neither filter, non-2xx.
	for i := 0; i < 3; i++ {
		out = append(out, rec(-6*time.Minute+time.Duration(i)*time.Second,
			"idle tick", 600))
	}
	// OUT of the [1h] window but matching the full pipeline: these must never
	// be counted by a [1h] query.
	for i, st := range []int{404, 500, 502, 503, 401, 403} {
		out = append(out, rec(-3*time.Hour-time.Duration(i)*time.Second,
			"response sent for /v2/old", st))
	}
	return out
}

// levelFixture provides a known level distribution, per-namespace Duration
// values, and a deliberate tie in per-app counts.
//
// Counts are derived by construction (apps alternate within each level group):
//
//	main  error=5 warn=3 info=7  -> 15 rows; app svc-a=9, svc-b=6
//	slow  info=4                 ->  4 rows; app svc-c=4, Durations 100..400
//	tie   info=9                 ->  9 rows; app svc-d=9  (ties with svc-a)
//
// The svc-d tie exists so count_values() can be asserted end to end on the
// case that distinguishes it from "group by a field": two input series sharing
// one value must collapse into a single bucket of 2.
//
// The three namespace names must NOT be prefixes of one another: a Loki regex
// matcher like {namespace=~"appx-1(-b)?"} reaches VL as an unanchored `~`
// match, so a "-b" sibling of the same prefix leaks into the result set and
// silently changes the expected counts.
func levelFixture(main, slow, tie string) []vlRecord {
	var out []vlRecord
	for _, lvl := range []struct {
		name string
		n    int
	}{{"error", 5}, {"warn", 3}, {"info", 7}} {
		for i := 0; i < lvl.n; i++ {
			app := "svc-a"
			if i%2 == 1 {
				app = "svc-b"
			}
			out = append(out, vlRecord{
				tsOffset:  -20*time.Minute + time.Duration(len(out))*time.Second,
				namespace: main,
				pod:       fmt.Sprintf("%s-%d", main, i%2),
				container: "main",
				app:       app,
				msg: map[string]interface{}{
					"message":  fmt.Sprintf("hello %s %d", lvl.name, i),
					"Duration": float64(10 * (i + 1)),
					"level":    lvl.name,
				},
				extra: map[string]string{"loglevel": lvl.name},
			})
		}
	}
	for i := 0; i < 4; i++ {
		out = append(out, vlRecord{
			tsOffset:  -15*time.Minute + time.Duration(i)*time.Second,
			namespace: slow,
			pod:       slow + "-0",
			container: "main",
			app:       "svc-c",
			msg: map[string]interface{}{
				"message":  fmt.Sprintf("y %d", i),
				"Duration": float64(100 * (i + 1)),
				"level":    "info",
			},
			extra: map[string]string{"loglevel": "info"},
		})
	}
	for i := 0; i < 9; i++ {
		out = append(out, vlRecord{
			tsOffset:  -12*time.Minute + time.Duration(i)*time.Second,
			namespace: tie,
			pod:       tie + "-0",
			container: "main",
			app:       "svc-d",
			msg: map[string]interface{}{
				"message":  fmt.Sprintf("z %d", i),
				"Duration": float64(5 * (i + 1)),
				"level":    "info",
			},
			extra: map[string]string{"loglevel": "info"},
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestVLQuerySemantics is one test with subtests on purpose: all fixtures are
// ingested once and every subtest shares a single proxy. Per-test ingestion
// raced VL's asynchronous row and field indexing, which showed up as whole
// subtests returning zero series — a flaky harness masquerading as a defect.
func TestVLQuerySemantics(t *testing.T) {
	base := requireVL(t)
	now := time.Now()

	// One suffix per run keeps repeated runs (and any leftover data in a
	// long-lived VL) out of these known answers.
	runID := now.UnixNano()
	trowNS := fmt.Sprintf("trow-%d", runID)
	mainNS := fmt.Sprintf("appmain-%d", runID)
	slowNS := fmt.Sprintf("appslow-%d", runID)
	tieNS := fmt.Sprintf("apptie-%d", runID)

	chainNS := fmt.Sprintf("appchain-%d", runID)

	records := append(trowFixture(trowNS), levelFixture(mainNS, slowNS, tieNS)...)
	records = append(records, chainFallbackFixture(chainNS)...)
	ingest(t, base, records, now)

	// LVP_TEST_PROXY_LOG=1 makes the proxy log every translated LogsQL query and
	// dumps its log at the end of the run. The defects this suite covers are all
	// "which aggregation path ran, and what did it ask VL", which is unanswerable
	// from the HTTP response alone.
	flags := vlSemanticsFlags()
	debugProxy := os.Getenv("LVP_TEST_PROXY_LOG") != ""
	if debugProxy {
		flags = append(flags, "-log-level=debug", "-debug-log-raw-queries")
	}
	p := startProxyWithBackendURL(t, base, flags...)
	if debugProxy {
		t.Cleanup(func() { fmt.Fprintf(os.Stderr, "proxy log:\n%s\n", p.stdout.String()) })
	}

	t.Run("PipelineCounts", func(t *testing.T) {
		testPipelineCounts(t, base, p, trowNS, now)
	})
	t.Run("InstantGrouping", func(t *testing.T) {
		testInstantGrouping(t, p, mainNS, slowNS, now)
	})
	t.Run("CountValues", func(t *testing.T) {
		testCountValues(t, p, mainNS, tieNS, now)
	})
	t.Run("JSONLineFormat", func(t *testing.T) {
		testJSONLineFormat(t, p, slowNS, now)
	})
	t.Run("PanelCompareDefects", func(t *testing.T) {
		testPanelCompareDefects(t, base, p, mainNS, chainNS, now)
	})
	t.Run("LabelMatcherAnchoring", func(t *testing.T) {
		testLabelMatcherAnchoring(t, p, mainNS, tieNS, now)
	})
}

// testPipelineCounts asserts that a parser pipeline does not change the count
// an aggregation reports, and in particular that the range window is honoured
// when the pipeline is present. Each expectation is first re-derived from VL
// directly, so the test cannot drift from the fixture.
func testPipelineCounts(t *testing.T, base string, p *proxyProc, ns string, now time.Time) {
	sel := fmt.Sprintf(`{namespace=%q,container="trow"}`, ns)
	vlSel := fmt.Sprintf(`"kubernetes.pod_namespace":=%q "kubernetes.container_name":="trow"`, ns)

	// Ground truth straight from VL, so the numbers below are measured and not
	// transcribed from the fixture comment.
	if got := vlCount(t, base, vlSel); got != 22 {
		t.Fatalf("fixture: VL sees %d rows in %s, want 22", got, ns)
	}
	if got := vlCount(t, base, vlSel+` "response sent" "/v2/"`); got != 12 {
		t.Fatalf("fixture: VL sees %d matching rows (all time), want 12", got)
	}

	tests := []struct {
		name  string
		logql string
		want  string
	}{
		{
			// The reported defect: with the full pipeline the proxy returned 83
			// where the pipeline-free superset was 16. The out-of-window rows in
			// the fixture make an unconstrained scan return 10 instead of 4.
			name: "full pipeline honours window and filters",
			logql: `sum(count_over_time(` + sel +
				` |= "response sent" |= "/v2/" | json | drop __error__,__error_details__` +
				` | regexp "(?P<status>[0-9]{3})" | status !~ "2.." [1h]))`,
			want: "4",
		},
		{
			name:  "no pipeline is the superset",
			logql: `sum(count_over_time(` + sel + `[1h]))`,
			want:  "16",
		},
		{
			// drop-error only: takes VL's native stats path.
			name: "drop stage alone",
			logql: `sum(count_over_time(` + sel +
				` |= "response sent" |= "/v2/" | json | drop __error__,__error_details__ [1h]))`,
			want: "6",
		},
		{
			// regexp + label filter without drop: takes the manual path.
			name: "regexp stage alone",
			logql: `sum(count_over_time(` + sel +
				` |= "response sent" |= "/v2/" | json` +
				` | regexp "(?P<status>[0-9]{3})" | status !~ "2.." [1h]))`,
			want: "4",
		},
		{
			// Removing the line filters must RAISE the count, never lower it —
			// the reported run saw it fall to 2.
			name: "pipeline without line filters",
			logql: `sum(count_over_time(` + sel +
				` | json | drop __error__,__error_details__` +
				` | regexp "(?P<status>[0-9]{3})" | status !~ "2.." [1h]))`,
			want: "10",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := queryInstant(t, p, tc.logql, now)
			got := scalarByLabels(t, resp)
			if len(got) != 1 {
				t.Fatalf("expected 1 series, got %d: %v", len(got), got)
			}
			for labels, val := range got {
				if val != tc.want {
					t.Errorf("%s = %s (labels %s), want %s", tc.name, val, labels, tc.want)
				}
				// A bare sum() collapses to no label dimensions in Loki, and VL's
				// internal __name__ column must never reach the client.
				if labels != "{}" {
					t.Errorf("bare sum() returned labels %s, want {}", labels)
				}
			}
		})
	}
}

// testInstantGrouping asserts the instant path groups exactly like the range
// path. Grafana stat panels and the MCP both use instant, so a grouping that
// only works on query_range is invisible until a panel is wrong.
func testInstantGrouping(t *testing.T, p *proxyProc, ns, slowNS string, now time.Time) {
	sel := fmt.Sprintf(`{namespace=%q}`, ns)
	bothNS := fmt.Sprintf(`{namespace=~"%s|%s"}`, ns, slowNS)

	t.Run("sum by level", func(t *testing.T) {
		assertVectorEquals(t, queryInstant(t, p, `sum by (level) (count_over_time(`+sel+`[1h]))`, now),
			map[string]string{
				"{level=error}": "5",
				"{level=warn}":  "3",
				"{level=info}":  "7",
			})
	})

	t.Run("sum by detected_level carries only detected_level", func(t *testing.T) {
		// The reported run returned BOTH detected_level and level, which renames
		// every Grafana series. assertVectorEquals compares the FULL label set,
		// so an extra label fails here.
		assertVectorEquals(t, queryInstant(t, p, `sum by (detected_level) (count_over_time(`+sel+`[1h]))`, now),
			map[string]string{
				"{detected_level=error}": "5",
				"{detected_level=warn}":  "3",
				"{detected_level=info}":  "7",
			})
	})

	t.Run("sum by app", func(t *testing.T) {
		assertVectorEquals(t, queryInstant(t, p, `sum by (app) (count_over_time(`+sel+`[1h]))`, now),
			map[string]string{
				"{app=svc-a}": "9",
				"{app=svc-b}": "6",
			})
	})

	t.Run("instant topk is not rejected", func(t *testing.T) {
		// The reported run answered 400 "unsupported instant aggregation target".
		resp := queryInstant(t, p, `topk(1, sum by (app) (count_over_time(`+sel+`[1h])))`, now)
		assertVectorEquals(t, resp, map[string]string{"{app=svc-a}": "9"})
	})

	t.Run("instant rate emits no empty level label", func(t *testing.T) {
		// Grouping by the derived level makes VL return a `level` column for
		// every series, "" where the field is absent. Loki emits no label at
		// all; the empty one used to reach Grafana as a series dimension.
		for _, s := range queryInstant(t, p, `rate(`+sel+`[1h])`, now).Data.Result {
			for k, v := range s.Metric {
				if strings.TrimSpace(v) == "" {
					t.Errorf("series %v carries empty label %q", s.Metric, k)
				}
			}
			if _, ok := s.Metric["level"]; ok {
				t.Errorf("series %v carries a level label; the fixture rows in this "+
					"namespace have no level field reachable without a parser stage", s.Metric)
			}
		}
	})

	t.Run("instant rate returns finite values", func(t *testing.T) {
		// The reported run returned NaN.
		got := scalarByLabels(t, queryInstant(t, p, `sum(rate(`+sel+`[1h]))`, now))
		if len(got) != 1 {
			t.Fatalf("sum(rate) returned %d series, want 1: %v", len(got), got)
		}
		for _, v := range got {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				t.Fatalf("sum(rate) value %q is not a number: %v", v, err)
			}
			if math.IsNaN(f) || math.IsInf(f, 0) {
				t.Fatalf("sum(rate) returned %v", f)
			}
			// 15 rows over a 1h window.
			if want := 15.0 / 3600.0; f < want*0.99 || f > want*1.01 {
				t.Errorf("sum(rate) = %v, want ~%v", f, want)
			}
		}
	})

	// The defect that unit tests could not see: the grouping label on a range
	// aggregation was replaced by "_stream, _msg", giving one series per pod on
	// the instant path and one per LOG LINE on the range path.
	t.Run("quantile_over_time by namespace groups per namespace", func(t *testing.T) {
		logql := `quantile_over_time(0.95, ` + bothNS + ` | json | unwrap Duration [1h]) by (namespace)`
		wantNS := map[string]bool{ns: true, slowNS: true}

		instant := queryInstant(t, p, logql, now)
		assertGroupedBy(t, instant, []string{"namespace"}, wantNS)

		rng := queryRange(t, p, logql, now.Add(-time.Hour), now, time.Hour)
		assertGroupedBy(t, rng, []string{"namespace"}, wantNS)

		// The -b namespace holds Durations 100,200,300,400, so its p95 must land
		// at the top of that range — proof the grouping did not silently mix the
		// two namespaces (whose combined values start at 10).
		for label, resp := range map[string]lokiResponse{"instant": instant, "range": rng} {
			for _, s := range resp.Data.Result {
				if s.Metric["namespace"] != slowNS {
					continue
				}
				f := seriesValue(t, s)
				if f < 300 || f > 400 {
					t.Errorf("%s: p95 of %s = %v, want within [300,400]", label, slowNS, f)
				}
			}
		}
	})

	// An outer aggregation OVER a range grouping carries two clauses; a single
	// stats stage can hold only one, and the outer one used to be dropped —
	// yielding per-namespace quantiles with no sum applied, which looks like a
	// real answer. Assert the numbers, not just the shape.
	t.Run("outer sum by over range grouping applies both", func(t *testing.T) {
		// Establish the inner stage's own answer first: one max per namespace.
		// Every assertion below is stated against these measured values rather
		// than against constants, so the fixture and the test cannot drift.
		inner := queryInstant(t, p,
			`max_over_time(`+bothNS+` | json | unwrap Duration [1h]) by (namespace)`, now)
		perNS := map[string]float64{}
		for _, s := range inner.Data.Result {
			perNS[s.Metric["namespace"]] = seriesValue(t, s)
		}
		if len(perNS) != 2 {
			t.Fatalf("inner query returned %d namespaces, want 2: %v", len(perNS), perNS)
		}

		outer := queryInstant(t, p,
			`sum by (namespace) (max_over_time(`+bothNS+` | json | unwrap Duration [1h]) by (namespace))`, now)

		// Summing by the SAME label the inner stage grouped by is the identity,
		// so every namespace must come back with its inner value intact. If the
		// outer clause were dropped the result would coincidentally match here,
		// which is why the label-set assertion below carries the weight.
		assertGroupedBy(t, outer, []string{"namespace"}, map[string]bool{ns: true, slowNS: true})
		for _, s := range outer.Data.Result {
			nsName := s.Metric["namespace"]
			if got, want := seriesValue(t, s), perNS[nsName]; got != want {
				t.Errorf("sum by (namespace) over %s = %v, want %v", nsName, got, want)
			}
		}

		// Collapsing to a DIFFERENT grouping proves the outer stage really ran:
		// summing across both namespaces must total their inner values, and the
		// namespace label must be gone.
		collapsed := queryInstant(t, p,
			`sum by (container) (max_over_time(`+bothNS+` | json | unwrap Duration [1h]) by (namespace))`, now)
		if len(collapsed.Data.Result) != 1 {
			t.Fatalf("sum by (container) returned %d series, want 1: %s",
				len(collapsed.Data.Result), describeSeries(collapsed))
		}
		got := seriesValue(t, collapsed.Data.Result[0])
		want := 0.0
		for _, v := range perNS {
			want += v
		}
		if got != want {
			t.Errorf("sum by (container) = %v, want %v (sum of %v)", got, want, perNS)
		}
		if _, leaked := collapsed.Data.Result[0].Metric["namespace"]; leaked {
			t.Errorf("outer grouping did not replace the inner one: %v",
				collapsed.Data.Result[0].Metric)
		}
	})

	// A two-stage aggregation is executed by VL, which buckets by `step`
	// (tumbling). LogQL's range aggregation is a SLIDING window of `range`, so
	// the two agree only while range <= step. Beyond that the proxy refuses
	// instead of returning a plausible wrong number.
	t.Run("two-stage range query rejects range > step", func(t *testing.T) {
		logql := `sum by (container) (max_over_time(` + bothNS + ` | json | unwrap Duration [1h]) by (namespace))`

		params := url.Values{}
		params.Set("query", logql)
		params.Set("start", strconv.FormatInt(now.Add(-time.Hour).Unix(), 10))
		params.Set("end", strconv.FormatInt(now.Unix(), 10))
		params.Set("step", "300") // 5m step under a 1h range → sliding

		resp, err := http.PostForm("http://"+p.listenAddr+"/loki/api/v1/query_range", params)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("range > step: expected HTTP 400, got %d: %s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "tumbling") {
			t.Errorf("error should explain the tumbling/sliding mismatch, got: %s", body)
		}

		// step >= range is exactly representable, so it must still answer.
		params.Set("step", "3600")
		okResp, err := http.PostForm("http://"+p.listenAddr+"/loki/api/v1/query_range", params)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		okBody, _ := io.ReadAll(okResp.Body)
		_ = okResp.Body.Close()
		if okResp.StatusCode != http.StatusOK {
			t.Fatalf("step >= range: expected HTTP 200, got %d: %s", okResp.StatusCode, okBody)
		}

		// And the single-stage sliding form is untouched by the guard.
		params.Set("query", `max_over_time(`+bothNS+` | json | unwrap Duration [1h]) by (namespace)`)
		params.Set("step", "300")
		singleResp, err := http.PostForm("http://"+p.listenAddr+"/loki/api/v1/query_range", params)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		singleBody, _ := io.ReadAll(singleResp.Body)
		_ = singleResp.Body.Close()
		if singleResp.StatusCode != http.StatusOK {
			t.Fatalf("single-stage sliding: expected HTTP 200, got %d: %s", singleResp.StatusCode, singleBody)
		}
	})

	t.Run("max_over_time by namespace stays grouped", func(t *testing.T) {
		logql := `max_over_time(` + bothNS + ` | json | unwrap Duration [1h]) by (namespace)`
		assertGroupedBy(t, queryInstant(t, p, logql, now), []string{"namespace"},
			map[string]bool{ns: true, slowNS: true})
	})
}

// testCountValues asserts count_values() is REJECTED with 400, matching Loki.
//
// count_values is a PromQL operator, not a LogQL one: real Loki (3.7.1) answers
// `parse error at line 1, col 1: syntax error: unexpected IDENTIFIER` for it.
// An earlier revision of this branch implemented it as a post-aggregation; the
// e2e error-parity suite caught that as a SILENT FAIL, because returning data
// for a query the reference implementation rejects is a worse compatibility bug
// than the missing feature. To count entries grouped by a log field, the LogQL
// spelling is `sum by (<field>) (count_over_time(...))`, which is supported.
func testCountValues(t *testing.T, p *proxyProc, ns, tieNS string, now time.Time) {
	sel := fmt.Sprintf(`{namespace=%q}`, ns)

	queries := []string{
		`count_values("c", sum by (level) (count_over_time(` + sel + `[1h])))`,
		`count_values("c", count_over_time(` + sel + `[1h]))`,
	}

	for _, q := range queries {
		t.Run("rejected: "+q, func(t *testing.T) {
			params := url.Values{}
			params.Set("query", q)
			params.Set("time", strconv.FormatInt(now.Unix(), 10))

			resp, err := http.PostForm("http://"+p.listenAddr+"/loki/api/v1/query", params)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 (Loki parity), got %d: %s", resp.StatusCode, body)
			}
			if !strings.Contains(string(body), "count_values") {
				t.Errorf("error body should name the operator, got: %s", body)
			}
		})
	}

	// The supported spelling must still work, so the rejection above is a
	// statement about count_values and not about grouping in general.
	t.Run("supported alternative groups by the field", func(t *testing.T) {
		assertVectorEquals(t,
			queryInstant(t, p, `sum by (level) (count_over_time(`+sel+`[1h]))`, now),
			map[string]string{
				"{level=error}": "5",
				"{level=warn}":  "3",
				"{level=info}":  "7",
			})
	})
}

// testJSONLineFormat confirms `| json` parses the ORIGINAL application message
// (the JSON inside _msg, per -line-field=_msg) rather than the VictoriaLogs
// record wrapping it, and that line_format renders a field extracted from it.
func testJSONLineFormat(t *testing.T, p *proxyProc, ns string, now time.Time) {
	params := url.Values{}
	params.Set("query", fmt.Sprintf(`{namespace=%q} | json | line_format "{{.message}}"`, ns))
	params.Set("start", strconv.FormatInt(now.Add(-time.Hour).Unix(), 10))
	params.Set("end", strconv.FormatInt(now.Unix(), 10))
	params.Set("limit", "10")

	resp, err := http.PostForm("http://"+p.listenAddr+"/loki/api/v1/query_range", params)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d: %s", resp.StatusCode, body)
	}

	var streams struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &streams); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	if streams.Data.ResultType != "streams" {
		t.Fatalf("resultType = %q, want streams\n%s", streams.Data.ResultType, body)
	}

	// The fixture's "slow" namespace logs {"message":"y 0".."y 3", ...}. After
	// `| json | line_format "{{.message}}"` each line must be the bare message
	// value — not the JSON object, and not the VL record.
	var lines []string
	for _, s := range streams.Data.Result {
		for _, v := range s.Values {
			if len(v) >= 2 {
				lines = append(lines, v[1])
			}
		}
	}
	if len(lines) != 4 {
		t.Fatalf("got %d lines, want 4: %v\n%s", len(lines), lines, body)
	}
	sort.Strings(lines)
	for i, want := range []string{"y 0", "y 1", "y 2", "y 3"} {
		if lines[i] != want {
			t.Errorf("line %d = %q, want %q (all: %v)", i, lines[i], want, lines)
		}
	}
	// Guard against the render-the-record failure mode explicitly.
	for _, l := range lines {
		if strings.Contains(l, "kubernetes.") || strings.Contains(l, `"message"`) {
			t.Errorf("line_format rendered the record instead of the message: %q", l)
		}
	}
}

// testLabelMatcherAnchoring asserts Loki's label-matcher contract against real
// VL: a `=~` matcher is anchored to the WHOLE label value.
//
// mainNS and tieNS are distinct roots, so this builds its own prefix-sibling
// pair from mainNS to exercise the case that was silently wrong: a pattern that
// is a strict substring of a real namespace name.
func testLabelMatcherAnchoring(t *testing.T, p *proxyProc, mainNS, tieNS string, now time.Time) {
	// mainNS is "appmain-<id>"; "ppmain-<id>" is a strict substring of it, so an
	// UNANCHORED match returns mainNS's 15 rows while Loki returns nothing.
	substr := strings.TrimPrefix(mainNS, "a")
	if substr == mainNS {
		t.Fatalf("fixture: expected mainNS %q to start with 'a'", mainNS)
	}

	count := func(logql string) string {
		got := scalarByLabels(t, queryInstant(t, p, logql, now))
		if len(got) != 1 {
			t.Fatalf("%s: expected 1 series, got %d: %v", logql, len(got), got)
		}
		for _, v := range got {
			return v
		}
		return ""
	}

	tests := []struct {
		name  string
		logql string
		want  string
	}{
		{
			// The defect: a substring pattern matched the longer real value.
			name:  "substring pattern matches nothing",
			logql: `sum(count_over_time({namespace=~"` + substr + `"}[1h]))`,
			want:  "0",
		},
		{
			name:  "exact pattern matches the namespace",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `"}[1h]))`,
			want:  "15",
		},
		{
			// Alternation must be grouped: "^a|b$" would match either a prefix
			// or a suffix and pull in unrelated namespaces.
			name:  "alternation matches both members exactly",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `|` + tieNS + `"}[1h]))`,
			want:  "24", // 15 + 9
		},
		{
			name:  "alternation with a substring member still excludes it",
			logql: `sum(count_over_time({namespace=~"` + substr + `|` + tieNS + `"}[1h]))`,
			want:  "9",
		},
		{
			name:  "match-all still matches the namespace",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `.*"}[1h]))`,
			want:  "15",
		},
		{
			name:  "negated substring pattern excludes nothing",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `"} | namespace !~ "` + substr + `" [1h]))`,
			want:  "15",
		},
		{
			// A line filter regex must stay a SUBSTRING match over the log line.
			// The fixture's messages are "hello error 0" etc.
			name:  "line filter regex remains unanchored",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `"} |~ "hello" [1h]))`,
			want:  "15",
		},
		{
			name:  "line filter regex anchored by the author still works",
			logql: `sum(count_over_time({namespace=~"` + mainNS + `"} |~ ".*hello.*" [1h]))`,
			want:  "15",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := count(tc.logql); got != tc.want {
				t.Errorf("%s\n got: %s\nwant: %s", tc.logql, got, tc.want)
			}
		})
	}
}

// chainFallbackFixture builds records that carry NO `kubernetes.pod_labels.app`
// and reach the `app` Loki label only through the SECOND field of the
// -field-mapping fallback chain. That is the production shape behind panel S6:
// trow's pods label themselves with app.kubernetes.io/name, not app.
func chainFallbackFixture(ns string) []vlRecord {
	var out []vlRecord
	for i := 0; i < 6; i++ {
		out = append(out, vlRecord{
			tsOffset:  -18*time.Minute + time.Duration(i)*time.Second,
			namespace: ns,
			pod:       ns + "-0",
			container: "c",
			app:       "", // no primary app pod-label
			msg: map[string]interface{}{
				"message": fmt.Sprintf("chain %d", i),
				"level":   "info",
			},
			extra: map[string]string{
				"kubernetes.pod_labels.app.kubernetes.io/name": "trow-registry",
				"loglevel": "info",
			},
		})
	}
	return out
}

// testPanelCompareDefects covers the defects found by comparing the deployed
// proxy against central Loki panel by panel on the same data (10.09.2026).
// Expected values are Loki's, measured on that run.
func testPanelCompareDefects(t *testing.T, base string, p *proxyProc, ns, chainNS string, now time.Time) {
	sel := fmt.Sprintf(`{namespace=%q}`, ns)

	// S4/S5. Grouping by the derived level made the translator inject
	// `| unpack_json from _msg`, which the compat layer read as a USER parser
	// stage and answered with a raw-row scan — `| sort by (_time) desc limit
	// 1000000` in VL. That returned 400 and OOM-killed both 4Gi VLSingles five
	// times. It must be a native stats aggregation, and it must return the label
	// the client asked for: Loki answers `sum by (level)` with `level` and
	// `sum by (detected_level)` with `detected_level`.
	for _, tc := range []struct {
		name  string
		label string
	}{
		{"S4 sum by level", "level"},
		{"S5 sum by detected_level", "detected_level"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logql := fmt.Sprintf(`sum by (%s) (count_over_time(%s[1h]))`, tc.label, sel)
			want := map[string]string{
				fmt.Sprintf("{%s=error}", tc.label): "5",
				fmt.Sprintf("{%s=warn}", tc.label):  "3",
				fmt.Sprintf("{%s=info}", tc.label):  "7",
			}
			assertVectorEquals(t, queryInstant(t, p, logql, now), want)
			// A 1h window with a 1m step is the shape that failed in production.
			assertVectorEquals(t, queryRange(t, p, logql, now.Add(-time.Hour), now, time.Hour), want)
		})
	}

	// The VALUES above are identical whichever path answers, so they cannot
	// catch the defect on a small fixture — the raw-row scan only fails at
	// production volume. Assert the PATH instead: a proxy whose raw-row cap is
	// below the fixture size answers only if it never reads raw rows.
	t.Run("S4/S5 level grouping never scans raw rows", func(t *testing.T) {
		capped := startProxyWithBackendURL(t, base,
			append(vlSemanticsFlags(), "-manual-range-metric-row-limit=3")...)

		for _, label := range []string{"level", "detected_level"} {
			logql := fmt.Sprintf(`sum by (%s) (count_over_time(%s[1h]))`, label, sel)
			want := map[string]string{
				fmt.Sprintf("{%s=error}", label): "5",
				fmt.Sprintf("{%s=warn}", label):  "3",
				fmt.Sprintf("{%s=info}", label):  "7",
			}
			// 15 rows in the namespace, cap 3: a raw-row scan cannot answer this.
			assertVectorEquals(t, queryInstant(t, capped, logql, now), want)
			assertVectorEquals(t, queryRange(t, capped, logql, now.Add(-time.Hour), now, time.Hour), want)
		}
	})

	// S6. A Loki label backed by a fallback chain cannot be a VL group-by key:
	// VL grouped by the chain's FIRST field, which these records do not carry,
	// so the panel showed {app=""} with an otherwise correct count.
	t.Run("S6 grouping by a fallback-chain label", func(t *testing.T) {
		logql := fmt.Sprintf(`sum by (app) (count_over_time({namespace=%q}[1h]))`, chainNS)
		want := map[string]string{"{app=trow-registry}": "6"}
		assertVectorEquals(t, queryInstant(t, p, logql, now), want)
		assertVectorEquals(t, queryRange(t, p, logql, now.Add(-time.Hour), now, time.Hour), want)
	})

	// T5. An outer aggregation over an UNGROUPED range aggregation has always
	// produced two stats stages and has always been evaluated correctly; the
	// two-stage guard added earlier must not divert it, at any step.
	t.Run("T5 nested range function at any step", func(t *testing.T) {
		logql := `max(quantile_over_time(0.95, ` + sel + ` | json | unwrap Duration [10m]))`
		for _, step := range []time.Duration{time.Minute, 10 * time.Minute, time.Hour} {
			resp := queryRange(t, p, logql, now.Add(-time.Hour), now, step)
			if len(resp.Data.Result) == 0 {
				t.Errorf("step %s: no series", step)
			}
		}
	})

	// S11. bytes_over_time already mapped to sum_len(_msg); its production 502
	// was the backends being dead from the S4/S5 OOM. Lock that it answers.
	t.Run("S11 bytes_over_time", func(t *testing.T) {
		logql := `bytes_over_time(` + sel + `[1h])`
		if len(queryRange(t, p, logql, now.Add(-time.Hour), now, time.Hour).Data.Result) == 0 {
			t.Error("bytes_over_time returned no series")
		}
		if len(queryInstant(t, p, logql, now).Data.Result) == 0 {
			t.Error("bytes_over_time instant returned no series")
		}
	})

	// rate must be count/range_seconds on every path — the panel run reported
	// Σ=657 where Loki gave 10.95 over a 60s range (exactly ×60).
	t.Run("rate is divided by the range seconds", func(t *testing.T) {
		count := singleSeriesValue(t, queryInstant(t, p, `sum(count_over_time(`+sel+`[1h]))`, now))
		for _, q := range []string{
			`sum(rate(` + sel + `[1h]))`,
			`sum by (app) (rate(` + sel + `[1h]))`,
			`sum(rate(` + sel + ` | json [1h]))`,
		} {
			total := 0.0
			for _, s := range queryInstant(t, p, q, now).Data.Result {
				total += seriesValue(t, s)
			}
			if want := count / 3600.0; math.Abs(total-want) > want*0.01 {
				t.Errorf("%s = %v, want %v (count %v / 3600s)", q, total, want, count)
			}
		}
	})
}

// singleSeriesValue returns the value of a response that must hold exactly one
// series.
func singleSeriesValue(t *testing.T, resp lokiResponse) float64 {
	t.Helper()
	if len(resp.Data.Result) != 1 {
		t.Fatalf("expected 1 series, got %d", len(resp.Data.Result))
	}
	return seriesValue(t, resp.Data.Result[0])
}

// seriesValue extracts the single sample of a vector series, or the last bucket
// of a matrix series.
func seriesValue(t *testing.T, s lokiSeries) float64 {
	t.Helper()
	var raw string
	switch {
	case len(s.Value) >= 2:
		raw, _ = s.Value[1].(string)
	case len(s.Values) >= 1 && len(s.Values[len(s.Values)-1]) >= 2:
		raw, _ = s.Values[len(s.Values)-1][1].(string)
	default:
		t.Fatalf("series %v carries no sample", s.Metric)
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("series %v value %q: %v", s.Metric, raw, err)
	}
	return f
}

// assertVectorEquals compares a vector/matrix response against an exact
// {canonical label set -> value} expectation.
func assertVectorEquals(t *testing.T, resp lokiResponse, want map[string]string) {
	t.Helper()
	got := scalarByLabels(t, resp)
	if len(got) != len(want) {
		t.Fatalf("got %d series %v, want %d %v", len(got), got, len(want), want)
	}
	for labels, wantVal := range want {
		gotVal, ok := got[labels]
		if !ok {
			t.Errorf("missing series %s (got %v)", labels, got)
			continue
		}
		// Values arrive as VL formats them ("5" or "5.0"); compare numerically.
		gf, err1 := strconv.ParseFloat(gotVal, 64)
		wf, err2 := strconv.ParseFloat(wantVal, 64)
		if err1 != nil || err2 != nil {
			if gotVal != wantVal {
				t.Errorf("series %s = %q, want %q", labels, gotVal, wantVal)
			}
			continue
		}
		if gf != wf {
			t.Errorf("series %s = %v, want %v", labels, gf, wf)
		}
	}
}

// assertGroupedBy asserts every series carries EXACTLY the given label keys and
// that the set of values for the first key matches wantValues. This is the
// assertion that catches "grouping was replaced by stream identity": extra
// labels like pod/container/_msg fail it even when the numbers look plausible.
func assertGroupedBy(t *testing.T, resp lokiResponse, keys []string, wantValues map[string]bool) {
	t.Helper()
	if len(resp.Data.Result) != len(wantValues) {
		t.Fatalf("got %d series, want %d: %s",
			len(resp.Data.Result), len(wantValues), describeSeries(resp))
	}
	seen := make(map[string]bool, len(wantValues))
	for _, s := range resp.Data.Result {
		if len(s.Metric) != len(keys) {
			t.Errorf("series labels %v carry %d keys, want exactly %v",
				s.Metric, len(s.Metric), keys)
			continue
		}
		for _, k := range keys {
			if _, ok := s.Metric[k]; !ok {
				t.Errorf("series labels %v missing key %q", s.Metric, k)
			}
		}
		seen[s.Metric[keys[0]]] = true
	}
	for v := range wantValues {
		if !seen[v] {
			t.Errorf("missing series for %s=%q: %s", keys[0], v, describeSeries(resp))
		}
	}
}

func describeSeries(resp lokiResponse) string {
	var b bytes.Buffer
	for _, s := range resp.Data.Result {
		b.WriteString(canonicalLabels(s.Metric))
		b.WriteByte(' ')
	}
	return b.String()
}
