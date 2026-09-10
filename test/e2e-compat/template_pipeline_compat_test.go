//go:build e2e

package e2e_compat

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests cover LogQL Go templates in `| line_format` / `| label_format`
// and the `__error__` parse-failure labels — everything VictoriaLogs cannot
// evaluate, so the proxy must do it itself. Each case is compared against the
// real Loki in the same stack over identical data.
//
// The fixtures reproduce the two production shapes the feature was written for:
// trow-registry lines (a JSON envelope whose `message` carries ANSI-coloured
// key=value pairs) and db-migrator lines (a JSON envelope rendered through a
// backtick-quoted `| line_format`).

const (
	tplLines     = 240 // trow lines, 5 s apart
	tplLineStepS = 5
)

// The e2e stack persists its data across runs, so each run gets its own
// namespace — otherwise a second run queries the union of both fixtures.
var (
	tplIngestOnce sync.Once
	tplStart      time.Time
	tplEnd        time.Time
	tplStreamNS   string
	tplErrStreamN string
)

const ansiESC = "\x1b"

// tplTrowLine mirrors a trow-registry `response sent` line.
func tplTrowLine(status, path string, durMS int) string {
	msg := fmt.Sprintf(
		"2026-09-10T00:00:00.000000Z %s[32m INFO%s[0m %s[2mtrow::routes%s[0m%s[2m:%s[0m response sent "+
			"%s[3mstatus%s[0m%s[2m=%s[0m%q %s[3mpath%s[0m%s[2m=%s[0m%q %s[3mduration_ms%s[0m%s[2m=%s[0m%d",
		ansiESC, ansiESC, ansiESC, ansiESC, ansiESC, ansiESC,
		ansiESC, ansiESC, ansiESC, ansiESC, status,
		ansiESC, ansiESC, ansiESC, ansiESC, path,
		ansiESC, ansiESC, ansiESC, ansiESC, durMS)
	b, _ := json.Marshal(map[string]string{"message": msg, "target": "trow::routes", "level": "INFO"})
	return string(b)
}

// tplTrowPaths cycles six request shapes: two upstreams plus a local one, and
// 4 of 6 responses 2xx. Over 240 lines that is 80 per upstream and 80 non-2xx.
var tplTrowPaths = []struct {
	path   string
	status string
	durMS  int
}{
	{"/v2/library/nginx/manifests/latest?ns=docker.io", "200", 12},
	{"/v2/library/nginx/blobs/sha256:aaa?ns=docker.io", "200", 30},
	{"/v2/maestra/api/manifests/v1?ns=515260921971.dkr.ecr.us-west-2.amazonaws.com", "200", 44},
	{"/v2/maestra/api/blobs/sha256:bbb?ns=515260921971.dkr.ecr.us-west-2.amazonaws.com", "404", 5},
	{"/v2/local/thing/manifests/v2", "200", 7},
	{"/v2/local/thing/blobs/sha256:ccc", "500", 99},
}

func ensureTemplateDataIngested(t *testing.T) {
	t.Helper()
	tplIngestOnce.Do(func() {
		waitForReady(t, proxyURL+"/ready", 30*time.Second)
		waitForReady(t, lokiURL+"/ready", 30*time.Second)

		runID := strconv.FormatInt(time.Now().UnixNano(), 36)
		tplStreamNS = "e2e-tpl-" + runID
		tplErrStreamN = "e2e-tpl-err-" + runID

		tplEnd = time.Now().Add(-3 * time.Minute).Truncate(time.Second)
		tplStart = tplEnd.Add(-time.Duration(tplLines*tplLineStepS) * time.Second)

		// +2 s so no sample lands exactly on a 60 s step boundary. The manual
		// aggregation path closes its window on both ends where Loki's range
		// vector is left-open, so a boundary sample is counted in two adjacent
		// buckets — a pre-existing skew of the shared helper (it shows on a plain
		// `sum by (ns) (rate({...}[2m]))` too) that would otherwise dominate the
		// comparison these cases are actually about.
		trow := make([]tplEntry, 0, tplLines)
		for i := 0; i < tplLines; i++ {
			p := tplTrowPaths[i%len(tplTrowPaths)]
			trow = append(trow, tplEntry{
				ts:   tplStart.Add(2*time.Second + time.Duration(i*tplLineStepS)*time.Second),
				line: tplTrowLine(p.status, p.path, p.durMS),
			})
		}
		tplPush(t, map[string]string{"namespace": tplStreamNS, "container": "trow", "app": "trow"}, trow)

		// db-migrator shape: a JSON envelope whose message carries backticks —
		// rendered through a backtick-quoted `| line_format`.
		mig := make([]tplEntry, 0, 60)
		for i := 0; i < 60; i++ {
			b, _ := json.Marshal(map[string]interface{}{
				"message": fmt.Sprintf("migration step %d applied `ok`", i),
				"level":   "info",
				"seq":     i,
			})
			mig = append(mig, tplEntry{ts: tplStart.Add(time.Duration(i*20) * time.Second), line: string(b)})
		}
		tplPush(t, map[string]string{"namespace": tplStreamNS, "container": "db-migrator-services", "app": "db-migrator"}, mig)

		// __error__ fixture: 15 well-formed JSON lines (5 info / 3 warn / 7
		// error) plus 6 that are not JSON at all.
		errLines := make([]tplEntry, 0, 21)
		// +10 s so no entry sits exactly on the `[20m]` window edge below: the
		// manual aggregation path closes its window on both ends while Loki's
		// range vector is left-open, and a boundary sample would then differ by
		// one for reasons unrelated to what these cases assert.
		add := func(i int, line string) {
			errLines = append(errLines, tplEntry{ts: tplStart.Add(10*time.Second + time.Duration(i*20)*time.Second), line: line})
		}
		idx := 0
		for _, lvl := range []struct {
			name string
			n    int
		}{{"info", 5}, {"warn", 3}, {"error", 7}} {
			for i := 0; i < lvl.n; i++ {
				b, _ := json.Marshal(map[string]string{"level": lvl.name, "msg": fmt.Sprintf("%s-%d", lvl.name, i)})
				add(idx, string(b))
				idx++
			}
		}
		for i := 0; i < 6; i++ {
			add(idx, fmt.Sprintf("plain text line %d not json", i))
			idx++
		}
		tplPush(t, map[string]string{"namespace": tplErrStreamN, "container": "errtest", "app": "errtest"}, errLines)

		forceVLFlush(t)
		tplWaitForLokiData(t)
	})
}

// tplWaitForLokiData polls until Loki has this suite's own fixture queryable.
// (The shared waitForLokiMetricData waits on the rich fixture from
// compat_extended_test.go, which these tests do not ingest.)
func tplWaitForLokiData(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	q := fmt.Sprintf(`sum(count_over_time({namespace=%q}[20m]))`, tplStreamNS)
	for time.Now().Before(deadline) {
		params := url.Values{}
		params.Set("query", q)
		params.Set("time", strconv.FormatInt(tplEnd.UnixNano(), 10))
		resp, err := http.Get(lokiURL + "/loki/api/v1/query?" + params.Encode())
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var payload map[string]interface{}
			if json.Unmarshal(raw, &payload) == nil {
				if data, ok := payload["data"].(map[string]interface{}); ok {
					if res, ok := data["result"].([]interface{}); ok && len(res) > 0 {
						return
					}
				}
			}
		}
		time.Sleep(time.Second)
	}
	t.Logf("warning: Loki has not made the template fixture queryable within 60s")
}

type tplEntry struct {
	ts   time.Time
	line string
}

func tplPush(t *testing.T, labels map[string]string, entries []tplEntry) {
	t.Helper()

	lokiValues := make([]interface{}, 0, len(entries))
	vlLines := make([]string, 0, len(entries))
	streamFields := make([]string, 0, len(labels))
	for k := range labels {
		streamFields = append(streamFields, k)
	}
	for _, e := range entries {
		lokiValues = append(lokiValues, []string{strconv.FormatInt(e.ts.UnixNano(), 10), e.line})
		row := map[string]string{"_time": e.ts.Format(time.RFC3339Nano), "_msg": e.line}
		for k, v := range labels {
			row[k] = v
		}
		j, _ := json.Marshal(row)
		vlLines = append(vlLines, string(j))
	}

	body, _ := json.Marshal(map[string]interface{}{
		"streams": []map[string]interface{}{{"stream": labels, "values": lokiValues}},
	})
	resp, err := http.Post(lokiURL+"/loki/api/v1/push", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("Loki push failed: %v", err)
	}
	resp.Body.Close()

	resp, err = http.Post(
		vlURL+"/insert/jsonline?_stream_fields="+strings.Join(streamFields, ","),
		"application/stream+json",
		strings.NewReader(strings.Join(vlLines, "\n")),
	)
	if err != nil {
		t.Fatalf("VL push failed: %v", err)
	}
	resp.Body.Close()
}

// ─── query helpers ──────────────────────────────────────────────────────────

func tplQuery(t *testing.T, baseURL, kind, query string) map[string]interface{} {
	t.Helper()
	params := url.Values{}
	params.Set("query", query)
	path := "/loki/api/v1/query_range"
	switch kind {
	case "instant":
		path = "/loki/api/v1/query"
		params.Set("time", strconv.FormatInt(tplEnd.UnixNano(), 10))
	case "range":
		params.Set("start", strconv.FormatInt(tplStart.UnixNano(), 10))
		params.Set("end", strconv.FormatInt(tplEnd.UnixNano(), 10))
		params.Set("step", "60")
	default: // logs
		params.Set("start", strconv.FormatInt(tplStart.UnixNano(), 10))
		params.Set("end", strconv.FormatInt(tplEnd.UnixNano(), 10))
		params.Set("limit", "5000")
		params.Set("direction", "backward")
	}
	resp, err := http.Get(baseURL + path + "?" + params.Encode())
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query %q against %s: status %d body %s", query, baseURL, resp.StatusCode, tplTruncate(string(raw)))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("bad JSON from %s: %v (%s)", baseURL, err, tplTruncate(string(raw)))
	}
	return payload
}

func tplTruncate(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

func tplResults(t *testing.T, payload map[string]interface{}) []interface{} {
	t.Helper()
	data, _ := payload["data"].(map[string]interface{})
	res, _ := data["result"].([]interface{})
	return res
}

// tplSeriesTotals maps each series' label set to the SUM of its samples. For a
// rate() query that sum is what distinguishes a proper rate from a raw count.
func tplSeriesTotals(t *testing.T, payload map[string]interface{}) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, item := range tplResults(t, payload) {
		s, _ := item.(map[string]interface{})
		metric, _ := s["metric"].(map[string]interface{})
		key := tplMetricKey(metric)
		if v, ok := s["value"].([]interface{}); ok && len(v) == 2 {
			out[key] += tplFloat(v[1])
			continue
		}
		values, _ := s["values"].([]interface{})
		for _, pair := range values {
			p, _ := pair.([]interface{})
			if len(p) == 2 {
				out[key] += tplFloat(p[1])
			}
		}
	}
	return out
}

func tplMetricKey(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, m[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func tplFloat(v interface{}) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(fmt.Sprintf("%v", v)), 64)
	return f
}

func tplLogLines(t *testing.T, payload map[string]interface{}) []string {
	t.Helper()
	var out []string
	for _, item := range tplResults(t, payload) {
		s, _ := item.(map[string]interface{})
		values, _ := s["values"].([]interface{})
		for _, pair := range values {
			p, _ := pair.([]interface{})
			if len(p) == 2 {
				out = append(out, fmt.Sprintf("%v", p[1]))
			}
		}
	}
	return out
}

// ─── queries under test ─────────────────────────────────────────────────────

func tplTrowSelector() string {
	return fmt.Sprintf(`{namespace=%q, container="trow"} |= "response sent" |= "/v2/"`, tplStreamNS)
}

// tplT2 is the trow "Non-2xx responses" panel: a `| regexp` reading the line a
// `| line_format` produced, then a label filter on the extracted status.
func tplT2() string {
	return `sum(count_over_time(` + tplTrowSelector() +
		` | json message="message" | line_format "{{ or .message __line__ }}"` +
		` | drop __error__, __error_details__` +
		` | regexp "status.*?=\\x1b\\[0m\"(?P<status>\\d{3})\"" | status !~ "2.." [20m])) or vector(0)`
}

// tplT6 is the trow "Upstream registry (?ns=)" panel: a conditional
// `| label_format` producing the label the rate() is grouped by.
func tplT6() string {
	return "sum by (upstream) (rate(" + tplTrowSelector() +
		` | json message="message" | line_format "{{ or .message __line__ }}"` +
		` | drop __error__, __error_details__` +
		` | regexp "\\?ns=(?P<ns>[^\"&]+)\""` +
		" | label_format upstream=`{{ if .ns }}{{ .ns }}{{ else }}(no ns - trow-local){{ end }}` [1m]))"
}

// tplT8 is the trow "Response status classes" panel: a printf template.
func tplT8() string {
	return "sum by (class) (rate(" + tplTrowSelector() +
		` | json message="message" | line_format "{{ or .message __line__ }}"` +
		` | drop __error__, __error_details__` +
		` | regexp "status.*?=\\x1b\\[0m\"(?P<status>\\d{3})\""` +
		" | label_format class=`{{ printf \"%.1sxx\" .status }}` [1m]))"
}

// TestTemplate_T2_NonSuccessCount is the instant shape whose pipeline the proxy
// used to skip entirely: the regexp saw the raw JSON envelope instead of the
// formatted line, extracted no status, and the `!~ "2.."` filter then passed
// EVERY line (908 vs Loki's 0 in production).
func TestTemplate_T2_NonSuccessCount(t *testing.T) {
	ensureTemplateDataIngested(t)

	proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "instant", tplT2()))
	lokiTotals := tplSeriesTotals(t, tplQuery(t, lokiURL, "instant", tplT2()))

	if len(proxyTotals) != 1 || len(lokiTotals) != 1 {
		t.Fatalf("expected one series each, proxy=%v loki=%v", proxyTotals, lokiTotals)
	}
	// The label set matters too: `sum(...)` yields {}, never VL's {__name__=…}.
	if _, ok := proxyTotals["{}"]; !ok {
		t.Errorf("proxy series must carry no labels, got %v", proxyTotals)
	}
	if proxyTotals["{}"] != lokiTotals["{}"] {
		t.Errorf("non-2xx count: proxy=%v loki=%v", proxyTotals, lokiTotals)
	}
	// 2 of the 6 cycled request shapes are non-2xx.
	if want := float64(tplLines / len(tplTrowPaths) * 2); proxyTotals["{}"] != want {
		t.Errorf("non-2xx count = %v, want %v", proxyTotals["{}"], want)
	}
}

// TestTemplate_T6_LabelFormatRate is the regression for the reported shape:
// three upstream series instead of one, each value a RATE (count / range
// seconds) rather than a raw count. Production saw Σ=657 where Loki gave 10.95
// — one collapsed series carrying undivided counts.
func TestTemplate_T6_LabelFormatRate(t *testing.T) {
	ensureTemplateDataIngested(t)

	proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "range", tplT6()))
	lokiTotals := tplSeriesTotals(t, tplQuery(t, lokiURL, "range", tplT6()))

	wantSeries := []string{
		"{upstream=docker.io}",
		"{upstream=515260921971.dkr.ecr.us-west-2.amazonaws.com}",
		"{upstream=(no ns - trow-local)}",
	}
	for _, key := range wantSeries {
		if _, ok := proxyTotals[key]; !ok {
			t.Errorf("missing series %s in proxy result %v", key, proxyTotals)
		}
		if _, ok := lokiTotals[key]; !ok {
			t.Errorf("missing series %s in Loki result %v", key, lokiTotals)
		}
	}
	if len(proxyTotals) != len(wantSeries) {
		t.Errorf("proxy returned %d series, want %d: %v", len(proxyTotals), len(wantSeries), proxyTotals)
	}
	for key := range proxyTotals {
		if strings.Contains(key, "{{") {
			t.Fatalf("series label carries raw template text: %s", key)
		}
	}

	// The rate shape: Σ over a [1m] rate must be ≈ Σ(counts)/60, i.e. two
	// orders of magnitude below the line count — never the count itself.
	proxySum, lokiSum := tplSum(proxyTotals), tplSum(lokiTotals)
	if proxySum >= float64(tplLines)/2 {
		t.Errorf("Σ=%v looks like an undivided count (%d lines ingested) — rate() must divide by the range seconds", proxySum, tplLines)
	}
	tplAssertClose(t, "T6 Σ", proxySum, lokiSum, 0.10)
}

// TestTemplate_T8_PrintfLabelFormat covers the `printf` template producing the
// grouping label.
func TestTemplate_T8_PrintfLabelFormat(t *testing.T) {
	ensureTemplateDataIngested(t)

	proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "range", tplT8()))
	lokiTotals := tplSeriesTotals(t, tplQuery(t, lokiURL, "range", tplT8()))

	for _, key := range []string{"{class=2xx}", "{class=4xx}", "{class=5xx}"} {
		if _, ok := proxyTotals[key]; !ok {
			t.Errorf("missing series %s in proxy result %v", key, proxyTotals)
		}
	}
	if len(proxyTotals) != len(lokiTotals) {
		t.Errorf("series count proxy=%d loki=%d (proxy=%v loki=%v)", len(proxyTotals), len(lokiTotals), proxyTotals, lokiTotals)
	}
	tplAssertClose(t, "T8 Σ", tplSum(proxyTotals), tplSum(lokiTotals), 0.10)
}

// TestTemplate_BacktickLineFormat is the D1/D2 shape: a backtick-quoted
// `| line_format`, which used to reach the client with its backticks printed.
func TestTemplate_BacktickLineFormat(t *testing.T) {
	ensureTemplateDataIngested(t)

	queries := map[string]string{
		"single_line_filter": fmt.Sprintf("{container=\"db-migrator-services\", namespace=%q} |~ `(?i).+` | json | line_format `{{.message}}`", tplStreamNS),
		"double_line_filter": fmt.Sprintf("{container=\"db-migrator-services\", namespace=%q} |~ `(?i).+` |~ `(?i).+` | json | line_format `{{.message}}`", tplStreamNS),
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			proxyLines := tplLogLines(t, tplQuery(t, proxyURL, "logs", query))
			lokiLines := tplLogLines(t, tplQuery(t, lokiURL, "logs", query))

			if len(proxyLines) != len(lokiLines) {
				t.Fatalf("line count proxy=%d loki=%d", len(proxyLines), len(lokiLines))
			}
			proxySet, lokiSet := tplSet(proxyLines), tplSet(lokiLines)
			for line := range lokiSet {
				if !proxySet[line] {
					t.Errorf("proxy is missing line %q", line)
				}
			}
			for _, line := range proxyLines {
				if strings.Contains(line, "{{") || strings.HasPrefix(line, "`") {
					t.Fatalf("proxy emitted the template text instead of evaluating it: %q", line)
				}
			}
		})
	}
}

// TestTemplate_ErrorLabelSemantics pins Loki's parse-failure model end to end.
// VictoriaLogs has no `__error__` flag, so a pushed-down `| json | __error__=""`
// used to count the 6 malformed lines Loki excludes.
func TestTemplate_ErrorLabelSemantics(t *testing.T) {
	ensureTemplateDataIngested(t)
	sel := fmt.Sprintf("{namespace=%q}", tplErrStreamN)

	t.Run("error_empty_excludes_parse_failures", func(t *testing.T) {
		q := "sum by (level) (count_over_time(" + sel + " | json | __error__=\"\" [20m]))"
		proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "instant", q))
		want := map[string]float64{"{level=info}": 5, "{level=warn}": 3, "{level=error}": 7}
		if len(proxyTotals) != len(want) {
			t.Fatalf("expected exactly %d level series (no empty group for the malformed lines), got %v", len(want), proxyTotals)
		}
		for k, v := range want {
			if proxyTotals[k] != v {
				t.Errorf("%s = %v, want %v (all=%v)", k, proxyTotals[k], v, proxyTotals)
			}
		}
		if _, ok := proxyTotals["{}"]; ok {
			t.Errorf("parse-failed lines must not form an empty-label group: %v", proxyTotals)
		}
	})

	t.Run("error_nonempty_keeps_only_parse_failures", func(t *testing.T) {
		q := "sum(count_over_time(" + sel + " | json | __error__!=\"\" [20m]))"
		proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "instant", q))
		lokiTotals := tplSeriesTotals(t, tplQuery(t, lokiURL, "instant", q))
		if proxyTotals["{}"] != 6 {
			t.Errorf("expected the 6 malformed lines, got %v", proxyTotals)
		}
		if proxyTotals["{}"] != lokiTotals["{}"] {
			t.Errorf("proxy=%v loki=%v", proxyTotals, lokiTotals)
		}
	})

	t.Run("log_query_excludes_parse_failures", func(t *testing.T) {
		q := sel + ` | json | __error__=""`
		proxyLines := tplLogLines(t, tplQuery(t, proxyURL, "logs", q))
		lokiLines := tplLogLines(t, tplQuery(t, lokiURL, "logs", q))
		if len(proxyLines) != 15 {
			t.Errorf("proxy returned %d lines, want the 15 well-formed ones", len(proxyLines))
		}
		if len(proxyLines) != len(lokiLines) {
			t.Errorf("line count proxy=%d loki=%d", len(proxyLines), len(lokiLines))
		}
	})

	t.Run("drop_error_filters_nothing", func(t *testing.T) {
		q := "sum(count_over_time(" + sel + " | json | drop __error__, __error_details__ [20m]))"
		proxyTotals := tplSeriesTotals(t, tplQuery(t, proxyURL, "instant", q))
		lokiTotals := tplSeriesTotals(t, tplQuery(t, lokiURL, "instant", q))
		if proxyTotals["{}"] != 21 {
			t.Errorf("`drop __error__` must keep all 21 lines, got %v", proxyTotals)
		}
		if proxyTotals["{}"] != lokiTotals["{}"] {
			t.Errorf("proxy=%v loki=%v", proxyTotals, lokiTotals)
		}
	})
}

// TestTemplate_UnknownFunctionIsRejected proves the proxy never emits template
// text: an unimplemented function is a 400 naming it.
func TestTemplate_UnknownFunctionIsRejected(t *testing.T) {
	ensureTemplateDataIngested(t)

	q := fmt.Sprintf(`{namespace=%q} | json | line_format "{{ .message | totallyNotALokiFunc }}"`, tplStreamNS)
	params := url.Values{}
	params.Set("query", q)
	params.Set("start", strconv.FormatInt(tplStart.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(tplEnd.UnixNano(), 10))
	resp, err := http.Get(proxyURL + "/loki/api/v1/query_range?" + params.Encode())
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unknown template function, got %d: %s", resp.StatusCode, tplTruncate(string(body)))
	}
	if !strings.Contains(string(body), "totallyNotALokiFunc") {
		t.Errorf("the 400 must name the unsupported function, got: %s", tplTruncate(string(body)))
	}
	if strings.Contains(string(body), "{{") {
		t.Errorf("the error must not carry the template text: %s", tplTruncate(string(body)))
	}
}

// TestTemplate_ConstantFormatStaysPushedDown guards the pushdown boundary: a
// format stage with no `{{` action is expressible in LogsQL, so it must keep
// going to VictoriaLogs rather than dragging the query onto the proxy-side path.
func TestTemplate_ConstantFormatStaysPushedDown(t *testing.T) {
	ensureTemplateDataIngested(t)

	q := fmt.Sprintf(`{namespace=%q, container="db-migrator-services"} | json | line_format ""`, tplStreamNS)
	proxyLines := tplLogLines(t, tplQuery(t, proxyURL, "logs", q))
	lokiLines := tplLogLines(t, tplQuery(t, lokiURL, "logs", q))
	if len(proxyLines) != len(lokiLines) {
		t.Errorf("line count proxy=%d loki=%d", len(proxyLines), len(lokiLines))
	}
	for _, line := range proxyLines {
		if line != "" {
			t.Fatalf("`line_format \"\"` must blank every line, got %q", line)
		}
	}
}

func tplSum(m map[string]float64) float64 {
	var total float64
	for _, v := range m {
		total += v
	}
	return total
}

func tplSet(lines []string) map[string]bool {
	out := make(map[string]bool, len(lines))
	for _, l := range lines {
		out[l] = true
	}
	return out
}

// tplAssertClose compares two totals within a relative tolerance. The window
// bounds now match Loki exactly (see TestWindowBounds_HalfOpenMatchesLoki), but
// these fixtures are ingested twice — once per backend — so the first and last
// evaluation points still depend on each backend's own view of the range edge.
// The per-step equality assertion lives in the boundary test; here the totals
// only need to agree.
func tplAssertClose(t *testing.T, what string, got, want, tolerance float64) {
	t.Helper()
	if want == 0 {
		if got != 0 {
			t.Errorf("%s: proxy=%v loki=0", what, got)
		}
		return
	}
	if rel := math.Abs(got-want) / want; rel > tolerance {
		t.Errorf("%s: proxy=%v loki=%v (%.1f%% apart, tolerance %.0f%%)", what, got, want, rel*100, tolerance*100)
	}
}

// ─── window bounds and __name__ ─────────────────────────────────────────────

// tplBoundaryNS is a fixture whose entries land EXACTLY on the step boundaries:
// t0, t0+20s, t0+40s, t0+60s … with step=60s and range=1m every third entry
// sits on a bucket edge. A closed left bound counted those twice.
var (
	tplBoundaryOnce  sync.Once
	tplBoundaryNS    string
	tplBoundaryStart time.Time
	tplBoundaryEnd   time.Time
)

const tplBoundaryEntries = 30 // 20 s apart → 10 minutes

func ensureBoundaryDataIngested(t *testing.T) {
	t.Helper()
	tplBoundaryOnce.Do(func() {
		waitForReady(t, proxyURL+"/ready", 30*time.Second)
		waitForReady(t, lokiURL+"/ready", 30*time.Second)

		tplBoundaryNS = "e2e-bound-" + strconv.FormatInt(time.Now().UnixNano(), 36)
		// Anchor on a whole minute so the query's step grid and the entry
		// timestamps coincide exactly — that alignment IS the test.
		tplBoundaryEnd = time.Now().Add(-3 * time.Minute).Truncate(time.Minute)
		tplBoundaryStart = tplBoundaryEnd.Add(-time.Duration(tplBoundaryEntries*20) * time.Second)

		entries := make([]tplEntry, 0, tplBoundaryEntries)
		for i := 0; i < tplBoundaryEntries; i++ {
			entries = append(entries, tplEntry{
				ts:   tplBoundaryStart.Add(time.Duration(i*20) * time.Second),
				line: fmt.Sprintf(`{"level":"info","seq":%d}`, i),
			})
		}
		tplPush(t, map[string]string{"namespace": tplBoundaryNS, "container": "bound", "app": "bound"}, entries)
		forceVLFlush(t)

		deadline := time.Now().Add(60 * time.Second)
		q := fmt.Sprintf(`sum(count_over_time({namespace=%q}[20m]))`, tplBoundaryNS)
		for time.Now().Before(deadline) {
			if len(tplResults(t, tplBoundaryQuery(t, lokiURL, "instant", q))) > 0 {
				return
			}
			time.Sleep(time.Second)
		}
		t.Logf("warning: Loki has not made the boundary fixture queryable within 60s")
	})
}

func tplBoundaryQuery(t *testing.T, baseURL, kind, query string) map[string]interface{} {
	t.Helper()
	params := url.Values{}
	params.Set("query", query)
	path := "/loki/api/v1/query_range"
	if kind == "instant" {
		path = "/loki/api/v1/query"
		params.Set("time", strconv.FormatInt(tplBoundaryEnd.UnixNano(), 10))
	} else {
		params.Set("start", strconv.FormatInt(tplBoundaryStart.UnixNano(), 10))
		params.Set("end", strconv.FormatInt(tplBoundaryEnd.UnixNano(), 10))
		params.Set("step", "60")
	}
	resp, err := http.Get(baseURL + path + "?" + params.Encode())
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query %q against %s: status %d body %s", query, baseURL, resp.StatusCode, tplTruncate(string(raw)))
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("bad JSON from %s: %v (%s)", baseURL, err, tplTruncate(string(raw)))
	}
	return payload
}

// tplPerStep flattens a matrix into timestamp → value for the single series.
func tplPerStep(t *testing.T, payload map[string]interface{}) map[int64]float64 {
	t.Helper()
	out := map[int64]float64{}
	for _, item := range tplResults(t, payload) {
		s, _ := item.(map[string]interface{})
		values, _ := s["values"].([]interface{})
		for _, pair := range values {
			p, _ := pair.([]interface{})
			if len(p) != 2 {
				continue
			}
			ts := int64(tplFloat(p[0]))
			out[ts] += tplFloat(p[1])
		}
	}
	return out
}

// TestWindowBounds_HalfOpenMatchesLoki is the regression for the manual
// aggregation window. Entries sit exactly on the 60 s step boundaries, so a
// closed left bound put every boundary entry into two adjacent buckets and read
// 4 where Loki reads 3. The query carries a template so it takes the proxy-side
// pipeline, but the helper under test is shared with every manual-path query.
func TestWindowBounds_HalfOpenMatchesLoki(t *testing.T) {
	ensureBoundaryDataIngested(t)

	queries := map[string]string{
		"count_over_time": fmt.Sprintf(
			"sum by (level) (count_over_time({namespace=%q} | json | line_format `{{.level}}` [1m]))", tplBoundaryNS),
		"rate": fmt.Sprintf(
			"sum by (level) (rate({namespace=%q} | json | line_format `{{.level}}` [1m]))", tplBoundaryNS),
	}

	for name, q := range queries {
		t.Run(name, func(t *testing.T) {
			proxySteps := tplPerStep(t, tplBoundaryQuery(t, proxyURL, "range", q))
			lokiSteps := tplPerStep(t, tplBoundaryQuery(t, lokiURL, "range", q))

			if len(lokiSteps) == 0 {
				t.Fatal("Loki returned no data points — fixture not queryable")
			}
			for ts, want := range lokiSteps {
				got, ok := proxySteps[ts]
				if !ok {
					t.Errorf("step %d: proxy has no point, Loki=%v", ts, want)
					continue
				}
				if math.Abs(got-want) > 1e-9 {
					t.Errorf("step %d: proxy=%v loki=%v", ts, got, want)
				}
			}
			for ts, got := range proxySteps {
				if _, ok := lokiSteps[ts]; !ok {
					t.Errorf("step %d: proxy has an extra point %v", ts, got)
				}
			}
		})
	}
}

// TestBinaryMetric_NoNameLabel pins that no metric result carries VictoriaLogs'
// internal `__name__` column marker. Loki never emits it, and on the binary path
// (`… or vector(0)`) it survived because that route skips the label translator —
// so Grafana saw the series renamed to {__name__="count(*)"}.
func TestBinaryMetric_NoNameLabel(t *testing.T) {
	ensureBoundaryDataIngested(t)

	queries := []string{
		fmt.Sprintf(`sum(count_over_time({namespace=%q}[10m])) or vector(0)`, tplBoundaryNS),
		fmt.Sprintf(`sum by (container) (count_over_time({namespace=%q}[10m])) or vector(0)`, tplBoundaryNS),
		fmt.Sprintf(`sum(count_over_time({namespace=%q}[10m])) * 2`, tplBoundaryNS),
	}
	for _, q := range queries {
		t.Run(q, func(t *testing.T) {
			payload := tplBoundaryQuery(t, proxyURL, "instant", q)
			for _, item := range tplResults(t, payload) {
				s, _ := item.(map[string]interface{})
				metric, _ := s["metric"].(map[string]interface{})
				if _, bad := metric["__name__"]; bad {
					t.Errorf("result carries __name__, which Loki never emits: %v", metric)
				}
			}
		})
	}
}
