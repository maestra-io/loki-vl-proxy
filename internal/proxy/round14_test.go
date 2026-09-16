package proxy

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"

	fj "github.com/valyala/fastjson"
)

// lokiQuantile is Loki's quantile (pkg/logql/range_vector.go, borrowed from
// Prometheus): sort, rank = q·(n−1), linear interpolation between the two
// neighbouring order statistics.
func lokiQuantile(q float64, values []float64) float64 {
	if len(values) == 0 {
		return math.NaN()
	}
	if q < 0 {
		return math.Inf(-1)
	}
	if q > 1 {
		return math.Inf(+1)
	}
	sort.Float64s(values)
	n := float64(len(values))
	rank := q * (n - 1)
	lowerIndex := math.Max(0, math.Floor(rank))
	upperIndex := math.Min(n-1, lowerIndex+1)
	weight := rank - math.Floor(rank)
	return values[int(lowerIndex)]*(1-weight) + values[int(upperIndex)]*weight
}

// Round 14, C013/C014: both proxy quantile implementations are Loki's
// formula, sample for sample. The documented reference (ten samples 109…199:
// p95 194.5, p50 154) plus 200 random sets of 1…40 samples at seven phis.
func TestRound14_QuantileMatchesLoki(t *testing.T) {
	ten := []float64{109, 119, 129, 139, 149, 159, 169, 179, 189, 199}
	if got := quantileFloat64(ten, 0.95); got != 194.5 {
		t.Fatalf("quantileFloat64 p95 = %v, want 194.5", got)
	}
	if got := quantileFloat64(ten, 0.5); got != 154 {
		t.Fatalf("quantileFloat64 p50 = %v, want 154", got)
	}
	rng := rand.New(rand.NewSource(14))
	for i := 0; i < 200; i++ {
		n := 1 + rng.Intn(40)
		values := make([]float64, n)
		window := make([]bareParserMetricSample, n)
		for j := range values {
			values[j] = math.Round(rng.Float64()*3000) / 2 // .0 / .5 steps, like duration_ms
			window[j] = bareParserMetricSample{tsNanos: int64(j), value: values[j]}
		}
		for _, phi := range []float64{0, 0.1, 0.5, 0.9, 0.95, 0.99, 1} {
			want := lokiQuantile(phi, append([]float64(nil), values...))
			if got := quantileFloat64(values, phi); math.Abs(got-want) > 1e-9 {
				t.Fatalf("quantileFloat64(phi=%v, n=%d) = %v, want %v", phi, n, got, want)
			}
			spec := bareParserMetricCompatSpec{funcName: "quantile_over_time", quantile: phi}
			if got := bareParserMetricWindowValue("quantile_over_time", window, spec); math.Abs(got-want) > 1e-9 {
				t.Fatalf("bareParserMetricWindowValue(phi=%v, n=%d) = %v, want %v", phi, n, got, want)
			}
		}
	}
}

func logLines(t *testing.T, body []byte) []string {
	t.Helper()
	v, err := fj.ParseBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range v.GetArray("data", "result") {
		for _, e := range s.GetArray("values") {
			out = append(out, string(e.GetArray()[1].GetStringBytes()))
		}
	}
	return out
}

func metricValues(t *testing.T, body []byte) []float64 {
	t.Helper()
	v, err := fj.ParseBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	var out []float64
	add := func(pt *fj.Value) {
		f, _ := strconv.ParseFloat(string(pt.GetArray()[1].GetStringBytes()), 64)
		out = append(out, f)
	}
	for _, s := range v.GetArray("data", "result") {
		for _, pt := range s.GetArray("values") {
			add(pt)
		}
		if pt := s.Get("value"); pt != nil {
			add(pt)
		}
	}
	return out
}

// Round 14, C032: Loki's ingester drops an entry that is an exact duplicate
// (timestamp and whole line) of one already in the stream. Two identical
// rows collapse to one on the logs path and on the row-scanning count path;
// a row with the same _msg but another field is a different line and stays.
// -dedupe-exact-duplicates=false keeps all three.
func TestRound14_DedupeExactDuplicates(t *testing.T) {
	row := func(controller string) string {
		return fmt.Sprintf(`{"_time":"2023-11-14T22:13:31.000000001Z","_msg":"Reconciler error","_stream":"{kubernetes.container_name=\"manager\",kubernetes.pod_name=\"p1\",kubernetes.pod_namespace=\"flux-system\"}","kubernetes.container_name":"manager","kubernetes.pod_name":"p1","kubernetes.pod_namespace":"flux-system","kubernetes.pod_labels.app":"helm-controller","controller":"%s"}`, controller)
	}
	srv, _ := rowsVL(t, row("helmrelease"), row("helmrelease"), row("kustomization"))
	defer srv.Close()

	p := newMaestraProxy(t, srv.URL)
	lines := logLines(t, queryRange(t, p, `{namespace="flux-system"}`, 1700000000, 1700000100, 0).Body.Bytes())
	if len(lines) != 2 {
		t.Fatalf("logs path: got %d lines, want 2 (one exact duplicate collapsed): %q", len(lines), lines)
	}
	if got := maxValue(metricValues(t, queryRange(t, p, `count_over_time({namespace="flux-system"}[1h])`, 1699996500, 1700003600, 900).Body.Bytes())); got != 2 {
		t.Fatalf("raw count path: peak %v, want 2 (the duplicate collapsed, the other line kept)", got)
	}

	off := newMaestraProxy(t, srv.URL) // a fresh instance: the first answer sits in p's query-range cache
	off.dedupeExactDuplicates = false
	if lines := logLines(t, queryRange(t, off, `{namespace="flux-system"}`, 1700000000, 1700000100, 0).Body.Bytes()); len(lines) != 3 {
		t.Fatalf("dedup off: got %d lines, want 3", len(lines))
	}
}

// Round 14, A021: bytes_over_time measures the line Loki stored — the record
// re-serialised the way vector shipped it — not the message. The Go-side
// count equals encoding/json of the same fields plus the wrapper; the
// translation sums the VictoriaLogs-side derivation; "line" keeps len(_msg).
func TestRound14_BytesOverTimeSourceRecord(t *testing.T) {
	const msg = "Reconciliation finished in 0s"
	rowJSON := `{"_time":"2026-09-16T09:54:04.141Z","_msg":"` + msg + `","_stream":"{kubernetes.pod_namespace=\"flux-system\"}","_stream_id":"abc","kubernetes.pod_namespace":"flux-system","kubernetes.pod_labels.app":"flux-operator","ResourceSetInputProvider.name":"auth-jwt","controller":"resourcesetinputprovider","level":"info","reconcileID":"9cb4740f-b2f1-4742-9766-8ce40babb265","tab":"a\tb\"c"}`
	line := map[string]string{
		"ResourceSetInputProvider.name": "auth-jwt", "controller": "resourcesetinputprovider", "level": "info",
		"reconcileID": "9cb4740f-b2f1-4742-9766-8ce40babb265", "tab": "a\tb\"c",
		"message": msg, "path": "/", "source_type": "http_server", "timestamp": "2026-09-16T09:54:04.141000000Z",
	}
	want, _ := json.Marshal(line) // sorted keys, no HTML escaping needed for these values
	v, err := fj.ParseBytes([]byte(rowJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got := lokiRecordLineLenFJ(v, []string{"kubernetes.*"}); got != len(want) {
		t.Fatalf("lokiRecordLineLenFJ = %d, want %d (%s)", got, len(want), want)
	}
	var entry map[string]interface{}
	_ = json.Unmarshal([]byte(rowJSON), &entry)
	if got := lokiRecordLineLenMap(entry, []string{"kubernetes.*"}); got != len(want) {
		t.Fatalf("lokiRecordLineLenMap = %d, want %d", got, len(want))
	}

	srv, _ := rowsVL(t)
	defer srv.Close()
	p := newMaestraProxy(t, srv.URL)
	if got := p.rowLineBytesFJ(v); got != float64(len(want)) {
		t.Fatalf("rowLineBytesFJ (record) = %v, want %d", got, len(want))
	}
	if got, ok := p.extractManualSampleValueFJ(v, "__bytes__", ""); !ok || got != float64(len(want)) {
		t.Fatalf("__bytes__ (record) = %v, want %d", got, len(want))
	}
	logsql := translate(t, p, `sum by (app) (bytes_over_time({namespace="flux-system"}[1h]))`)
	if !strings.Contains(logsql, "| pack_json as __lvp_l | pack_json fields (_time, _stream, _stream_id, kubernetes.*) as __lvp_x") ||
		!strings.Contains(logsql, "math __lvp_a - __lvp_b + 88 as __lvp_bytes") || !strings.Contains(logsql, "sum(__lvp_bytes)") || strings.Contains(logsql, "sum_len") {
		t.Fatalf("record bytes translation: %s", logsql)
	}

	p.bytesSourceRecord = false
	p.translationCache = nil // the record-mode translation above is cached by query text
	if got := p.rowLineBytesFJ(v); got != float64(len(msg)) {
		t.Fatalf("rowLineBytesFJ (line) = %v, want %d", got, len(msg))
	}
	if logsql := translate(t, p, `sum by (app) (bytes_over_time({namespace="flux-system"}[1h]))`); !strings.Contains(logsql, "sum_len(_msg)") || strings.Contains(logsql, "pack_json") {
		t.Fatalf("line bytes translation: %s", logsql)
	}
}

// Round 14, A120: Loki rejected lines over limits_config.max_line_size
// (512KB here) at ingest; VictoriaLogs kept them. With -loki-max-line-size
// the proxy drops them on the logs path and on the row-scanning count path,
// and the native count of a query that already scans rows filters on the
// same derived size; a bare stream count stays a block-level count.
func TestRound14_LokiMaxLineSize(t *testing.T) {
	big := strings.Repeat("x", 700)
	row := func(exc string) string {
		return fmt.Sprintf(`{"_time":"2023-11-14T22:13:31Z","_msg":"Broker: Message size too large","_stream":"{kubernetes.pod_namespace=\"joom-pro\"}","kubernetes.pod_namespace":"joom-pro","kubernetes.pod_labels.product":"tenant","Category":"Kafka","Exception":"%s"}`, exc)
	}
	srv, _ := rowsVL(t, row("short"), row(big))
	defer srv.Close()
	p := newMaestraProxy(t, srv.URL)
	p.lokiMaxLineSize = 512
	if lines := logLines(t, queryRange(t, p, `{product="tenant"}`, 1700000000, 1700000100, 0).Body.Bytes()); len(lines) != 1 {
		t.Fatalf("logs path: got %d lines, want 1 (the 700-byte exception dropped)", len(lines))
	}
	if got := maxValue(metricValues(t, queryRange(t, p, `count_over_time({product="tenant"}[1h])`, 1699996500, 1700003600, 900).Body.Bytes())); got != 1 {
		t.Fatalf("raw count path: peak %v, want 1", got)
	}
	scanning := translate(t, p, `sum by (product) (count_over_time({product="tenant"} |= "Message size too large" | json [1m]))`)
	if !strings.Contains(scanning, "| filter __lvp_bytes:<=512 | delete __lvp_bytes") {
		t.Fatalf("native count with a line filter must carry the size filter: %s", scanning)
	}
	if bare := translate(t, p, `sum by (product) (count_over_time({product="tenant"}[1m]))`); strings.Contains(bare, "pack_json") {
		t.Fatalf("bare stream count must stay a block-level count: %s", bare)
	}
	off := newMaestraProxy(t, srv.URL) // a fresh instance: the first answer sits in p's query-range cache
	if lines := logLines(t, queryRange(t, off, `{product="tenant"}`, 1700000000, 1700000100, 0).Body.Bytes()); len(lines) != 2 {
		t.Fatalf("limit off: got %d lines, want 2", len(lines))
	}
}

// Round 14, D030: a bare range aggregation over `| json` keys its series by
// the parsed fields under Loki's spelling only — `State_ElapsedMilliseconds`
// and `State__OriginalFormat_`, never the dotted VictoriaLogs name, none of
// the collector's kubernetes.* metadata (not in the line), and the lifted
// message as `message`.
func TestRound14_BareJSONIdentityUsesLokiNames(t *testing.T) {
	row := `{"_time":"2023-11-14T22:13:31Z","_msg":"Request finished","_stream":"{kubernetes.container_name=\"api\",kubernetes.pod_name=\"api-1\",kubernetes.pod_namespace=\"operations-bulk-api\"}","kubernetes.container_name":"api","kubernetes.pod_name":"api-1","kubernetes.pod_namespace":"operations-bulk-api","kubernetes.pod_labels.app":"api","kubernetes.pod_ip":"10.0.0.1","Category":"Hosting","State.ElapsedMilliseconds":"16032.6","State.{OriginalFormat}":"Request finished {Method}"}`
	srv, _ := rowsVL(t, row)
	defer srv.Close()
	p := newMaestraProxy(t, srv.URL)
	series := seriesLabels(t, queryRange(t, p, `count_over_time({namespace="operations-bulk-api"} | json | State_ElapsedMilliseconds > 10000 [1h])`, 1700000000, 1700000000, 60).Body.Bytes())
	if len(series) != 1 {
		t.Fatalf("want one series, got %v", series)
	}
	m := series[0]
	for _, want := range []string{"State_ElapsedMilliseconds", "State__OriginalFormat_", "Category", "message", "namespace", "pod", "container", "app"} {
		if _, ok := m[want]; !ok {
			t.Errorf("series lacks %q: %v", want, m)
		}
	}
	for k := range m {
		if strings.ContainsAny(k, ".{}") || strings.HasPrefix(k, "kubernetes_") {
			t.Errorf("series carries a non-Loki label %q: %v", k, m)
		}
	}
}

func maxValue(values []float64) float64 {
	m := 0.0
	for _, v := range values {
		m = math.Max(m, v)
	}
	return m
}

func translate(t *testing.T, p *Proxy, logql string) string {
	t.Helper()
	out, err := p.translateQueryWithContext(t.Context(), logql)
	if err != nil {
		t.Fatalf("%s: %v", logql, err)
	}
	return out
}
