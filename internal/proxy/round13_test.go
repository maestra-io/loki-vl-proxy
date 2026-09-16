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

// newMaestraProxy builds a proxy configured the way the pod-logs deployment
// runs it (fluxcd base/pod-logs/loki-api.yaml): vlagent-shaped storage, mapped
// stream labels with fallback chains, a computed job, derived level, the
// message as the line, line filters fanned out over the split-out fields.
func newMaestraProxy(t *testing.T, backend string) *Proxy {
	t.Helper()
	f := false
	p, err := New(Config{
		BackendURL: backend, Cache: cache.New(60, 100), LogLevel: "error",
		LabelStyle: LabelStyleUnderscores, MetadataFieldMode: MetadataFieldModeHybrid, TranslateOTel: &f,
		FieldMappings: []FieldMapping{
			{VLField: "kubernetes.pod_namespace", LokiLabel: "namespace"},
			{VLField: "kubernetes.container_name", LokiLabel: "container"},
			{VLField: "kubernetes.pod_name", LokiLabel: "pod"},
			{VLField: "kubernetes.pod_node_name", LokiLabel: "node_name"},
			{VLFields: []string{"kubernetes.pod_labels.app", "kubernetes.pod_labels.app.kubernetes.io/name"}, LokiLabel: "app"},
			{VLFields: []string{"kubernetes.pod_labels.product", "kubernetes.namespace_labels.product"}, LokiLabel: "product"},
		},
		ComputedLabels:      []ComputedLabel{{LokiLabel: "job", Join: []string{"namespace", "app"}, Sep: "/"}},
		DerivedLevelFields:  []string{"loglevel", "LogLevel", "level", "Level", "severity", "severity_text", "lvl"},
		DerivedLevelGroupBy: true,
		MsgFieldAliases:     []string{"message", "Message", "msg", "log"},
		LineField:           "_msg",
		LineFilterFields:    []string{"_msg", "Scopes", "Exception", "Category", "State.*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.maxStatsQuerySeries = 10000
	return p
}

// rowsVL serves the given ndjson rows for /select/logsql/query and an empty
// matrix for the stats endpoints.
func rowsVL(t *testing.T, rows ...string) (*httptest.Server, func() []string) {
	t.Helper()
	return newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		switch {
		case strings.Contains(r.URL.Path, "stats_query"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
		case strings.HasSuffix(r.URL.Path, "/field_names"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"values":[]}`)
		default:
			w.Header().Set("Content-Type", "application/x-ndjson")
			for _, row := range rows {
				fmt.Fprintln(w, row)
			}
		}
	})
}

// fluxRow is a vlagent row of a flux-system controller: the JSON line split
// into fields (level, ts, controller), the message in _msg.
func fluxRow(ts, pod, app, level string) string {
	return fmt.Sprintf(`{"_time":"%s","_msg":"Reconciler error","_stream":"{kubernetes.container_name=\"manager\",kubernetes.pod_name=\"%s\",kubernetes.pod_namespace=\"flux-system\"}","kubernetes.container_name":"manager","kubernetes.pod_name":"%s","kubernetes.pod_namespace":"flux-system","kubernetes.pod_labels.app":"%s","kubernetes.pod_node_name":"node1","level":"%s","ts":"%s","controller":"helmrelease"}`, ts, pod, pod, app, level, ts)
}

const plainRow = `{"_time":"2023-11-14T22:13:31Z","_msg":"plain text line","_stream":"{kubernetes.pod_namespace=\"flux-system\"}","kubernetes.pod_namespace":"flux-system"}`

func queryRange(t *testing.T, p *Proxy, logql string, start, end, step int64) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?query="+url.QueryEscape(logql)+
		fmt.Sprintf("&start=%d&end=%d&step=%d&limit=100", start, end, step), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d %s", logql, rec.Code, rec.Body.String())
	}
	return rec
}

func queryInstant(t *testing.T, p *Proxy, logql string, at int64) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	p.handleQuery(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query?query="+url.QueryEscape(logql)+fmt.Sprintf("&time=%d", at), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: HTTP %d %s", logql, rec.Code, rec.Body.String())
	}
	return rec
}

// Round 13, class I: `| level=~…` right after the selector, then a line
// filter. The injected unpack pipes keep the stored fields, so the fan-out
// over Category still finds the four Kafka errors (Loki 4, proxy was {}).
func TestRound13_LevelFilterBeforeLineFilterKeepsStoredFields(t *testing.T) {
	vl, seen := rowsVL(t)
	p := newMaestraProxy(t, vl.URL)
	queryRange(t, p, `{app="pushhub"} | level=~"error|critical|fatal" |~ "(?i)kafka"`, 1700000000, 1700003600, 60)
	var got string
	for _, q := range seen() {
		if strings.Contains(q, "/select/logsql/query") {
			got = q
		}
	}
	for _, want := range []string{
		"| unpack_json from _msg keep_original_fields | unpack_logfmt from _msg keep_original_fields | filter (",
		`Category:~"(?i)kafka"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("want %s in %s", want, got)
		}
	}
}

// Round 13, class J: `| json | __error__ != ""` on rows whose JSON the
// collector already split matched EVERY line (26017 = all) and
// `__error__ = ""` none; Loki, holding the whole JSON line, parses it. Only
// the plain-text row is a parser error now — on the metric path and the logs
// path alike.
func TestRound13_JSONErrorFilterOnCollectorSplitRows(t *testing.T) {
	vl, _ := rowsVL(t, fluxRow("2023-11-14T22:13:30Z", "helm-1", "helm-controller", "info"), plainRow)
	p := newMaestraProxy(t, vl.URL)

	rec := queryInstant(t, p, `sum(count_over_time({namespace="flux-system"} | json | __error__ != "" [1h]))`, 1700000100)
	if !strings.Contains(rec.Body.String(), `"value":[1700000100,"1"]`) {
		t.Fatalf("only the plain-text row is a parser error, got %s", rec.Body.String())
	}

	rec = queryRange(t, p, `{namespace="flux-system"} | json | __error__ = ""`, 1699996500, 1700003600, 900)
	body := rec.Body.String()
	if !strings.Contains(body, `"Reconciler error"`) || strings.Contains(body, "plain text line") {
		t.Fatalf("the split row parses, the plain row does not: %s", body)
	}
}

// Round 13, N2 (logs form): the label-filter regexp `"\\d{4}-…"` reached the
// proxy-side evaluator unescaped twice and dropped every row (Loki 1000,
// proxy 0). The metric path was already right; the logs path now keeps the row.
func TestRound13_DoubleQuotedRegexpLabelFilterOnTheLogsPath(t *testing.T) {
	vl, _ := rowsVL(t, `{"_time":"2023-11-14T22:13:30Z","_msg":"2026-09-16 10:03:18 WARN  [kafka-admin-client-thread] MirrorCheckpoint x","_stream":"{kubernetes.pod_namespace=\"a\"}","kubernetes.pod_namespace":"a","kubernetes.pod_labels.app":"kafka-mirror-maker-2"}`)
	p := newMaestraProxy(t, vl.URL)
	q := "{namespace=~\"a|b\", app=\"kafka-mirror-maker-2\"} | json | message=~\"\\\\d{4}-\\\\d{2}-\\\\d{2} \\\\d{2}:\\\\d{2}:\\\\d{2} (ERROR|WARN) .*\" | message!~\"(?i).*could not alter configuration.*\" | line_format \"{{.message}}\""
	rec := queryRange(t, p, q, 1699996500, 1700003600, 900)
	if !strings.Contains(rec.Body.String(), "MirrorCheckpoint x") {
		t.Fatalf("the matching row was dropped: %s", rec.Body.String())
	}
}

func seriesLabels(t *testing.T, body []byte) []map[string]string {
	t.Helper()
	v, err := fj.ParseBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, item := range v.GetArray("data", "result") {
		m := map[string]string{}
		item.GetObject("metric").Visit(func(k []byte, vv *fj.Value) { m[string(k)] = string(vv.GetStringBytes()) })
		out = append(out, m)
	}
	return out
}

func assertStreamIdentity(t *testing.T, path string, series []map[string]string, wantApp string) {
	t.Helper()
	found := false
	for _, m := range series {
		if m["app"] != wantApp {
			continue
		}
		found = true
		for _, k := range []string{"namespace", "container", "pod", "node_name", "job", "service_name"} {
			if m[k] == "" {
				t.Errorf("%s: series %v lacks %s", path, m, k)
			}
		}
		if m["job"] != "flux-system/"+wantApp || m["service_name"] != wantApp {
			t.Errorf("%s: job/service_name off in %v", path, m)
		}
		for _, k := range []string{"level", "detected_level"} {
			if _, has := m[k]; has {
				t.Errorf("%s: a bare range aggregation carries the derived %s: %v", path, k, m)
			}
		}
	}
	if !found {
		t.Errorf("%s: no series for app=%s in %v", path, wantApp, series)
	}
}

// Round 13, class G: a bare range aggregation is keyed the way Loki keys a
// stream — every collector label (the mapped app/product/node_name, the
// computed job) and no derived level. The raw sliding-window path answered
// {container, namespace, pod, level, service_name="manager"}: app was
// missing, level split one pod into two series, service_name named the
// container (Loki 11 series with 54 points, proxy 9 with 51 on
// `count_over_time({namespace="flux-system"}[1h])`).
func TestRound13_BareRangeIdentity_RawPath(t *testing.T) {
	vl, _ := rowsVL(t,
		fluxRow("2023-11-14T22:13:30Z", "helm-1", "helm-controller", "info"),
		fluxRow("2023-11-14T22:13:31Z", "helm-1", "helm-controller", "error"),
		fluxRow("2023-11-14T22:13:32Z", "src-1", "source-controller", "info"))
	p := newMaestraProxy(t, vl.URL)
	rec := queryRange(t, p, `count_over_time({namespace="flux-system"}[1h])`, 1699996500, 1700003600, 900)
	series := seriesLabels(t, rec.Body.Bytes())
	if len(series) != 2 {
		t.Fatalf("want one series per pod, got %d: %v", len(series), series)
	}
	assertStreamIdentity(t, "raw", series, "helm-controller")
	assertStreamIdentity(t, "raw", series, "source-controller")
}

// The same identity on the template path (a pipeline the proxy evaluates)
// with a NARROW parser — `| json msg="msg"` names its field, so the row's other
// split-out fields are not Loki's parsed labels and do not key the series
// (round 12 lock: a broad `| json` keys by every field, as Loki does).
func TestRound13_BareRangeIdentity_TemplatePath(t *testing.T) {
	vl, _ := rowsVL(t,
		fluxRow("2023-11-14T22:13:30Z", "helm-1", "helm-controller", "info"),
		fluxRow("2023-11-14T22:13:31Z", "helm-1", "helm-controller", "error"))
	p := newMaestraProxy(t, vl.URL)
	rec := queryInstant(t, p, `count_over_time({namespace="flux-system"} | json msg="msg" | line_format "{{.msg}}" | drop msg [1h])`, 1700000100)
	series := seriesLabels(t, rec.Body.Bytes())
	if len(series) != 1 {
		t.Fatalf("want one series for the pod, got %d: %v", len(series), series)
	}
	// service_name is not part of the template identity (round 12 lock).
	series[0]["service_name"] = "helm-controller"
	assertStreamIdentity(t, "template", series, "helm-controller")
}

// And on the native stats path (range == step): VictoriaLogs groups by the
// stream AND the mapped fields, the response resolves each chain and joins
// the computed label.
func TestRound13_BareRangeIdentity_NativePath(t *testing.T) {
	vl, seen := newRecordingVL(t, func(w http.ResponseWriter, r *http.Request, _ string) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "stats_query_range") {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[`+
				`{"metric":{"_stream":"{kubernetes.container_name=\"manager\",kubernetes.pod_name=\"helm-1\",kubernetes.pod_namespace=\"flux-system\"}","kubernetes.pod_namespace":"flux-system","kubernetes.container_name":"manager","kubernetes.pod_name":"helm-1","kubernetes.pod_node_name":"node1","app":"helm-controller","product":"infra"},"values":[[1700003600.000001,"5"]]}`+
				`]}}`)
			return
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	})
	p := newMaestraProxy(t, vl.URL)
	rec := queryRange(t, p, `count_over_time({namespace="flux-system"}[1h])`, 1700000000, 1700007200, 3600)
	grouped := false
	for _, q := range seen() {
		grouped = grouped || strings.Contains(q, `| format if ("kubernetes.pod_labels.app.kubernetes.io/name":*) "<kubernetes.pod_labels.app.kubernetes.io/name>" as app | format if ("kubernetes.pod_labels.app":*) "<kubernetes.pod_labels.app>" as app | format if ("kubernetes.namespace_labels.product":*) "<kubernetes.namespace_labels.product>" as product | format if ("kubernetes.pod_labels.product":*) "<kubernetes.pod_labels.product>" as product | stats by (_stream, "kubernetes.pod_namespace", "kubernetes.container_name", "kubernetes.pod_name", "kubernetes.pod_node_name", app, product) count()`)
	}
	if !grouped {
		t.Fatalf("the bare aggregation must group by the stream and the mapped fields: %v", seen())
	}
	series := seriesLabels(t, rec.Body.Bytes())
	assertStreamIdentity(t, "native", series, "helm-controller")
	if series[0]["product"] != "infra" {
		t.Fatalf("the product chain falls back to the namespace label: %v", series)
	}
}
