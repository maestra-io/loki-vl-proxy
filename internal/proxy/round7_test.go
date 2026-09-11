package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A Kubernetes pod label is named by Loki after its SANITIZED KEY alone —
// `strimzi.io/cluster` becomes `strimzi_io_cluster` — while VictoriaLogs keeps
// the whole path. The alias learner only ever derived the sanitized FULL path, so
// `{strimzi_io_cluster="…"}` went to the backend verbatim as a field that does not
// exist: 0 rows where Loki returned 41 035.
func TestLearnFieldAliases_KubernetesLabelLeaf(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	lt.LearnFieldAliases([]string{
		"kubernetes.pod_labels.strimzi.io/cluster",
		"kubernetes.namespace_labels.tenant_id",
		"kubernetes.pod_namespace",
	})
	if got := lt.ToVL("strimzi_io_cluster"); got != "kubernetes.pod_labels.strimzi.io/cluster" {
		t.Errorf("strimzi_io_cluster -> %q", got)
	}
	if got := lt.ToVL("tenant_id"); got != "kubernetes.namespace_labels.tenant_id" {
		t.Errorf("tenant_id -> %q", got)
	}
	// The sanitized full path keeps working too.
	if got := lt.ToVL("kubernetes_pod_labels_strimzi_io_cluster"); got != "kubernetes.pod_labels.strimzi.io/cluster" {
		t.Errorf("full path -> %q", got)
	}
}

// A leaf alias must never shadow a field the backend already has under that name.
func TestLearnFieldAliases_LeafDoesNotShadowRealField(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	lt.LearnFieldAliases([]string{"kubernetes.pod_labels.app", "app"})
	if got := lt.ToVL("app"); got != "app" {
		t.Errorf("app -> %q, want the real top-level field", got)
	}
}

// A LogQL range vector has its own window. The pushdown asks VictoriaLogs for
// buckets whose width IS the step, so a range SHORTER than the step was silently
// widened to the step. Engage the finer grid there and nowhere else: for a range
// LONGER than the step the existing path already evaluates the full window, and
// folding on top would double-count.
func TestPlanRangeWindowRollup(t *testing.T) {
	const start, end = "1700000000", "1700003600"
	for _, tc := range []struct {
		name   string
		query  string
		step   string
		want   bool
		fineNs int64
	}{
		{"range shorter than step", `count_over_time({a="b"}[30m])`, "3600", true, int64(30 * time.Minute)},
		{"range shorter, not a divisor", `count_over_time({a="b"}[7m])`, "600", true, int64(time.Minute)},
		{"rate is additive over its constant divisor", `sum(rate({a="b"}[5m]))`, "3600", true, int64(5 * time.Minute)},
		{"range equal to step", `count_over_time({a="b"}[1h])`, "3600", false, 0},
		{"range longer than step", `count_over_time({a="b"}[30m])`, "600", false, 0},
		{"non-additive aggregation", `avg_over_time({a="b"} | unwrap d [30m])`, "3600", false, 0},
		{"subquery keeps its own grid", `max_over_time(rate({a="b"}[5m])[1h:5m])`, "3600", false, 0},
		{"not a metric query", `{a="b"}`, "3600", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, ok := planRangeWindowRollup(tc.query, start, end, tc.step)
			if ok != tc.want {
				t.Fatalf("engaged=%v, want %v", ok, tc.want)
			}
			if ok && plan.fineNs != tc.fineNs {
				t.Fatalf("fine=%d, want %d", plan.fineNs, tc.fineNs)
			}
		})
	}
}

// The fold selects the inner grid's points that land on the requested step grid;
// the inner point at t already IS the `(t-range, t]` window.
func TestRollupStatsQRWindow_SelectsRequestedGrid(t *testing.T) {
	body := []byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"a":"b"},"values":[
[1700000000,"5"],[1700001800,"7"],[1700003600,"9"]]}]}}`)
	plan := rangeWindowPlan{
		startNs: 1700000000 * int64(time.Second),
		endNs:   1700003600 * int64(time.Second),
		stepNs:  int64(time.Hour),
		rangeNs: int64(30 * time.Minute),
		fineNs:  int64(30 * time.Minute),
	}
	var got struct {
		Data struct {
			Result []struct {
				Values [][]json.RawMessage `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rollupStatsQRWindow(body, plan), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Data.Result) != 1 || len(got.Data.Result[0].Values) != 2 {
		t.Fatalf("expected the two hourly points, got %+v", got.Data.Result)
	}
	if string(got.Data.Result[0].Values[0][1]) != `"5"` || string(got.Data.Result[0].Values[1][1]) != `"9"` {
		t.Fatalf("wrong points selected: %+v", got.Data.Result[0].Values)
	}
}

// Grafana's newer auto-step variable was not in the token table, so a panel using
// it was answered with `expected ], got IDENT ("_interval")`.
func TestQueryRange_GrafanaAutoIntervalToken(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer backend.Close()

	p, err := New(Config{BackendURL: backend.URL, LogLevel: "error"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	for _, token := range []string{"$__auto_interval", "${__auto_interval}", "$__auto", "$__interval", "$__range"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/loki/api/v1/query_range?query=sum%28count_over_time%28%7Bapp%3D%22a%22%7D%5B"+token+"%5D%29%29"+
				"&start=1700000000&end=1700003600&step=60", nil)
		p.handleQueryRange(rec, req)
		if rec.Code == http.StatusBadRequest {
			t.Errorf("%s rejected: %s", token, rec.Body.String())
		}
	}
}
