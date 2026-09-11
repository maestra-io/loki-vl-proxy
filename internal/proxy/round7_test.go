package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		// A range LONGER than the step needs the finer grid too: round 8 measured
		// the pushdown evaluating `floor(range/step)·step`, so `[15m]`@600 came back
		// identical to `[10m]`. gcd(30m, 10m) is the step itself here, which makes
		// the plan a no-op in practice but keeps the ratio integral by construction.
		{"range longer than step", `count_over_time({a="b"}[30m])`, "600", true, int64(10 * time.Minute)},
		{"range longer than step, fractional ratio", `count_over_time({a="b"}[15m])`, "600", true, int64(5 * time.Minute)},
		{"non-additive aggregation", `avg_over_time({a="b"} | unwrap d [30m])`, "3600", false, 0},
		{"subquery keeps its own grid", `max_over_time(rate({a="b"}[5m])[1h:5m])`, "3600", false, 0},
		{"not a metric query", `{a="b"}`, "3600", false, 0},
		// Grafana's fractional `$__auto` step against a whole-second range gives a
		// sub-second gcd, which VictoriaLogs cannot bucket — those stay on the
		// existing path rather than being refused over a rounding artefact.
		{"sub-second fine grid", `sum_over_time({a="b"}[1s])`, "1.964s", false, 0},
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
		// The stub backend always answers 200, so anything else is a failed proxy
		// path — not just the 400 the missing token used to produce.
		if rec.Code != http.StatusOK {
			t.Errorf("%s -> HTTP %d: %s", token, rec.Code, rec.Body.String())
		}
	}
}

// CodeRabbit 3985990726: learned aliases persist across inventory calls, so a
// field that shows up LATER under its own exact name has to invalidate the alias
// learned for it earlier — otherwise ToVL keeps answering with the aliased field.
func TestLearnFieldAliases_ExactFieldInLaterInventoryWins(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	lt.LearnFieldAliases([]string{"kubernetes.pod_labels.app"})
	if got := lt.ToVL("app"); got != "kubernetes.pod_labels.app" {
		t.Fatalf("first inventory: app -> %q", got)
	}
	// Second call: the backend now reports a real `app` field. An inventory of
	// nothing but exact names produces no buckets at all, so the invalidation has
	// to happen before that early return.
	lt.LearnFieldAliases([]string{"app"})
	if got := lt.ToVL("app"); got != "app" {
		t.Fatalf("after the exact field appeared: app -> %q, want \"app\"", got)
	}
}

// CodeRabbit 3985990734: LogQL accepts `d`, `w` and `y`, which time.ParseDuration
// rejects. Failing to parse here silently kept the step-wide window.
func TestPlanRangeWindowRollup_DayBasedRange(t *testing.T) {
	plan, ok := planRangeWindowRollup(`count_over_time({a="b"}[1d])`, "1700000000", "1700086400", "172800")
	if !ok {
		t.Fatalf("a day-based range must plan a rollup")
	}
	if plan.rangeNs != int64(24*time.Hour) {
		t.Fatalf("range parsed as %v", time.Duration(plan.rangeNs))
	}
	if plan2, ok := planRangeWindowRollup(`count_over_time({a="b"}[1d12h])`, "1700000000", "1700259200", "259200"); !ok ||
		plan2.rangeNs != int64(36*time.Hour) {
		t.Fatalf("compound day range: ok=%v range=%v", ok, time.Duration(plan2.rangeNs))
	}
}

// CodeRabbit 3985990730: when the grid a correct evaluation needs is finer than
// this instance will scan, the only fallback is the step-wide window — the defect
// this path removes. Refuse instead, and say how to make it answerable.
func TestPlanRangeWindowRollup_RefusesInsteadOfFallingBack(t *testing.T) {
	// [7m] at a 10m step needs 1-minute buckets; over 30 days that is far past the cap.
	const start = "1700000000"
	end := "1702592000"
	plan, err, ok := planRangeWindowRollupDetailed(`count_over_time({a="b"}[7m])`, start, end, "600")
	if ok {
		t.Fatalf("expected a refusal, got a plan %+v", plan)
	}
	if err == nil {
		t.Fatalf("an unplannable rollup must report WHY, not silently fall back to the step-wide window")
	}
	for _, want := range []string{"7m0s", "10m0s", "widen the step"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message missing %q: %s", want, err.Error())
		}
	}
	// A grid inside the cap still plans normally.
	if _, err, ok := planRangeWindowRollupDetailed(`count_over_time({a="b"}[7m])`, start, "1700086400", "600"); err != nil || !ok {
		t.Fatalf("a grid inside the cap must plan: err=%v ok=%v", err, ok)
	}
}

// CodeRabbit 3985990756: an UNRECOGNISED named value is no level at all to Loki,
// and must not suppress the line-text heuristic the way a real level does.
func TestApplyDerivedLevel_UnrecognisedNamedValueFallsBackToText(t *testing.T) {
	p := &Proxy{derivedLevelFields: []string{"level"}}
	labels := map[string]string{"level": "Bizarre"}
	p.applyDerivedLevel(labels, "boom [error] while writing")
	if labels["detected_level"] != "error" {
		t.Fatalf("detected_level = %q, want error from the line text", labels["detected_level"])
	}
	// A RECOGNISED value still wins over the line text.
	real := map[string]string{"level": "warning"}
	p.applyDerivedLevel(real, "boom [error] while writing")
	if real["detected_level"] != "warn" {
		t.Fatalf("detected_level = %q, want warn from the named field", real["detected_level"])
	}
}
