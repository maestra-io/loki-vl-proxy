package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
