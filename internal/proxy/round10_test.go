package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// --- defect 1: the bounded sort ---

func TestSortByTimePipeCarriesTheLimit(t *testing.T) {
	cases := []struct {
		forward bool
		n       int
		want    string
	}{
		{false, 1000, " | sort by (_time desc) limit 1000"},
		{true, 200, " | sort by (_time) limit 200"},
		// A caller that folds the whole match client-side must not be truncated.
		{false, 0, " | sort by (_time desc)"},
		{true, -1, " | sort by (_time)"},
	}
	for _, tc := range cases {
		if got := sortByTimePipe(tc.forward, tc.n); got != tc.want {
			t.Errorf("sortByTimePipe(%v, %d) = %q, want %q", tc.forward, tc.n, got, tc.want)
		}
	}
}

// The logs path must push the effective limit into LogsQL. Without it
// VictoriaLogs buffers the whole match to satisfy an unbounded `| sort`, which
// is what pinned both us-omega replicas at 255.5 MiB of a 256 MiB limit.
func TestLogsPathPushesLimitIntoLogsQL(t *testing.T) {
	var received atomic.Value
	received.Store("")
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		received.Store(r.FormValue("query"))
		_, _ = w.Write([]byte{})
	}))
	defer vl.Close()

	for _, tc := range []struct{ path, want string }{
		{`/loki/api/v1/query_range?query=%7Bapp%3D%22nginx%22%7D&start=1&end=2&limit=37`, "| sort by (_time desc) limit 37"},
		{`/loki/api/v1/query_range?query=%7Bapp%3D%22nginx%22%7D&start=1&end=2&limit=37&direction=forward`, "| sort by (_time) limit 37"},
		// No limit given: the proxy's own maxLines ceiling still has to reach VL.
		{`/loki/api/v1/query_range?query=%7Bapp%3D%22nginx%22%7D&start=1&end=2`, "| sort by (_time desc) limit "},
	} {
		doGet(t, vl.URL, tc.path)
		got, _ := received.Load().(string)
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s\n  got:  %q\n  want it to contain %q", tc.path, got, tc.want)
		}
	}
}

// --- defect 2: the empty-valued group survives the Phase-2 whitelist ---

// VictoriaLogs matches a row whose field is ABSENT with `in("")` — measured on
// v1.50.0 — so admitting the empty value is all Phase 2 needs.
func TestBuildVLInFilterKeepsEmptyValue(t *testing.T) {
	got := buildVLInFilter("level", []string{"info", "warn", ""})
	if want := `level:in("info","warn","")`; got != want {
		t.Errorf("buildVLInFilter = %q, want %q", got, want)
	}
}

// Same family as CM16: a value carrying a backslash must be doubled, or the
// whole query is an HTTP 400.
func TestBuildVLInFilterEscapesBackslashes(t *testing.T) {
	got := buildVLInFilter("path", []string{`C:\temp`, `say "hi"`})
	if want := `path:in("C:\\temp","say \"hi\"")`; got != want {
		t.Errorf("buildVLInFilter = %q, want %q", got, want)
	}
}

// --- defect D: label-alias resolution is deterministic, not replica-local ---

// Before round 10 an alias was learned ONLY as a side effect of a metadata
// request that missed its cache. A replica that had served only query_range
// therefore translated `{strimzi_io_cluster="x"}` to a field VictoriaLogs does
// not have — 0 rows, HTTP 200 — while its sibling answered 5000, and the
// translation cache froze whichever answer came first.
func TestLabelAliasResolvedOnTheQueryPath(t *testing.T) {
	const vlField = "kubernetes.pod_labels.strimzi.io/cluster"
	var fieldNamesCalls atomic.Int32
	var received atomic.Value
	received.Store("")

	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch {
		case strings.Contains(r.URL.Path, "field_names"):
			fieldNamesCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{
					{"value": vlField, "hits": 10},
					{"value": "app", "hits": 10},
				},
			})
		default:
			received.Store(r.FormValue("query"))
			_, _ = w.Write([]byte{})
		}
	}))
	defer vl.Close()

	c := cache.New(60*time.Second, 1000)
	p, err := New(Config{BackendURL: vl.URL, Cache: c, LogLevel: "error", LabelStyle: LabelStyleUnderscores})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	// A fresh replica that has served NOTHING else.
	if p.labelTranslator.ToVL("strimzi_io_cluster") != "strimzi_io_cluster" {
		t.Fatal("precondition: the alias must be unknown before the query")
	}
	got, err := p.translateQueryWithContext(context.Background(), `{strimzi_io_cluster="kf-x"}`)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	if !strings.Contains(got, vlField) {
		t.Errorf("translation did not resolve the alias: %q", got)
	}
	if fieldNamesCalls.Load() == 0 {
		t.Error("the field inventory was never consulted")
	}

	// And the grouping position, which is what returned 4 series with an empty
	// value: VictoriaLogs groups an absent field under no value at all.
	got, err = p.translateQueryWithContext(context.Background(),
		`sum(count_over_time({app="kafka"}[5m])) by (strimzi_io_cluster)`)
	if err != nil {
		t.Fatalf("translate grouping: %v", err)
	}
	if strings.Contains(got, "(strimzi_io_cluster)") {
		t.Errorf("grouping still names the unresolved Loki label: %q", got)
	}
}

// The RESPONSE direction has to answer under the name Loki uses. Sanitizing the
// whole VL path gives `kubernetes_pod_labels_strimzi_io_cluster`, which no
// dashboard selects on — a grouping would carry real values under a label name
// nobody asked for, which is only half a fix for the empty-value symptom.
func TestLearnedAliasRoundTripsBothWays(t *testing.T) {
	const vlField = "kubernetes.pod_labels.strimzi.io/cluster"
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	lt.LearnFieldAliases([]string{vlField, "app"})

	if got := lt.ToVL("strimzi_io_cluster"); got != vlField {
		t.Errorf("ToVL(strimzi_io_cluster) = %q, want %q", got, vlField)
	}
	if got := lt.ToLoki(vlField); got != "strimzi_io_cluster" {
		t.Errorf("ToLoki(%s) = %q, want %q", vlField, got, "strimzi_io_cluster")
	}
	// A field that is not in a Kubernetes label map keeps plain sanitization.
	if got := lt.ToLoki("k8s.namespace.name"); got != "k8s_namespace_name" {
		t.Errorf("ToLoki(k8s.namespace.name) = %q", got)
	}
	// A collision on the leaf must drop BOTH directions, not leave the response
	// side answering for a mapping the query side has disowned.
	lt2 := NewLabelTranslator(LabelStyleUnderscores, nil)
	lt2.LearnFieldAliases([]string{vlField, "kubernetes.namespace_labels.strimzi.io/cluster"})
	if got := lt2.ToLoki(vlField); got != "kubernetes_pod_labels_strimzi_io_cluster" {
		t.Errorf("ambiguous leaf must not keep a reverse alias, got %q", got)
	}
}

// A pipeline label filter names a label exactly as the selector does, and the
// translator resolves it the same way — so it has to drive discovery too.
func TestLabelFilterStageNames(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{`strimzi_io_cluster="kf-x"`, []string{"strimzi_io_cluster"}},
		{`detected_level =~ "err.*"`, []string{"detected_level"}},
		{`status >= 500`, []string{"status"}},
		{`a="1" and b!="2"`, []string{"a", "b"}},
		{`a="1" or b=~"2"`, []string{"a", "b"}},
		{`not_a_filter`, nil},
	} {
		got := labelFilterStageNames(tc.raw)
		if len(got) != len(tc.want) {
			t.Errorf("labelFilterStageNames(%q) = %v, want %v", tc.raw, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("labelFilterStageNames(%q) = %v, want %v", tc.raw, got, tc.want)
				break
			}
		}
	}
	if names := queryLabelNames(`{app="x"} | strimzi_io_cluster="kf-x"`); !containsString(names, "strimzi_io_cluster") {
		t.Errorf("queryLabelNames missed the pipeline filter label: %v", names)
	}
}

// A label the inventory could not account for must NOT have its translation
// cached: the discovery window is an hour wide, and pinning a query against a
// field VictoriaLogs does not have is the defect this closes.
func TestAliasDiscoveryRefusesToCacheAnUnresolvedLabel(t *testing.T) {
	var fieldNamesCalls atomic.Int32
	vl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.Contains(r.URL.Path, "field_names") {
			fieldNamesCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			// The inventory knows nothing about the label the query names.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"values": []map[string]any{{"value": "app", "hits": 1}},
			})
			return
		}
		_, _ = w.Write([]byte{})
	}))
	defer vl.Close()

	c := cache.New(60*time.Second, 1000)
	p, err := New(Config{BackendURL: vl.URL, Cache: c, LogLevel: "error", LabelStyle: LabelStyleUnderscores})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	if p.ensureQueryLabelAliases(context.Background(), `{strimzi_io_cluster="kf-x"}`) {
		t.Error("an unresolved label must forfeit the translation-cache write")
	}
	if fieldNamesCalls.Load() == 0 {
		t.Error("the inventory was never consulted")
	}
}

// NeedsAliasDiscovery must not send the proxy to the backend for a label it can
// already answer — that is what keeps the cost at one cached call per replica.
func TestNeedsAliasDiscoveryScope(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, nil)
	for _, tc := range []struct {
		label string
		want  bool
	}{
		{"strimzi_io_cluster", true},
		{"app_kubernetes_io_name", true},
		{"app", false}, // no underscore: nothing to invert
		{"", false},    // nothing at all
		{"_msg", true}, // shaped like a candidate; the inventory settles it
	} {
		if got := lt.NeedsAliasDiscovery(tc.label); got != tc.want {
			t.Errorf("NeedsAliasDiscovery(%q) = %v, want %v", tc.label, got, tc.want)
		}
	}
	lt.LearnFieldAliases([]string{"kubernetes.pod_labels.strimzi.io/cluster"})
	if lt.NeedsAliasDiscovery("strimzi_io_cluster") {
		t.Error("a learned alias must not trigger another lookup")
	}
	if NewLabelTranslator(LabelStylePassthrough, nil).NeedsAliasDiscovery("strimzi_io_cluster") {
		t.Error("passthrough style has no aliases to discover")
	}
}
