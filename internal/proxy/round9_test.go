package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
)

// The translator emits the explicit `| unpack_json from _msg` form for derived
// levels, and the strip removed only the VERB — leaving ` from _msg  from _msg`,
// which VictoriaLogs reads as two WORD filters ("the line contains `from`" AND
// "contains `_msg`"). The level-discovery query then matched only the proxy's own
// logs, and the whitelist built from it threw away 99.6 % of the data: 45 rows
// returned of 11 826.
func TestStripUnpackStagesForTopN_RemovesTheWholeStage(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`ns:="a" | unpack_json from _msg | unpack_logfmt from _msg | filter level:="x"`, `ns:="a" | filter level:="x"`},
		{`ns:="a" | unpack_json | unpack_logfmt | filter level:="x"`, `ns:="a" | filter level:="x"`},
		{`ns:="a" | unpack_json from _msg | stats by (level) count()`, `ns:="a" | stats by (level) count()`},
		{`ns:="a" | filter level:="x"`, `ns:="a" | filter level:="x"`},
	} {
		got := strings.Join(strings.Fields(stripUnpackStagesForTopN(tc.in)), " ")
		if got != tc.want {
			t.Errorf("%s ->\n got %s\nwant %s", tc.in, got, tc.want)
		}
		if strings.Contains(got, "from _msg") {
			t.Errorf("a bare `from _msg` argument survived and becomes a word filter: %s", got)
		}
	}

	// CodeRabbit 3988862272: a filter VALUE may legitimately contain the text of a
	// pipeline stage — a line filter over the proxy's own logs does — and
	// rewriting it changes what the user asked for.
	for _, q := range []string{
		"ns:=\"a\" ~\"| unpack_json from _msg\" | unpack_logfmt from _msg | stats count()",
		"ns:=\"a\" ~`| unpack_logfmt from _msg` | stats count()",
	} {
		got := stripUnpackStagesForTopN(q)
		if !strings.Contains(got, "| unpack_json from _msg") && !strings.Contains(got, "| unpack_logfmt from _msg") {
			t.Errorf("the quoted literal was rewritten: %s -> %s", q, got)
		}
	}
	// The real stage next to a quoted one is still removed.
	got := stripUnpackStagesForTopN("ns:=\"a\" ~\"| unpack_json from _msg\" | unpack_logfmt from _msg | stats count()")
	if strings.Count(got, "unpack_json") != 1 {
		t.Errorf("the quoted literal must survive verbatim: %s", got)
	}
	if strings.Contains(got, "unpack_logfmt") {
		t.Errorf("the real stage next to it must still go: %s", got)
	}
}

// `level` is a STORED stream label; `detected_level` is the one Loki INFERS.
// Grouping by the two is not the same question, and answering `sum by (level)`
// with a value read out of the message moved 192 rows into `{level="info"}`, a
// series that exists neither in Loki nor in the store.
func TestLogqlGroupsByDetectedLevel(t *testing.T) {
	for _, tc := range []struct {
		query string
		level bool
		infer bool
	}{
		{`sum by (level) (count_over_time({app="a"}[1h]))`, true, false},
		{`sum by (detected_level) (count_over_time({app="a"}[1h]))`, true, true},
		{`sum by (level, pod) (count_over_time({app="a"}[1h]))`, true, false},
		{`sum by (pod) (count_over_time({app="a"}[1h]))`, false, false},
	} {
		if got := logqlGroupsByLevel(tc.query); got != tc.level {
			t.Errorf("%s: groupsByLevel = %v, want %v", tc.query, got, tc.level)
		}
		if got := logqlGroupsByDetectedLevel(tc.query); got != tc.infer {
			t.Errorf("%s: groupsByDetectedLevel = %v, want %v", tc.query, got, tc.infer)
		}
	}
	// The text fallback for a query the parser rejects must draw the same line.
	if logqlGroupsByDetectedLevel(`sum by (level) (rate({app="a"}[$unparseable]))`) {
		t.Error("the text fallback must not read `level` as `detected_level`")
	}
}

// Whitespace hugging a bracket carries no meaning: `sum  (  rate  ( … )  )` is
// the same query, and a doubled space kept the shape-matching from recognising
// it — a 400 on something Loki answers.
func TestQueryRange_DoubledSpacesAroundBrackets(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer backend.Close()

	p, err := New(Config{BackendURL: backend.URL, LogLevel: "error"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	for _, q := range []string{
		`sum  (  rate  ({namespace="flux-system"}[5m])  )`,
		`sum ( rate ({namespace="flux-system"} [5m]) )`,
		`topk (3, sum by (ns) (count_over_time({app="a"}[5m])))`,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/loki/api/v1/query_range?query="+url.QueryEscape(q)+
				"&start=1700000000&end=1700003600&step=300", nil)
		p.handleQueryRange(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s -> HTTP %d: %s", q, rec.Code, rec.Body.String())
		}
	}
}

// A label the user NAMED in by() identifies the series even when its value is
// empty: Loki answers `{lf=""}`, and dropping the name made it `{}` — the same
// numbers under a different series in Grafana.
func TestTemplateMetricLabels_KeepsAnEmptyNamedLabel(t *testing.T) {
	spec := statsCompatSpec{GroupBy: []string{"lf"}, OrigGroupBy: []string{"lf"}, ByExplicit: true}
	out := templateMetricLabels(map[string]string{"lf": "", "pod": "p1"}, spec)
	if _, ok := out["lf"]; !ok {
		t.Fatalf("the named grouping label was dropped for an empty value: %v", out)
	}
	if out["lf"] != "" {
		t.Fatalf("lf = %q, want the empty value Loki reports", out["lf"])
	}
	if _, ok := out["pod"]; ok {
		t.Fatalf("only the named labels belong in the series: %v", out)
	}
	// Without an explicit by(), an empty stream label is still dropped, as Loki does.
	bare := templateMetricLabels(map[string]string{"lf": "", "pod": "p1"}, statsCompatSpec{})
	if _, ok := bare["lf"]; ok {
		t.Fatalf("an empty label must not appear without an explicit by(): %v", bare)
	}
}

var _ = logqlpkg.Parse

// CodeRabbit 3988862277: `without (detected_level)` REMOVES the label, it does
// not ask for one. Inferring a level there splits a series the query asked to
// collapse — the post-processing drops `detected_level` but never merges two
// groups that ended up with different inferred levels.
func TestLogqlGroupsByDetectedLevel_IgnoresWithout(t *testing.T) {
	for _, q := range []string{
		`sum without (detected_level) (count_over_time({app="a"}[1h]))`,
		`sum without (detected_level, pod) (count_over_time({app="a"}[1h]))`,
	} {
		if logqlGroupsByDetectedLevel(q) {
			t.Errorf("%s: `without` removes the label, it does not license inference", q)
		}
	}
	// The text fallback, for a query the parser rejects, must draw the same line.
	if logqlGroupsByDetectedLevel(`sum without (detected_level) (rate({app="a"}[$unparseable]))`) {
		t.Error("the text fallback read a `without` clause as a grouping")
	}
	// `by` still licenses it.
	if !logqlGroupsByDetectedLevel(`sum by (detected_level) (count_over_time({app="a"}[1h]))`) {
		t.Error("`by (detected_level)` must still infer")
	}
}

// CodeRabbit 3988862308: an ABSENT label and a label PRESENT with an empty value
// are different things to Loki — it omits the first and reports `{lf=""}` for
// the second.
func TestTemplateMetricLabels_AbsentIsNotPresentEmpty(t *testing.T) {
	spec := statsCompatSpec{GroupBy: []string{"lf", "missing"}, OrigGroupBy: []string{"lf", "missing"}, ByExplicit: true}
	out := templateMetricLabels(map[string]string{"lf": ""}, spec)
	if v, ok := out["lf"]; !ok || v != "" {
		t.Fatalf("a present-but-empty label must survive: %v", out)
	}
	if _, ok := out["missing"]; ok {
		t.Fatalf("an absent label must not be invented: %v", out)
	}
}

// CodeRabbit 3988862301: the reservation ran BEFORE parsing, the timestamp check
// and the pipeline, so rows those threw away spent the shared memory budget on
// nothing — and a scan that fits in memory was refused because of the rows that
// never reached it.
func TestFetchTemplatePipelineEntries_ChargesOnlyRetainedEntries(t *testing.T) {
	// More discarded rows than one reservation chunk, so charging them exhausts a
	// budget of exactly one chunk while the three retained entries fit easily.
	const kept = 3
	discarded := manualScanReservationChunk + 100

	base := time.Unix(1700000040, 0).UTC()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/x-ndjson")
		// Rows the parser throws away: they must not be charged.
		for i := 0; i < discarded; i++ {
			_, _ = fmt.Fprintln(w, "{not json")
		}
		for i := 0; i < kept; i++ {
			_, _ = fmt.Fprintln(w, vlLineTS(base.Add(time.Duration(i)*time.Second), "hello", `{app="a"}`))
		}
	}))
	defer backend.Close()

	p := newGapTestProxy(t, backend.URL)
	// A budget far smaller than the discarded rows, larger than the retained ones.
	p.manualScanBudget = newManualScanBudget(manualScanReservationChunk)

	pipeline, err := logqlpkg.NewPipeline(nil)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	plan := &templatePlan{pipeline: pipeline, baseLogsQL: `app:="a"`, fallbackLogsQL: `app:="a"`}
	entries, err := p.fetchTemplatePipelineEntries(context.Background(), plan,
		base, base.Add(time.Minute), true, true, 0)
	if err != nil {
		t.Fatalf("%d discarded rows exhausted a budget that fits the %d retained ones: %v",
			discarded, kept, err)
	}
	if len(entries) != kept {
		t.Fatalf("kept %d entries, want %d", len(entries), kept)
	}
}
