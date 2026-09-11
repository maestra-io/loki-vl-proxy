package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// A near-coprime range/step pair drives the common grid down to a second while
// the number of OUTPUT points stays small — 21809 buckets for 36 points in the
// case that reported this. Refusing is the last resort: the plan comes back
// populated so those points can be evaluated one window at a time.
func TestPlanRangeWindowRollup_CoprimeYieldsAPlanForPerPointEvaluation(t *testing.T) {
	// gcd(7m, 11m1s) = 1s, so the common grid would need a bucket per second
	// across the whole day while the request asks for 131 points.
	plan, err, ok := planRangeWindowRollupDetailed(
		`count_over_time({a="b"}[7m])`, "1700000000", "1700086400", "661")
	if ok {
		t.Fatalf("a coprime pair cannot use the common grid, got a plan %+v", plan)
	}
	if err == nil {
		t.Fatal("the caller needs to know WHY, to choose the per-point path")
	}
	if plan.rangeNs != int64(7*time.Minute) || plan.stepNs != int64(11*time.Minute+time.Second) {
		t.Fatalf("the plan must carry the window for per-point evaluation: %+v", plan)
	}
	if plan.endNs <= plan.startNs {
		t.Fatalf("the plan must carry the request bounds: %+v", plan)
	}
}

// The per-point fallback answers rather than 400s, and stays bounded: one inner
// request per output point, capped, and never the whole grid.
func TestEvaluatePerPointWindows_AnswersACoprimeRequest(t *testing.T) {
	var mu sync.Mutex
	var calls int
	// Each inner request is one window `(t-range, t+range]` at step=range, so the
	// point the fold wants is `start + range`. The stub answers on the request's
	// own grid, and guards its counter: the windows run concurrently.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		calls++
		mu.Unlock()
		// Answer on the OUTER grid: each inner window then finds its own point and
		// the merge picks the newest one that does not overshoot it.
		var points []string
		for ts := int64(1700000000); ts <= 1700003000; ts += 661 {
			points = append(points, fmt.Sprintf(`[%d,"7"]`, ts))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[`+
			`{"metric":{"app":"a"},"values":[%s]}]}}`, strings.Join(points, ","))
	}))
	defer backend.Close()

	p, err := New(Config{BackendURL: backend.URL, LogLevel: "error"})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	plan := rangeWindowPlan{
		startNs: 1700000000 * int64(time.Second),
		endNs:   1700000000*int64(time.Second) + 4*int64(11*time.Minute),
		stepNs:  int64(11 * time.Minute),
		rangeNs: int64(7 * time.Minute),
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet,
		"/loki/api/v1/query_range?query="+url.QueryEscape(`count_over_time({a="b"}[7m])`)+
			"&start=1700000000&end=1700002640&step=660", nil)
	if !p.evaluatePerPointWindows(rec, req, plan) {
		t.Fatal("the per-point path must answer a coprime request instead of refusing")
	}
	if rec.Code != http.StatusOK && rec.Code != 0 {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"app":"a"`) {
		t.Fatalf("no series in %s", rec.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if calls == 0 {
		t.Fatal("no inner request was made")
	}

	// Bounded: a request asking for more points than the cap is declined, so the
	// fan-out can never be unbounded.
	huge := plan
	huge.endNs = plan.startNs + int64(maxPerPointWindows+1)*plan.stepNs
	if p.evaluatePerPointWindows(httptest.NewRecorder(), req, huge) {
		t.Fatal("the per-point path must decline a fan-out past its cap")
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
