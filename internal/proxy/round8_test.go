package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// A binary expression was the ONE path that answered with VictoriaLogs' own
// field names: `{service.name="checkout"}` where every other path says
// `{service_name="checkout"}`, so Grafana drew the same series under two
// identities depending on the operator. Both operands are still fetched and
// matched on VL names — that is what keeps the join consistent — and the
// translation happens once, on the way out.
func TestBinaryMetric_TranslatesLabelsBackToLoki(t *testing.T) {
	// fetchBinOpSides runs the two operands CONCURRENTLY, so the stub's counter
	// needs its own lock.
	var mu sync.Mutex
	var queries []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		queries = append(queries, r.FormValue("query"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{"service.name":"checkout","kubernetes.pod_namespace":"flux-system"},` +
			`"values":[[1700000040,"3"],[1700000100,"4"],[1700000160,"5"]]}]}}`))
	}))
	defer backend.Close()

	p, err := New(Config{
		BackendURL: backend.URL,
		Cache:      cache.New(time.Second, 10),
		LogLevel:   "error",
		LabelStyle: LabelStyleUnderscores,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	// `unless` between two IDENTICAL operands is empty by definition — the label
	// assertion only applies where series survive.
	for _, tc := range []struct {
		op           string
		expectSeries bool
	}{{"or", true}, {"and", true}, {"+", true}, {"unless", false}} {
		op := tc.op
		t.Run(op, func(t *testing.T) {
			rec := httptest.NewRecorder()
			q := `sum by (service_name) (count_over_time({app="a"}[1m])) ` + op +
				` sum by (service_name) (count_over_time({app="b"}[1m]))`
			req := httptest.NewRequest(http.MethodGet,
				"/loki/api/v1/query_range?query="+url.QueryEscape(q)+
					"&start=1700000040&end=1700000160&step=60", nil)
			p.proxyBinaryMetricQueryRangeVM(rec, req, op, `app:="a" | stats count()`, `app:="b" | stats count()`, nil)

			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if strings.Contains(body, `"service.name"`) || strings.Contains(body, `"kubernetes.pod_namespace"`) {
				t.Fatalf("binary result kept VictoriaLogs field names: %s", body)
			}
			if tc.expectSeries && !strings.Contains(body, `"service_name"`) {
				t.Fatalf("expected the Loki label name in %s", body)
			}
			if !tc.expectSeries {
				return
			}
			// The values must be untouched by the renaming.
			var parsed struct {
				Data struct {
					Result []struct {
						Values [][]json.RawMessage `json:"values"`
					} `json:"result"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(parsed.Data.Result) == 0 || len(parsed.Data.Result[0].Values) == 0 {
				t.Fatalf("no samples survived: %s", body)
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	if len(queries) == 0 {
		t.Fatal("the stub backend was never called")
	}
}

// A grouping label the backend cannot see — built by `| regexp` + `| label_format`
// — forces the raw-row path, and the 10,000-row ceiling turned Trow Registry
// panels Loki draws (3 series / 354 points) into a 400. The cap was small because
// it had to be a VictoriaLogs `limit`, which VL executes by SORTING the whole
// match; streaming without one and counting rows on the proxy side lets the panel
// answer, with the same truncation contract one row past the cap.
func TestCollectRangeMetricSamples_FoldsFarMoreThanTenThousandRows(t *testing.T) {
	const rows = 25_000

	var mu sync.Mutex
	var sawLimit string
	base := time.Unix(1700000040, 0).UTC()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		sawLimit = r.Form.Get("limit")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-ndjson")
		for i := 0; i < rows; i++ {
			ts := base.Add(time.Duration(i%120) * time.Second)
			_, _ = fmt.Fprintln(w, vlLineTS(ts, "GET /v2/ns ok", `{app="trow"}`))
		}
	}))
	defer backend.Close()

	p := newGapTestProxy(t, backend.URL)
	series, err := p.collectRangeMetricSamples(context.Background(), `app:="trow"`, nil, nil, false, "__count__", "",
		base, base.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("%d rows refused: %v", rows, err)
	}
	total := 0
	for _, s := range series {
		total += len(s.Samples)
	}
	if total != rows {
		t.Fatalf("folded %d samples, want all %d", total, rows)
	}

	mu.Lock()
	limit := sawLimit
	mu.Unlock()
	if limit != "" {
		t.Fatalf("a limit reached VictoriaLogs (%q): VL implements it as a sort over the whole match, "+
			"which is why the cap had to be small enough to refuse real panels", limit)
	}

	// The contract one row past the cap is unchanged: refuse rather than return a
	// silently short aggregate.
	p.rangeMetricRowLimit = rows - 1
	if _, err := p.collectRangeMetricSamples(context.Background(), `app:="trow"`, nil, nil, false, "__count__", "",
		base, base.Add(2*time.Minute)); err == nil {
		t.Fatal("a scan past the cap must still report truncation")
	}
}

// VictoriaLogs buckets `[b, b+step)` while LogQL's range vector is the
// right-closed `(t-range, t]`. The bucketed fold read the VL grid as-is, so an
// entry sitting exactly on a bucket edge landed in the window that OPENS there
// instead of the one that ENDS there. On uniform data the two errors cancelled —
// the sample wrongly added at `t-range` replaced the one wrongly dropped at `t` —
// and the difference only showed at the edges of a series, where just one of the
// two exists: `sum(count_over_time({…}[30m]))` at step=900 returned 36 on its
// last point where Loki returned 35.
func TestCollectRangeMetricHits_RequestsTheLokiGrid(t *testing.T) {
	var mu sync.Mutex
	var gotOffset, gotStep string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		gotOffset = r.Form.Get("offset")
		gotStep = r.Form.Get("step")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		// With the epsilon offset VictoriaLogs labels buckets `b+0.000001`, which is
		// no longer an integer second — the parser has to cope.
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
			`{"metric":{},"values":[[1700000040.000001,"3"],[1700000100.000001,"4"]]}]}}`))
	}))
	defer backend.Close()

	p := newGapTestProxy(t, backend.URL)
	base := time.Unix(1700000040, 0).UTC()
	series, err := p.collectRangeMetricHits(context.Background(), `app:="a"`, nil, nil, false, "count()",
		base, base.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	mu.Lock()
	offset, step := gotOffset, gotStep
	mu.Unlock()
	if offset == "" || !strings.HasPrefix(offset, "-") {
		t.Fatalf("offset = %q, want the negative epsilon that makes VL's buckets right-closed", offset)
	}
	if step != "60s" {
		t.Fatalf("step = %q, want 60s", step)
	}

	var stamps []int64
	for _, s := range series {
		for _, sample := range s.Samples {
			stamps = append(stamps, sample.ts)
		}
	}
	if len(stamps) != 2 {
		t.Fatalf("expected both buckets, got %d samples", len(stamps))
	}
	for _, ts := range stamps {
		if ts%int64(time.Second) != 0 {
			t.Fatalf("a fractional bucket label survived: %d — it would never match the fold grid", ts)
		}
	}
}
