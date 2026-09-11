package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The underscore fallback adds the RAW Loki label name as a second grouping key
// so data that spells the same label with underscores (`service_name` for OTel's
// `service.name`) still groups. It must NOT do that for a label an explicit
// -field-mapping points at an unrelated field: `namespace` →
// `kubernetes.pod_namespace` would then also group by whatever a log body calls
// `namespace`, and `sum by (namespace) (count_over_time({namespace=
// "flux-system"}[1h]))` came back as 38 series where Loki returns 1.
func TestAddUnderscoreFallbackByLabels_SkipsMappedLabels(t *testing.T) {
	p := newUnderscoreFallbackTestProxy(t, []FieldMapping{
		{VLField: "kubernetes.pod_namespace", LokiLabel: "namespace"},
	})

	got := p.addUnderscorefallbackByLabels(
		`f:="x" | stats by ("kubernetes.pod_namespace") count()`, []string{"namespace"})
	if strings.Contains(got, ", namespace)") {
		t.Fatalf("a mapped label must not add the raw name as a second key: %s", got)
	}

	// The underscore twin of a dotted field is still added — that is the case the
	// fallback exists for.
	got = p.addUnderscorefallbackByLabels(
		`f:="x" | stats by ("service.name") count()`, []string{"service_name"})
	if !strings.Contains(got, ", service_name)") {
		t.Fatalf("the underscore twin must still be grouped: %s", got)
	}
}

func newUnderscoreFallbackTestProxy(t *testing.T, mappings []FieldMapping) *Proxy {
	t.Helper()
	p := newGapTestProxy(t, "http://127.0.0.1:1")
	p.labelTranslator = NewLabelTranslator(LabelStyleUnderscores, mappings)
	return p
}

// Loki evaluates a metric range query on multiples of the step and truncates
// BOTH bounds down to that grid. Measured on 3.7.1: with step=137 every returned
// timestamp satisfies `ts % 137 == 0` and the first point sits BEFORE the
// requested start. Starting at `start` shifted the whole series (+27s at
// step=137, +39s at step=97) while a step dividing the start looked fine.
func TestAlignRangeRequestToStepGrid(t *testing.T) {
	const start, end = 1789082880, 1789083480
	for _, step := range []int64{137, 97, 60, 300} {
		req := httptest.NewRequest(http.MethodGet,
			fmt.Sprintf("/loki/api/v1/query_range?query=%s&start=%d&end=%d&step=%d",
				url.QueryEscape(`sum(count_over_time({app="a"}[5m]))`), start, end, step), nil)
		_ = req.ParseForm()
		alignRangeRequestToStepGrid(req, `sum(count_over_time({app="a"}[5m]))`)

		for _, bound := range []struct {
			name string
			want int64
		}{
			{"start", start / step * step},
			{"end", end / step * step},
		} {
			ns, ok := parseLokiTimeToUnixNano(req.FormValue(bound.name))
			if !ok {
				t.Fatalf("step=%d: %s did not parse: %q", step, bound.name, req.FormValue(bound.name))
			}
			if got := ns / int64(time.Second); got != bound.want {
				t.Fatalf("step=%d: %s = %d, want %d (k*step grid)", step, bound.name, got, bound.want)
			}
		}
	}

	// A LOG query has no evaluation grid; moving its bounds would change which
	// lines it returns.
	logReq := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/loki/api/v1/query_range?query=%s&start=%d&end=%d&step=137",
			url.QueryEscape(`{app="a"}`), start, end), nil)
	_ = logReq.ParseForm()
	alignRangeRequestToStepGrid(logReq, `{app="a"}`)
	if got := logReq.FormValue("start"); got != strconv.Itoa(start) {
		t.Fatalf("a log query's start was moved to %q", got)
	}
}

// A BARE comparison FILTERS: the sample keeps its own value, non-matching
// samples go, and a series left with nothing goes with them. Only `bool` scores
// 1/0. The proxy used to strip `bool` and score every comparison, so `… > 1000`
// drew a flat line of 1s and `… > 100000` drew zeros where Loki returns nothing.
func TestQueryRange_BareComparisonFiltersBoolScores(t *testing.T) {
	base := time.Unix(1700000040, 0).UTC()
	const step = 60

	var mu sync.Mutex
	var calls int
	vlBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"app":"a"},"values":[[%d,"2"],[%d,"9"]]}]}}`,
			base.Unix(), base.Unix()+step)
	}))
	defer vlBackend.Close()

	p := newGapTestProxy(t, vlBackend.URL)
	query := func(expr string) [][]interface{} {
		t.Helper()
		params := url.Values{}
		params.Set("query", expr)
		params.Set("start", strconv.FormatInt(base.Unix()+step, 10))
		params.Set("end", strconv.FormatInt(base.Unix()+2*step, 10))
		params.Set("step", strconv.Itoa(step))
		rec := httptest.NewRecorder()
		p.handleQueryRange(rec, httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", expr, rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Result []struct {
					Values [][]interface{} `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: decode: %v", expr, err)
		}
		if len(resp.Data.Result) == 0 {
			return nil
		}
		return resp.Data.Result[0].Values
	}

	// Bare: the matching sample keeps its OWN value, the other is dropped.
	got := query(`sum(count_over_time({app="a"}[1m])) > 5`)
	if len(got) != 1 || fmt.Sprintf("%v", got[0][1]) != "9" {
		t.Fatalf("bare comparison did not filter: %v", got)
	}
	// Nothing matches → no series at all.
	if got := query(`sum(count_over_time({app="a"}[1m])) > 100000`); len(got) != 0 {
		t.Fatalf("expected no series, got %v", got)
	}
	// `bool` scores every sample.
	got = query(`sum(count_over_time({app="a"}[1m])) > bool 5`)
	if len(got) != 2 || fmt.Sprintf("%v", got[0][1]) != "0" || fmt.Sprintf("%v", got[1][1]) != "1" {
		t.Fatalf("bool comparison did not score 0/1: %v", got)
	}
	// Arithmetic is untouched.
	got = query(`sum(count_over_time({app="a"}[1m])) * 2`)
	if len(got) != 2 || fmt.Sprintf("%v", got[0][1]) != "4" {
		t.Fatalf("arithmetic changed: %v", got)
	}
}

// `or` and `unless` select series; they are not arithmetic. Routing them through
// the arithmetic path emptied them once a comparison started dropping left
// series without a right-hand match.
func TestCombineMetricResults_SetOperations(t *testing.T) {
	left := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"level":"info"},"values":[[100,"4"],[160,"6"]]},` +
		`{"metric":{"level":"debug"},"values":[[100,"1"],[160,"2"]]}]}}`)
	right := []byte(`{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"level":"debug"},"values":[[100,"1"]]},` +
		`{"metric":{"level":"warn"},"values":[[160,"9"]]}]}}`)

	read := func(body []byte) map[string][][]interface{} {
		t.Helper()
		var resp struct {
			Data struct {
				Result []struct {
					Metric map[string]string `json:"metric"`
					Values [][]interface{}   `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out := map[string][][]interface{}{}
		for _, s := range resp.Data.Result {
			out[s.Metric["level"]] = s.Values
		}
		return out
	}

	// `or`: every left series survives, and a right-only series joins them.
	got := read(combineMetricResults(left, right, "or", "matrix"))
	if len(got) != 3 || len(got["info"]) != 2 || len(got["warn"]) != 1 {
		t.Fatalf("or lost series: %v", got)
	}
	// `unless`: the left samples the right also has are removed.
	got = read(combineMetricResults(left, right, "unless", "matrix"))
	if len(got["info"]) != 2 {
		t.Fatalf("unless dropped an unmatched left series: %v", got)
	}
	if len(got["debug"]) != 1 || fmt.Sprintf("%v", got["debug"][0][0]) != "160" {
		t.Fatalf("unless kept the matched sample: %v", got)
	}
	// `and`: only the samples the right also has.
	got = read(combineMetricResults(left, right, "and", "matrix"))
	if _, ok := got["info"]; ok {
		t.Fatalf("and kept an unmatched series: %v", got)
	}
	if len(got["debug"]) != 1 || fmt.Sprintf("%v", got["debug"][0][0]) != "100" {
		t.Fatalf("and kept the wrong sample: %v", got)
	}
}
