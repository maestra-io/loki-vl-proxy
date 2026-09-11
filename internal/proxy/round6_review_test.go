package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// CodeRabbit 3984724000: an INSTANT sample whose timestamp the right-hand side
// does not carry must be dropped, exactly as the matrix branch already does.
// Before the fix the left value was emitted verbatim, as if the operation had
// been applied to it.
func TestApplyBinaryToSample_DropsUnmatchedInstantSample(t *testing.T) {
	sample := map[string]interface{}{
		"metric": map[string]interface{}{"app": "a"},
		"value":  []interface{}{"1700000000", "7"},
	}
	applyBinaryToSample(sample, map[string]float64{"1700000060": 2}, "+")
	if _, present := sample["value"]; present {
		t.Fatalf("unmatched instant sample must be dropped, got %v", sample["value"])
	}

	matched := map[string]interface{}{
		"metric": map[string]interface{}{"app": "a"},
		"value":  []interface{}{"1700000000", "7"},
	}
	applyBinaryToSample(matched, map[string]float64{"1700000000": 2}, "+")
	value, ok := matched["value"].([]interface{})
	if !ok || len(value) < 2 || value[1] != "9" {
		t.Fatalf("matched instant sample must be combined, got %v", matched["value"])
	}
}

// CodeRabbit 3985252718: `or` must index only the left series that SURVIVED the
// empty-series drop. A left series that arrives with no samples is gone from the
// result, so merging the right's samples into it silently loses them.
func TestCombineSetOperation_OrKeepsRightWhenLeftSeriesIsEmpty(t *testing.T) {
	left := []interface{}{
		map[string]interface{}{
			"metric": map[string]interface{}{"app": "a"},
			"values": []interface{}{},
		},
	}
	right := []interface{}{
		map[string]interface{}{
			"metric": map[string]interface{}{"app": "a"},
			"values": []interface{}{[]interface{}{float64(1700000000), "5"}},
		},
	}
	got := combineSetOperation(left, right, map[string]map[string]float64{}, "or")
	if len(got) != 1 {
		t.Fatalf("or must keep the right series when the left one is empty, got %d series: %v", len(got), got)
	}
	series, _ := got[0].(map[string]interface{})
	values, _ := series["values"].([]interface{})
	if len(values) != 1 {
		t.Fatalf("expected the right series' single sample, got %v", series)
	}
}

// CodeRabbit 3984724018: Grafana emits `[$__interval]`, which the LogQL parser
// rejects as a duration. Resolving the tokens must happen BEFORE validation, or
// a legitimate dashboard panel is answered with 400.
func TestQueryRange_GrafanaTemplateDurationIsNotRejected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer backend.Close()

	p, err := New(Config{
		BackendURL: backend.URL,
		Cache:      cache.New(time.Second, 10),
		LogLevel:   "error",
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	for _, query := range []string{
		`sum(rate({app="a"}[$__interval]))`,
		`sum(count_over_time({app="a"}[$__range]))`,
		`sum(rate({app="a"}[${__interval}]))`,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/loki/api/v1/query_range?query="+url.QueryEscape(query)+"&start=1700000000&end=1700003600&step=60", nil)
		p.handleQueryRange(rec, req)
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("%s was rejected before token resolution: %s", query, rec.Body.String())
		}
	}
}
