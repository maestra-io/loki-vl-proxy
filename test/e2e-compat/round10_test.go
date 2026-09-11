//go:build e2e

package e2e_compat

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// derivedLevelProxyURL is the only e2e proxy configured the way us-omega and
// us-omicron are (-derived-level-fields / -derived-level-group-by). CM16 lives
// behind those flags.
var derivedLevelProxyURL = envOr("DERIVED_LEVEL_PROXY_URL", "http://localhost:13111")

// queryRangeStatus runs a LogQL query against a host and returns its HTTP status
// and body, without asserting anything about either.
func queryRangeStatus(t *testing.T, base, logql string, start, end time.Time, extra url.Values) (int, []byte) {
	t.Helper()
	q := url.Values{}
	q.Set("query", logql)
	q.Set("start", fmt.Sprintf("%d", start.UnixNano()))
	q.Set("end", fmt.Sprintf("%d", end.UnixNano()))
	q.Set("limit", "1000")
	for k, vs := range extra {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	resp, err := http.Get(base + "/loki/api/v1/query_range?" + q.Encode())
	if err != nil {
		t.Fatalf("GET %s: %v", base, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// TestRound10_DerivedLevelFilterIsAccepted is CM16 end to end. On maestra.13 the
// proxy answered this query with HTTP 400 because the generated `_msg` regexp
// carried a lone `\[`, which VictoriaLogs will not unquote. It must now answer
// the way Loki does.
func TestRound10_DerivedLevelFilterIsAccepted(t *testing.T) {
	end := time.Now()
	start := end.Add(-1 * time.Hour)

	for _, logql := range []string{
		`{app="e2e-test"} | json | detected_level = "error"`,
		`{app="e2e-test"} | json | detected_level = "warn"`,
		`{app="e2e-test"} | detected_level =~ "err.*"`,
		`{app="e2e-test"} | logfmt | detected_level = "info"`,
	} {
		status, body := queryRangeStatus(t, derivedLevelProxyURL, logql, start, end, nil)
		if status != http.StatusOK {
			t.Errorf("proxy %s -> HTTP %d: %s", logql, status, truncate(string(body), 300))
			continue
		}
		var parsed struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil || parsed.Status != "success" {
			t.Errorf("proxy %s -> unparseable/non-success body: %s", logql, truncate(string(body), 200))
		}
	}
}

// TestRound10_LogsPathBoundsTheSort proves the limit reaches LogsQL. The proxy
// exposes the query it sent in its debug log, but the black-box assertion is the
// one that matters: asking for N lines returns at most N.
func TestRound10_LogsPathBoundsTheSort(t *testing.T) {
	end := time.Now()
	start := end.Add(-24 * time.Hour)
	for _, limit := range []string{"5", "17"} {
		status, body := queryRangeStatus(t, proxyURL, `{app="e2e-test"}`, start, end,
			url.Values{"limit": {limit}})
		if status != http.StatusOK {
			t.Fatalf("HTTP %d: %s", status, truncate(string(body), 200))
		}
		var parsed struct {
			Data struct {
				Result []struct {
					Values [][]any `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("parse: %v", err)
		}
		total := 0
		for _, s := range parsed.Data.Result {
			total += len(s.Values)
		}
		want := 0
		_, _ = fmt.Sscanf(limit, "%d", &want)
		if total > want {
			t.Errorf("limit=%s returned %d entries", limit, total)
		}
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
