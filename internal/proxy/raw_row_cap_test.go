package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCollectRangeMetricSamples_RowCapBoundary pins the raw-row scan cap.
//
// The cap is PROXY-SIDE: no `limit` is sent, because VictoriaLogs executes one by
// SORTING the whole match — the thing that OOM-killed VLSingle — while an
// unlimited query streams in arbitrary order and is folded row by row. Rows are
// counted as they arrive and the scan stops the moment the cap is passed, so a
// result of exactly rowLimit rows is COMPLETE and only rowLimit+1 proves there
// was more to read. Comparing `rowsScanned >= rowLimit` instead turns every
// exactly-full result into a 400.
func TestCollectRangeMetricSamples_RowCapBoundary(t *testing.T) {
	const rowCap = 10

	tests := []struct {
		name          string
		rowsAvailable int
		wantErr       bool
	}{
		{name: "well under the cap", rowsAvailable: 3, wantErr: false},
		{name: "one below the cap", rowsAvailable: rowCap - 1, wantErr: false},
		{name: "exactly the cap is complete", rowsAvailable: rowCap, wantErr: false},
		{name: "one over the cap is truncated", rowsAvailable: rowCap + 1, wantErr: true},
		{name: "far over the cap is truncated", rowsAvailable: rowCap * 5, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var requestedLimit string
			base := time.Unix(1700000000, 0).UTC()

			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse form: %v", err)
					return
				}
				if r.URL.Path != "/select/logsql/query" {
					return
				}
				requestedLimit = r.Form.Get("limit")

				// Behave like an UNLIMITED VictoriaLogs query: stream every matching
				// row, in no particular order, and let the proxy stop reading.
				n := tc.rowsAvailable
				w.Header().Set("Content-Type", "application/x-ndjson")
				for i := 0; i < n; i++ {
					_, _ = fmt.Fprintln(w, vlLineTS(base.Add(time.Duration(i)*time.Millisecond), "msg", `{app="api"}`))
				}
			}))
			defer backend.Close()

			p := newGapTestProxy(t, backend.URL)
			p.rangeMetricRowLimit = rowCap

			params := url.Values{}
			params.Set("query", `rate({app="api"}[2m])`)
			params.Set("start", strconv.FormatInt(base.Unix(), 10))
			params.Set("end", strconv.FormatInt(base.Add(5*time.Minute).Unix(), 10))
			params.Set("step", "30")
			req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/query_range?"+params.Encode(), nil)
			rec := httptest.NewRecorder()
			p.handleQueryRange(rec, req)

			// No `limit` may reach VictoriaLogs: it implements one as a sort over the
			// whole match, which is what made the cap have to be small enough to
			// refuse panels Loki answers.
			if requestedLimit != "" {
				t.Errorf("a limit reached the backend (%q) — that is the sort this path must avoid", requestedLimit)
			}

			gotErr := rec.Code == http.StatusBadRequest
			if gotErr != tc.wantErr {
				t.Fatalf("%d rows available with cap %d: status %d (truncation reported = %v, want %v): %s",
					tc.rowsAvailable, rowCap, rec.Code, gotErr, tc.wantErr, rec.Body.String())
			}
			if tc.wantErr && rec.Code == http.StatusBadRequest {
				if body := rec.Body.String(); !strings.Contains(body, "manual-range-metric-row-limit") {
					t.Errorf("truncation error should name the flag, got: %s", body)
				}
			}
		})
	}
}

// TestUserParserStageIsReadFromTheClientQuery pins the distinction the
// injected-chain stripping used to blur.
//
// -derived-level-group-by makes the translator inject `| unpack_json from _msg`
// of its own. A regex that removed those pipes from the TRANSLATED query also
// removed the user's translated `| json` / `| logfmt`, after which the compat
// layer could pick native VL aggregation — which counts parse-failed rows that
// Loki drops. The answer is read from the CLIENT's query instead, where the two
// can never be confused.
func TestUserParserStageIsReadFromTheClientQuery(t *testing.T) {
	tests := []struct {
		name  string
		logql string
		want  bool
	}{
		{
			// The injected chain lives in the translated query only; the client
			// wrote no parser stage, so Loki's error-exclusion cannot apply.
			name:  "derived-level grouping alone is not a user parser stage",
			logql: `sum by (level) (count_over_time({namespace="a"}[1h]))`,
			want:  false,
		},
		{
			// The case the regex broke: the user DID parse, and grouping by level
			// makes the translator inject its chain alongside. Error-exclusion
			// still applies, so this must stay on the manual path.
			name:  "derived-level grouping WITH a user parser stage",
			logql: `sum by (level) (count_over_time({namespace="a"} | json [1h]))`,
			want:  true,
		},
		{
			name:  "user json without level grouping",
			logql: `sum by (app) (count_over_time({namespace="a"} | json [1h]))`,
			want:  true,
		},
		{
			name:  "user logfmt",
			logql: `sum(count_over_time({namespace="a"} | logfmt [1h]))`,
			want:  true,
		},
		{
			name:  "user regexp",
			logql: `sum(count_over_time({namespace="a"} | regexp "(?P<x>a)" [1h]))`,
			want:  true,
		},
		{
			name:  "no parser at all",
			logql: `sum(count_over_time({namespace="a"}[1h]))`,
			want:  false,
		},
		{
			// A line filter carrying the text is data, not a stage.
			name:  "parser name inside a line filter is not a stage",
			logql: `sum(count_over_time({namespace="a"} |= "| json " [1h]))`,
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := logqlUsesParserStage(tc.logql); got != tc.want {
				t.Errorf("logqlUsesParserStage(%q) = %v, want %v", tc.logql, got, tc.want)
			}
		})
	}
}
