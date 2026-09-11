package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/cache"
)

// A window whose backend fetch ERRORS leaves a hole in the mined range. Serving
// the remaining windows as a complete answer silently under-reports a Drilldown
// panel — the shape seen in CI, where a pattern covered only part of the
// requested range while the direct Loki answer covered all of it. The failed
// window must be retried, and if it still errors the windowed result must be
// refused so the caller falls back to the full-range fetch.
func TestFetchPatternsFromWindows_RefusesPartialCoverageOnWindowError(t *testing.T) {
	const line = `{"_time":"%s","_msg":"stable pattern alpha component=collector"}` + "\n"

	var failStart atomic.Int64 // window start whose fetch is refused (0 = none)
	var failBudget atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		startNs, _ := strconv.ParseInt(r.FormValue("start"), 10, 64)
		if fs := failStart.Load(); fs != 0 && fs == startNs && failBudget.Load() != 0 {
			failBudget.Add(-1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		ts := time.Unix(0, startNs).UTC().Format(time.RFC3339Nano)
		_, _ = fmt.Fprintf(w, line, ts)
	}))
	defer backend.Close()

	enabled := true
	p, err := New(Config{
		BackendURL:      backend.URL,
		Cache:           cache.New(60*time.Second, 100),
		LogLevel:        "error",
		PatternsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	base := time.Date(2026, 9, 10, 22, 0, 0, 0, time.UTC).UnixNano()
	windows := []queryRangeWindow{
		{startNs: base, endNs: base + int64(20*time.Minute) - 1},
		{startNs: base + int64(20*time.Minute), endNs: base + int64(40*time.Minute) - 1},
		{startNs: base + int64(40*time.Minute), endNs: base + int64(60*time.Minute) - 1},
	}
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/patterns", nil)

	// Every window answers: full coverage, accepted.
	entries, successes, diag := p.fetchPatternsFromWindows(req, "*", 2000, 200, 4, windows, "30", 100)
	if successes != len(windows) || len(entries) == 0 || diag.windowFailed != 0 {
		t.Fatalf("healthy fan-out should accept every window: successes=%d entries=%d failed=%d", successes, len(entries), diag.windowFailed)
	}

	// One window fails on BOTH the parallel pass and the serial retry: the mined
	// set no longer covers the requested range, so it must not be returned.
	failStart.Store(windows[1].startNs)
	failBudget.Store(-1) // unlimited
	entries, successes, diag = p.fetchPatternsFromWindows(req, "*", 2000, 200, 4, windows, "30", 100)
	if diag.windowFailed == 0 {
		t.Fatalf("expected an unrecovered window failure, diag=%+v", diag)
	}
	if successes != 0 || len(entries) != 0 {
		t.Fatalf("partial window coverage must be refused, got successes=%d entries=%d", successes, len(entries))
	}

	// A single transient failure is recovered by the retry, so coverage is complete.
	failBudget.Store(1)
	entries, successes, diag = p.fetchPatternsFromWindows(req, "*", 2000, 200, 4, windows, "30", 100)
	if diag.windowFailed != 0 || successes != len(windows) || len(entries) == 0 {
		t.Fatalf("retry should recover a transient window failure: successes=%d entries=%d failed=%d", successes, len(entries), diag.windowFailed)
	}
	if body, _ := json.Marshal(entries); !strings.Contains(string(body), "pattern") {
		t.Fatalf("expected mined pattern entries, got %s", body)
	}
}

// CodeRabbit 3985252726: a worker that returns while waiting on the semaphore —
// the request context was cancelled — never reaches fetchWindow, so it shows up
// neither as accepted nor as failed. Without counting the windows that actually
// RAN, the surviving ones look like the whole range and get served (and cached)
// as a complete answer.
func TestFetchPatternsFromWindows_RefusesWindowsSkippedOnCancelledContext(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		<-release // hold the in-flight workers so the rest stay queued on the semaphore
		startNs, _ := strconv.ParseInt(r.FormValue("start"), 10, 64)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"_time":"%s","_msg":"stable pattern alpha component=collector"}`+"\n",
			time.Unix(0, startNs).UTC().Format(time.RFC3339Nano))
	}))
	defer backend.Close()

	enabled := true
	p, err := New(Config{
		BackendURL:      backend.URL,
		Cache:           cache.New(60*time.Second, 100),
		LogLevel:        "error",
		PatternsEnabled: &enabled,
	})
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}

	base := time.Date(2026, 9, 10, 22, 0, 0, 0, time.UTC).UnixNano()
	windows := make([]queryRangeWindow, 0, 16)
	for i := 0; i < 16; i++ {
		windows = append(windows, queryRangeWindow{
			startNs: base + int64(i)*int64(5*time.Minute),
			endNs:   base + int64(i+1)*int64(5*time.Minute) - 1,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/loki/api/v1/patterns", nil).WithContext(ctx)

	done := make(chan struct{})
	var entries []patternResultEntry
	var successes int
	var diag patternFetchDiagnostics
	go func() {
		defer close(done)
		entries, successes, diag = p.fetchPatternsFromWindows(req, "*", 2000, 200, 4, windows, "30", 100)
	}()

	// Cancel while the queued workers are blocked on the semaphore (the in-flight
	// ones are parked in the handler), then let the in-flight ones answer.
	time.Sleep(100 * time.Millisecond)
	cancel()
	close(release)
	<-done

	// The semaphore is 8 wide, so at most 8 windows were ever in flight while the
	// context was live: the set can never be complete here.
	if diag.windowCompleted >= len(windows) {
		t.Fatalf("expected the cancellation to skip queued windows, completed=%d/%d", diag.windowCompleted, len(windows))
	}
	if successes != 0 || len(entries) != 0 {
		t.Fatalf("windows skipped on a cancelled context must not pass as full coverage: completed=%d/%d successes=%d entries=%d",
			diag.windowCompleted, len(windows), successes, len(entries))
	}
	if !diag.likelyLowCoverage() {
		t.Fatalf("an incomplete window set must be reported as low coverage: %+v", diag)
	}
}

// The rule CodeRabbit 3985252726 asks for, stated directly: coverage is complete
// only when every window RAN. Counting accepted+failed is not enough — a worker
// cancelled while queued on the semaphore is in neither bucket.
func TestPatternWindowSetIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name  string
		diag  patternFetchDiagnostics
		total int
		want  bool
	}{
		{"every window ran", patternFetchDiagnostics{windowCompleted: 4, windowAccepted: 4}, 4, false},
		{"every window ran, some empty", patternFetchDiagnostics{windowCompleted: 4, windowAccepted: 1}, 4, false},
		{"a window errored", patternFetchDiagnostics{windowCompleted: 4, windowFailed: 1}, 4, true},
		{"a window never ran", patternFetchDiagnostics{windowCompleted: 3, windowAccepted: 3}, 4, true},
		{"three of four, as CodeRabbit put it", patternFetchDiagnostics{windowCompleted: 3, windowAccepted: 3}, 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := patternWindowSetIncomplete(tc.diag, tc.total); got != tc.want {
				t.Fatalf("patternWindowSetIncomplete(%+v, %d) = %v, want %v", tc.diag, tc.total, got, tc.want)
			}
		})
	}
}
