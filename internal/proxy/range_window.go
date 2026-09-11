package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
)

// A LogQL range vector has its OWN window: `count_over_time({…}[30m])` evaluated
// at step=1h counts the 30 minutes before each point, not the hour. The pushdown
// asks VictoriaLogs for `| stats count()` over `stats_query_range` buckets, whose
// width is the request's STEP — so the window silently became the step. Measured
// against Loki 3.7.1: `[30m]` at step=3600 returned 21823 where Loki (and a
// native LogsQL query with the right window) returned 11982; the error is exactly
// zero when range == step and present for every other pair.
//
// The fix evaluates on a FINE grid of gcd(range, step) buckets and folds each
// Loki point from the buckets inside its own `(t-range, t]` window. That is exact
// for the aggregations whose value over a window is the fold of its parts —
// count/sum/bytes and the two rates, which are those counts over a constant
// divisor. Everything else keeps the existing path.
type rangeWindowPlan struct {
	startNs int64
	endNs   int64
	stepNs  int64
	rangeNs int64
	fineNs  int64
}

// maxRangeWindowFineBuckets caps the fine grid. A `[7m]` window at step=10m over
// weeks asks for 1-minute buckets across the whole span; the cap keeps one panel
// from turning into a scan the backend cannot afford. Beyond it the request is
// REFUSED — the only fallback available is the step-wide window, which is the
// defect this file exists to remove.
const maxRangeWindowFineBuckets = 20_000

// additiveRangeOps are the range aggregations whose window value is the SUM of
// the values of its parts. rate and bytes_rate qualify because the translator
// emits the division by the range seconds inside the per-bucket pipeline, so the
// divisor is a constant that factors out of the sum.
var additiveRangeOps = map[logqlpkg.RangeOp]bool{
	logqlpkg.RangeCountOverTime: true,
	logqlpkg.RangeSumOverTime:   true,
	logqlpkg.RangeBytesOverTime: true,
	logqlpkg.RangeRate:          true,
	logqlpkg.RangeBytesRate:     true,
}

// planRangeWindowRollup decides whether a request needs the fine-grid rollup and
// returns the grid to use. It engages only when the LogQL range differs from the
// step — when they are equal the existing single-pass pushdown is already exact.
func planRangeWindowRollup(logqlQuery, startRaw, endRaw, stepRaw string) (rangeWindowPlan, bool) {
	plan, _, ok := planRangeWindowRollupDetailed(logqlQuery, startRaw, endRaw, stepRaw)
	return plan, ok
}

// errRangeWindowTooFine reports that the grid a correct evaluation needs is
// finer than this instance will scan. Returning it is deliberate: the only
// alternative is the step-wide window, which is the defect this file removes, and
// a silently wrong number is worse than a refusal that names its own remedy.
type errRangeWindowTooFine struct {
	rangeDur time.Duration
	stepDur  time.Duration
	buckets  int64
}

func (e *errRangeWindowTooFine) Error() string {
	return fmt.Sprintf(
		"range %s with step %s needs %d evaluation buckets to be computed correctly, over the %d this instance allows; "+
			"widen the step or shorten the time range",
		e.rangeDur, e.stepDur, e.buckets, maxRangeWindowFineBuckets)
}

// planRangeWindowRollupDetailed is planRangeWindowRollup plus the reason a
// needed rollup could not be planned.
func planRangeWindowRollupDetailed(logqlQuery, startRaw, endRaw, stepRaw string) (rangeWindowPlan, error, bool) {
	var plan rangeWindowPlan
	rangeDur, ok := logqlRangeWindow(logqlQuery)
	if !ok || rangeDur <= 0 {
		return plan, nil, false
	}
	stepDur, ok := parsePositiveStepDuration(stepRaw)
	if !ok || stepDur <= 0 {
		return plan, nil, false
	}
	// Only a range SHORTER than the step needs the finer grid. When the range is
	// longer the existing pushdown already evaluates the full window per point
	// (measured against Loki 3.7.1: `[2m]`@60s, `[4m]`@120s and `[30m]`@900s all
	// match point for point); re-folding those would double-count.
	if rangeDur >= stepDur {
		return plan, nil, false
	}
	startNs, hasStart := parseLokiTimeToUnixNano(startRaw)
	endNs, hasEnd := parseLokiTimeToUnixNano(endRaw)
	if !hasStart || !hasEnd || endNs < startNs {
		return plan, nil, false
	}
	stepNs := stepDur.Nanoseconds()
	rangeNs := rangeDur.Nanoseconds()
	fineNs := gcdInt64(rangeNs, stepNs)
	if fineNs <= 0 {
		return plan, nil, false
	}
	if fineNs < int64(time.Second) {
		// VictoriaLogs buckets at second resolution, so a sub-second grid is not
		// implementable — and it only ever arises from Grafana's fractional `$__auto`
		// step against a whole-second range (`[1s]` at step 1.964s), where the
		// residual is under one bucket. Leave those on the existing path instead of
		// refusing a panel over a rounding artefact.
		return plan, nil, false
	}
	if buckets := (endNs - startNs + rangeNs) / fineNs; buckets > maxRangeWindowFineBuckets {
		// Refuse rather than fall back: the fallback is the step-wide window, which
		// is exactly the wrong answer this file exists to stop returning.
		return plan, &errRangeWindowTooFine{rangeDur: rangeDur, stepDur: stepDur, buckets: buckets}, false
	}
	return rangeWindowPlan{
		startNs: startNs,
		endNs:   endNs,
		stepNs:  stepNs,
		rangeNs: rangeNs,
		fineNs:  fineNs,
	}, nil, true
}

// logqlRangeWindow returns the range selector's window for a query the rollup can
// fold — a single additive range aggregation, optionally wrapped in a vector
// aggregation. A subquery (`[1h:5m]`) is left alone: its inner step already
// defines the grid.
func logqlRangeWindow(logqlQuery string) (time.Duration, bool) {
	expr, err := logqlpkg.Parse(strings.TrimSpace(logqlQuery))
	if err != nil {
		return 0, false
	}
	for {
		switch e := expr.(type) {
		case *logqlpkg.VectorAggregation:
			expr = e.Inner
		case *logqlpkg.RangeAggregation:
			if e.Step != "" || !additiveRangeOps[e.Op] {
				return 0, false
			}
			// LogQL accepts `d`, `w` and `y`, which time.ParseDuration rejects —
			// `[1d12h]` would otherwise fail to parse here and silently keep the
			// step-wide window this whole file exists to remove.
			return parsePositiveStepDuration(e.Range)
		default:
			return 0, false
		}
		if expr == nil {
			return 0, false
		}
	}
}

func gcdInt64(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

// rollupStatsQRWindow folds a fine-grid stats_query_range response onto the Loki
// grid: the point at t is the sum of the buckets whose own window lies inside
// `(t-range, t]`. Timestamps come out as FINAL Loki points, so the caller must
// not also run the bucket-END relabelling.
func rollupStatsQRWindow(body []byte, plan rangeWindowPlan) []byte {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	seriesKey, container, raw := statsQRSeriesArray(payload)
	if raw == nil {
		return body
	}
	var series []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &series); err != nil {
		return body
	}
	for i, s := range series {
		valuesRaw, ok := s["values"]
		if !ok {
			continue
		}
		var points [][]json.RawMessage
		if err := json.Unmarshal(valuesRaw, &points); err != nil {
			continue
		}
		folded := foldRangeWindowPoints(points, plan)
		encoded, err := json.Marshal(folded)
		if err != nil {
			continue
		}
		s["values"] = encoded
		series[i] = s
	}
	encodedSeries, err := json.Marshal(series)
	if err != nil {
		return body
	}
	if container == nil {
		payload[seriesKey] = encodedSeries
		out, err := json.Marshal(payload)
		if err != nil {
			return body
		}
		return out
	}
	container[seriesKey] = encodedSeries
	encodedContainer, err := json.Marshal(container)
	if err != nil {
		return body
	}
	payload["data"] = encodedContainer
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

// statsQRSeriesArray locates the series array in either response shape VL uses:
// a top-level "results", or Loki's "data"."result".
func statsQRSeriesArray(payload map[string]json.RawMessage) (string, map[string]json.RawMessage, json.RawMessage) {
	if raw, ok := payload["results"]; ok {
		return "results", nil, raw
	}
	dataRaw, ok := payload["data"]
	if !ok {
		return "", nil, nil
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		return "", nil, nil
	}
	raw, ok := data["result"]
	if !ok {
		return "", nil, nil
	}
	return "result", data, raw
}

// foldRangeWindowPoints sums the fine buckets of each Loki evaluation point's own
// window. A point whose window holds no bucket is omitted, which is what Loki does
// for an empty range.
func foldRangeWindowPoints(points [][]json.RawMessage, plan rangeWindowPlan) [][]json.RawMessage {
	if len(points) == 0 {
		return [][]json.RawMessage{}
	}
	buckets := make(map[int64]float64, len(points))
	for _, point := range points {
		if len(point) < 2 {
			continue
		}
		tsNs, ok := statsQRRawPointNano(point[0])
		if !ok {
			continue
		}
		// Snap onto the fine grid the fold indexes by: timestamps arrive as whole
		// seconds, and a sub-second fine step would otherwise miss its slot.
		tsNs = plan.startNs + int64(math.Round(float64(tsNs-plan.startNs)/float64(plan.fineNs)))*plan.fineNs
		value, ok := statsQRRawPointFloat(point[1])
		if !ok {
			continue
		}
		buckets[tsNs] += value
	}

	out := make([][]json.RawMessage, 0, int((plan.endNs-plan.startNs)/plan.stepNs)+1)
	for t := plan.startNs; t <= plan.endNs; t += plan.stepNs {
		// The inner evaluation ran with step = gcd(range, step), where the range is
		// at least as long as that step — the regime the pushdown already gets
		// right — so its point at t IS the `(t-range, t]` window. Selecting the
		// points that land on the requested step grid is the whole fold.
		total, seen := buckets[t]
		if !seen {
			continue
		}
		ts, err := json.Marshal(t / int64(time.Second))
		if err != nil {
			continue
		}
		out = append(out, []json.RawMessage{
			ts,
			json.RawMessage(strconv.Quote(strconv.FormatFloat(total, 'f', -1, 64))),
		})
	}
	return out
}

// statsQRRawPointNano reads a point timestamp, which VL emits as whole seconds
// and Loki-shaped responses may carry as a string.
func statsQRRawPointNano(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, false
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return int64(f * float64(time.Second)), true
	}
	return 0, false
}

func statsQRRawPointFloat(raw json.RawMessage) (float64, bool) {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// rangeWindowRollupKey marks a request that is already the INNER evaluation of a
// sliding-window rollup, so the wrapper does not recurse into itself.
type rangeWindowRollupKey struct{}

// rangeWindowRollupActive reports whether r is the inner evaluation.
func rangeWindowRollupActive(ctx context.Context) bool {
	return ctx != nil && ctx.Value(rangeWindowRollupKey{}) != nil
}

// withRangeWindowRollup marks a request as the inner evaluation.
func withRangeWindowRollup(ctx context.Context) context.Context {
	return context.WithValue(ctx, rangeWindowRollupKey{}, struct{}{})
}

// requestWithFineStep clones r with the step replaced by the plan's fine grid and
// the inner-evaluation marker set.
func requestWithFineStep(r *http.Request, plan rangeWindowPlan) *http.Request {
	inner := r.Clone(withRangeWindowRollup(r.Context()))
	fine := formatLogQLDuration(time.Duration(plan.fineNs))
	q := inner.URL.Query()
	q.Set("step", fine)
	inner.URL.RawQuery = q.Encode()
	// r.Form is already parsed at this point and FormValue reads it first.
	if inner.Form != nil {
		inner.Form.Set("step", fine)
	}
	if inner.PostForm != nil && inner.PostForm.Get("step") != "" {
		inner.PostForm.Set("step", fine)
	}
	return inner
}
