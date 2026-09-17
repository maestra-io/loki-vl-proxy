package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	fj "github.com/valyala/fastjson"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
	"github.com/ReliablyObserve/Loki-VL-proxy/internal/translator"
)

type statsCompatSpec struct {
	BaseQuery   string
	GroupBy     []string
	OrigGroupBy []string // original Loki label names before VL translation (e.g. detected_level → level)
	ByExplicit  bool     // true when "by ()" was present — aggregate all into one series
	Func        string
	Field       string

	// OuterAggAcrossSeries is the outer aggregation that must run ACROSS the
	// per-label-set series instead of being folded into a pooled grouping — see
	// outerAggregationOverSeries. OuterAggBy carries its by() labels.
	OuterAggAcrossSeries string
	OuterAggBy           []string
	// OuterAggWithout says OuterAggBy lists the labels to DROP (`without (…)`)
	// rather than the ones to keep.
	OuterAggWithout bool

	// UserParserStages records whether the CLIENT's LogQL carried a parser stage
	// (| json, | logfmt, | pattern, | regexp, | unpack). It is read from the
	// original query, never sniffed out of the translated LogsQL: the translator
	// injects parser pipes of its own for -derived-level-group-by, and those are
	// indistinguishable from the user's once the query is a string.
	//
	// The distinction decides whether Loki's "parse-failed lines are excluded
	// from the aggregation" semantics apply — which only a user's parser can
	// trigger — so getting it wrong either returns rows Loki would drop or
	// forces a raw-row scan that need not happen.
	UserParserStages bool
}

type originalRangeMetricSpec struct {
	Func        string
	Window      time.Duration
	UnwrapField string
	UnwrapConv  string
	HasUnwrap   bool
	BaseQuery   string // inner stream selector + pipeline, without range window [T]
}

type rangeMetricSample struct {
	ts    int64
	value float64
}

var (
	rangeMetricUnwrapRE  = regexp.MustCompile(`(?s)\|\s*unwrap\s+([^|\[]+)`)
	outerAggregationRE   = regexp.MustCompile(`^(?:sum|avg|max|min|count(?:_values)?|stddev|stdvar|sort(?:_desc)?|topk|bottomk)\s*(?:(?:by|without)\s*\([^)]*\)\s*)?`)
	outerByAfterRE       = regexp.MustCompile(`\)\s+by\s*\(([^)]+)\)\s*$`)
	outerByBeforeRE      = regexp.MustCompile(`^(?:sum|avg|min|max|count[^(]*|stddev|stdvar)\s+by\s*\(([^)]+)\)\s*\(`)
	outerWithoutAfterRE  = regexp.MustCompile(`\)\s+without\s*\(([^)]+)\)\s*$`)
	outerWithoutBeforeRE = regexp.MustCompile(`^(?:sum|avg|min|max|count[^(]*|stddev|stdvar)\s+without\s*\(([^)]+)\)\s*\(`)
)

// parseOriginalWithoutLabels returns the labels of the outer `without (…)`
// clause, nil when the aggregation has none.
func parseOriginalWithoutLabels(logql string) []string {
	var raw string
	if m := outerWithoutAfterRE.FindStringSubmatch(logql); m != nil {
		raw = m[1]
	} else if m := outerWithoutBeforeRE.FindStringSubmatch(logql); m != nil {
		raw = m[1]
	}
	return splitLabelList(raw)
}

func splitLabelList(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, l := range strings.Split(raw, ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func parseStatsCompatSpec(logsqlQuery string) (statsCompatSpec, bool) {
	idx := strings.Index(logsqlQuery, "| stats ")
	if idx < 0 {
		return statsCompatSpec{}, false
	}

	spec := statsCompatSpec{
		BaseQuery: strings.TrimSpace(logsqlQuery[:idx]),
	}
	rest := strings.TrimSpace(logsqlQuery[idx+len("| stats "):])
	if rest == "" {
		return statsCompatSpec{}, false
	}

	if strings.HasPrefix(rest, "by (") {
		closeIdx := strings.Index(rest, ")")
		if closeIdx > len("by (") {
			labels := strings.TrimSpace(rest[len("by ("):closeIdx])
			if labels != "" {
				for _, label := range strings.Split(labels, ",") {
					label = strings.TrimSpace(label)
					if label != "" {
						spec.GroupBy = append(spec.GroupBy, label)
					}
				}
			}
			rest = strings.TrimSpace(rest[closeIdx+1:])
		} else if closeIdx == len("by (") {
			// "by ()" — explicit empty grouping: one series, no label dimensions.
			spec.ByExplicit = true
			rest = strings.TrimSpace(rest[closeIdx+1:])
		}
	}

	openIdx := strings.Index(rest, "(")
	switch {
	case openIdx < 0:
		spec.Func = strings.TrimSpace(rest)
	case strings.HasSuffix(rest, ")"):
		spec.Func = strings.TrimSpace(rest[:openIdx])
		spec.Field = strings.TrimSpace(rest[openIdx+1 : len(rest)-1])
	default:
		return statsCompatSpec{}, false
	}

	if spec.BaseQuery == "" || spec.Func == "" {
		return statsCompatSpec{}, false
	}

	return spec, true
}

// parseSingleFieldCountSpec accepts only a translated query of the exact shape
// `<base> | stats by (<field>) count()` — the shape the single-field count fast
// paths (windowed /hits, two-phase top-N, Drilldown field paths) rebuild from
// BaseQuery. parseStatsCompatSpec reads only the first stats pipe, so the rate
// translation `| stats by (f) count() as __lvp_inner | math __lvp_inner/<window>
// ...` also reports Func "count"; rebuilding it as a bare count() drops the
// per-second division and returns raw window counts where Loki returns rates.
func parseSingleFieldCountSpec(logsqlQuery string) (statsCompatSpec, bool) {
	spec, ok := parseStatsCompatSpec(logsqlQuery)
	if !ok || spec.Func != "count" || len(spec.GroupBy) != 1 {
		return statsCompatSpec{}, false
	}
	// The count() stats pipe must be the final stage.
	rest := logsqlQuery[strings.Index(logsqlQuery, "| stats ")+len("| stats "):]
	if strings.Contains(rest, "|") || !strings.HasSuffix(strings.TrimSpace(rest), "count()") {
		return statsCompatSpec{}, false
	}
	return spec, true
}

// stripOuterLabelReplace removes label_replace(v, ...) wrappers from a logql
// expression, returning the innermost wrapped expression. This allows
// parseOriginalRangeMetricSpec to reach the actual metric function even when
// the query is wrapped in one or more label_replace() calls.
func stripOuterLabelReplace(logql string) string {
	for {
		logql = strings.TrimSpace(logql)
		if !strings.HasPrefix(logql, "label_replace(") {
			break
		}
		idx := strings.Index(logql, "(")
		if idx < 0 {
			break
		}
		depth := 0
		commaAt := -1
		for i := idx + 1; i < len(logql); i++ {
			c := logql[i]
			switch {
			case c == '(':
				depth++
			case c == ')':
				if depth == 0 {
					goto done
				}
				depth--
			case c == ',' && depth == 0:
				commaAt = i
				goto done
			}
		}
	done:
		if commaAt < 0 {
			break
		}
		logql = strings.TrimSpace(logql[idx+1 : commaAt])
	}
	return logql
}

func parseOriginalRangeMetricSpec(logql string) (originalRangeMetricSpec, bool) {
	logql = strings.TrimSpace(logql)
	// Strip label_replace wrappers so the inner metric function is visible.
	logql = stripOuterLabelReplace(logql)
	// Strip outer aggregation like "sum by (method) (rate(...))" → "rate(...)"
	// so we parse the inner range function, not the aggregation operator.
	if loc := outerAggregationRE.FindStringIndex(logql); loc != nil && loc[0] == 0 && loc[1] < len(logql) {
		inner := strings.TrimSpace(logql[loc[1]:])
		if strings.HasPrefix(inner, "(") && strings.HasSuffix(inner, ")") {
			inner = strings.TrimSpace(inner[1 : len(inner)-1])
		}
		logql = inner
	}
	openIdx := strings.Index(logql, "(")
	closeIdx := strings.LastIndex(logql, ")")
	if openIdx <= 0 || closeIdx <= openIdx {
		return originalRangeMetricSpec{}, false
	}

	spec := originalRangeMetricSpec{
		Func: strings.TrimSpace(logql[:openIdx]),
	}
	body := strings.TrimSpace(logql[openIdx+1 : closeIdx])
	bracketOpen := strings.LastIndex(body, "[")
	bracketClose := strings.LastIndex(body, "]")
	if bracketOpen < 0 || bracketClose <= bracketOpen {
		return originalRangeMetricSpec{}, false
	}
	spec.Window = parseLokiDuration(strings.TrimSpace(body[bracketOpen+1 : bracketClose]))
	if spec.Window < 0 {
		return originalRangeMetricSpec{}, false
	}
	spec.BaseQuery = strings.TrimSpace(body[:bracketOpen])

	unwrap := rangeMetricUnwrapRE.FindStringSubmatch(body)
	if len(unwrap) == 2 {
		spec.HasUnwrap = true
		spec.UnwrapField, spec.UnwrapConv = parseUnwrapExpression(unwrap[1])
	}

	return spec, true
}

// isLogRangeWindowFunc reports the log-line range functions whose Loki window
// (t-range, t] excludes lines on its lower edge and includes the evaluation time.
func isLogRangeWindowFunc(manualFunc string) bool {
	switch manualFunc {
	case "rate", "count_over_time", "bytes_over_time", "bytes_rate":
		return true
	}
	return false
}

func isManualRangeStatsFunc(funcName string) bool {
	switch strings.TrimSpace(funcName) {
	case "rate", "count", "sum_len", "sum", "avg", "max", "min", "stddev", "stdvar", "quantile", "first", "last", "__rate_counter__":
		return true
	default:
		return false
	}
}

func normalizeManualMetricFunction(spec statsCompatSpec, origSpec originalRangeMetricSpec) string {
	switch strings.TrimSpace(origSpec.Func) {
	case "rate":
		return "rate"
	case "count_over_time":
		return "count_over_time"
	case "bytes_over_time":
		return "bytes_over_time"
	case "bytes_rate":
		return "bytes_rate"
	case "sum_over_time":
		return "sum"
	case "avg_over_time":
		return "avg"
	case "max_over_time":
		return "max"
	case "min_over_time":
		return "min"
	case "stddev_over_time":
		return "stddev"
	case "stdvar_over_time":
		return "stdvar"
	case "first_over_time":
		return "first"
	case "last_over_time":
		return "last"
	case "rate_counter":
		return "rate_counter"
	case "quantile_over_time":
		return "quantile"
	}

	switch strings.TrimSpace(spec.Func) {
	case "rate":
		return "rate"
	case "count":
		return "count_over_time"
	case "sum_len":
		if strings.TrimSpace(origSpec.Func) == "bytes_rate" {
			return "bytes_rate"
		}
		return "bytes_over_time"
	case "sum":
		return "sum"
	case "avg":
		return "avg"
	case "max":
		return "max"
	case "min":
		return "min"
	case "stddev":
		return "stddev"
	case "stdvar":
		return "stdvar"
	case "quantile":
		return "quantile"
	case "first":
		return "first"
	case "last":
		return "last"
	case "__rate_counter__":
		return "rate_counter"
	default:
		return ""
	}
}

func metricFuncRequiresUnwrap(funcName string) bool {
	switch strings.TrimSpace(funcName) {
	case "sum_over_time", "avg_over_time", "max_over_time", "min_over_time", "stddev_over_time", "stdvar_over_time", "first_over_time", "last_over_time", "quantile_over_time", "rate_counter":
		return true
	default:
		return false
	}
}

func unwrapErrorFuncName(funcName string) string {
	funcName = strings.TrimSpace(funcName)
	if funcName != "" {
		return funcName
	}
	return "range_aggregation"
}

func parseStatsQuantileSpec(field string) (float64, string, bool) {
	parts := strings.SplitN(field, ",", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	phi, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	if err != nil {
		return 0, "", false
	}
	return phi, strings.TrimSpace(parts[1]), true
}

func parseUnwrapExpression(expr string) (field, conv string) {
	expr = strings.TrimSpace(expr)
	expr = strings.Trim(expr, "`\"")

	switch {
	case strings.HasPrefix(expr, "duration(") && strings.HasSuffix(expr, ")"):
		field = strings.TrimSpace(expr[len("duration(") : len(expr)-1])
		conv = "duration"
	case strings.HasPrefix(expr, "bytes(") && strings.HasSuffix(expr, ")"):
		field = strings.TrimSpace(expr[len("bytes(") : len(expr)-1])
		conv = "bytes"
	default:
		field = strings.TrimSpace(expr)
	}

	field = strings.Trim(field, "`\"")
	return field, conv
}

// parseOriginalByLabels extracts the outer by(...) label names from a LogQL
// metric query. Handles both "sum(...) by (labels)" and "sum by (labels) (...)"
// forms. Returns nil when no outer by-clause is present.
func parseOriginalByLabels(logql string) []string {
	var raw string
	if m := outerByAfterRE.FindStringSubmatch(logql); m != nil {
		raw = m[1]
	} else if m := outerByBeforeRE.FindStringSubmatch(logql); m != nil {
		raw = m[1]
	}
	return splitLabelList(raw)
}

// rejectMultiStageSlidingRange answers a two-stage range query that the native
// backend cannot evaluate faithfully. Returns true when it wrote a response.
//
// VL's stats_query_range buckets by `step` (tumbling); a LogQL range
// aggregation is a SLIDING window of `range` evaluated every `step`. They
// coincide only while range <= step, which is the case that is allowed through.
func (p *Proxy) rejectMultiStageSlidingRange(w http.ResponseWriter, r *http.Request, originalLogql string) bool {
	step, stepOk := parsePositiveStepDuration(r.FormValue("step"))
	origSpec, hasOrigSpec := parseOriginalRangeMetricSpec(originalLogql)
	if !stepOk || !hasOrigSpec || origSpec.Window <= step {
		return false
	}
	p.writeError(w, http.StatusBadRequest, fmt.Sprintf(
		"unsupported query: an aggregation over a range aggregation with its own grouping "+
			"(for example `sum by (a) (max_over_time({...}[%s]) by (b))`) is evaluated by the "+
			"backend in tumbling %s buckets, which does not match LogQL's sliding %s window. "+
			"Use a step >= the range, or drop one of the two grouping clauses.",
		formatLogQLDuration(origSpec.Window), formatLogQLDuration(step), formatLogQLDuration(origSpec.Window)))
	return true
}

func (p *Proxy) handleStatsCompatRange(w http.ResponseWriter, r *http.Request, originalLogql, logsqlQuery string) bool {
	// A pipeline carrying a Go template (| line_format / | label_format) cannot
	// be evaluated by VictoriaLogs at all — see template_pipeline.go. It must be
	// caught before every branch below, because the translated LogsQL looks
	// perfectly ordinary (the template became a `| format` pipe) and would
	// otherwise be routed straight to the native stats endpoint.
	if p.handleTemplateMetricRange(w, r, originalLogql, logsqlQuery) {
		return true
	}
	// A genuine two-stage aggregation (inner range grouping + outer aggregation)
	// is not expressible in this layer's single-fold model — see
	// isMultiStageStatsQuery — so VictoriaLogs runs both stages natively.
	//
	// VL's stats_query_range buckets by `step` (tumbling), while a LogQL range
	// aggregation is a SLIDING window of `range` evaluated every `step`. The two
	// coincide only while range <= step. Beyond that the native result is wrong,
	// and evaluating a sliding TWO-stage fold is not something this layer can do
	// (it folds once, per series). Refuse rather than return a plausible number.
	if isMultiStageStatsQuery(logsqlQuery) && rangeAggregationHasOwnGrouping(originalLogql) {
		return p.rejectMultiStageSlidingRange(w, r, originalLogql)
	}
	// Queries containing | math are multi-stage VL rate pipelines built by the translator
	// (e.g. sum(rate({...} | json [w]))). For tumbling windows (range == step), VL can
	// execute them natively — no manual decomposition needed. For any other range, fall
	// through to the manual path which evaluates each step's (T-range, T] window.
	//
	// Exception: queries with parser stages (| json, | logfmt, etc.) without an explicit
	// "| drop __error__" opt-in must NOT use VL native stats for tumbling windows. Loki
	// excludes parse-failed lines from metric aggregation; VL counts all lines. The manual
	// path (collectRangeMetricSamples) preserves Loki's error-exclusion semantics.
	if strings.Contains(logsqlQuery, "| math ") {
		step, stepOk := parsePositiveStepDuration(r.FormValue("step"))
		origSpec, hasOrigSpec := parseOriginalRangeMetricSpec(originalLogql)
		if stepOk && hasOrigSpec && origSpec.Window > 0 && p.statsRangeIsTumbling(r, origSpec.Window, step) {
			spec, specOk := parseStatsCompatSpec(logsqlQuery)
			spec.UserParserStages = logqlUsesParserStage(originalLogql)
			// Parser stages without an explicit drop-error opt-in require the manual path
			// to preserve Loki's error-exclusion semantics. Use origSpec.BaseQuery (the inner
			// LogQL stream selector + pipeline without the range window) for the drop-error
			// check — hasDropErrorOnlyPostParserStage requires the pipeline without outer
			// aggregation or range window brackets.
			if !specOk || !spec.UserParserStages || hasDropErrorOnlyPostParserStage(origSpec.BaseQuery) {
				return false
			}
			// Parser stage without drop-error — fall through to the manual path below.
		}
	}
	spec, ok := parseStatsCompatSpec(logsqlQuery)
	if !ok {
		return false
	}
	spec.UserParserStages = logqlUsesParserStage(originalLogql)
	if !isManualRangeStatsFunc(spec.Func) {
		return false
	}
	// Capture original Loki by-labels so we can translate VL label names back
	// in the metric response (e.g. VL "level" → Loki "detected_level").
	spec.OrigGroupBy = parseOriginalByLabels(originalLogql)
	origSpec, hasOrigSpec := parseOriginalRangeMetricSpec(originalLogql)

	manualFunc := normalizeManualMetricFunction(spec, origSpec)
	if manualFunc == "" {
		return false
	}
	step, _ := parsePositiveStepDuration(r.FormValue("step"))
	rangeEqualsStep := p.statsRangeIsTumbling(r, origSpec.Window, step)
	// For tumbling windows, an explicit "| drop __error__" in the original LogQL opts in to
	// VL's count-all semantics (parse failures counted). Use origSpec.BaseQuery — the inner
	// pipeline without outer aggregation or range brackets — so hasDropErrorOnlyPostParserStage
	// can correctly identify the drop-error clause.
	if manualFunc != "quantile" && rangeEqualsStep && spec.UserParserStages && hasOrigSpec && hasDropErrorOnlyPostParserStage(origSpec.BaseQuery) {
		return false
	}
	if !manualQuantileRoutable(spec, manualFunc) &&
		!shouldUseManualRangeMetricCompat(spec.BaseQuery, manualFunc, rangeEqualsStep) {
		return false
	}
	if !hasOrigSpec || origSpec.Window <= 0 {
		p.writeError(w, http.StatusBadRequest, "invalid range metric query")
		return true
	}
	if metricFuncRequiresUnwrap(origSpec.Func) && (!origSpec.HasUnwrap || strings.TrimSpace(origSpec.UnwrapField) == "") {
		p.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func)))
		return true
	}
	// A bare outer aggregation without by() collapses all streams into one empty-label
	// series in Loki. Set ByExplicit=true so buildManualMetricLabels returns {} and
	// collectRangeMetricSamples produces a single series — not one per stream.
	applyLokiSeriesDecomposition(&spec, originalLogql, manualFunc)
	return p.proxyManualRangeMetricRange(w, r, spec, origSpec, manualFunc)
}

// isMultiStageStatsQuery reports whether the translated LogsQL aggregates TWICE
// — an inner `| stats by (...) <fn>() as __lvp_inner` feeding an outer
// `| stats [by (...)] <fn>(__lvp_inner)`.
//
// The stats-compat layer models ONE aggregation: it reads raw rows and folds
// them with a single function, and parseStatsCompatSpec takes its grouping from
// the FIRST stats stage. On a two-stage query that silently returns the INNER
// result, relabelled with the OUTER query's by() names — e.g.
// `sum by (container) (max_over_time(... ) by (namespace))` came back as
// {container="<namespace value>"} carrying the per-namespace max, with the sum
// never applied. VictoriaLogs executes both stages correctly on its own, so
// these queries must fall through to the native stats path.
//
// Rate pipelines are the deliberate exception: the translator builds them as
// `stats … as __lvp_inner | math … | stats …`, and the manual path implements
// their per-step accumulation on purpose. They are identified by `| math `.
// rangeAggregationHasOwnGrouping reports whether the RANGE aggregation carries
// its own `by (...)` / `without (...)` clause, as in
// `sum by (app) (max_over_time({...}[5m]) by (ns))`.
//
// That is the only shape the two-stage translation introduces. An outer
// aggregation over an UNGROUPED range aggregation — `max(quantile_over_time(…))`
// — has also always produced two stats stages, but the compat layer has handled
// it correctly for far longer, so it must not be diverted.
func rangeAggregationHasOwnGrouping(logql string) bool {
	logql = strings.TrimSpace(stripOuterLabelReplace(logql))
	loc := outerAggregationRE.FindStringIndex(logql)
	if loc == nil || loc[0] != 0 || loc[1] >= len(logql) {
		// No outer aggregation: a trailing clause here belongs to the range
		// aggregation itself, which is a single stage.
		return false
	}
	inner := strings.TrimSpace(logql[loc[1]:])
	if !strings.HasPrefix(inner, "(") || !strings.HasSuffix(inner, ")") {
		return false
	}
	inner = strings.TrimSpace(inner[1 : len(inner)-1])
	return outerByAfterRE.MatchString(inner) || rangeWithoutAfterRE.MatchString(inner)
}

// rangeWithoutAfterRE is outerByAfterRE's `without (...)` twin.
var rangeWithoutAfterRE = regexp.MustCompile(`\)\s+without\s*\(([^)]*)\)\s*$`)

func isMultiStageStatsQuery(logsqlQuery string) bool {
	// Count PIPE stages only. A line filter carrying the literal text — e.g.
	// `{...} |= "| stats "`, translated to `~"| stats "` — is data, not a stage,
	// and a raw scan would read a one-stage query as two and route it away from
	// the compat layer. stripQuotedSpans blanks quoted contents in place, so
	// offsets and every unquoted stage marker survive.
	scanned := stripQuotedSpans(logsqlQuery)
	if strings.Contains(scanned, "| math ") {
		return false
	}
	return strings.Count(scanned, "| stats ") >= 2
}

// isRateMathPipeline reports whether a translated LogsQL query is a rate-style
// pipeline: a per-bucket stats stage, a `| math <field>/<window>` division and a
// second stats stage that re-aggregates the divided value.
//
// parseStatsCompatSpec only understands a SINGLE stats clause, so it reads such
// a pipeline as a plain `count` and swallows the division into Field. Any caller
// that REBUILDS a query from that spec would therefore drop the division and
// return counts — rate multiplied by the window in seconds (a topk(5, sum by (ns)
// (rate([5m]))) panel came back ×300 against Loki).
func isRateMathPipeline(logsqlQuery string) bool {
	scanned := stripQuotedSpans(logsqlQuery)
	return strings.Contains(scanned, "| math ") && strings.Count(scanned, "| stats ") >= 2
}

// statsRangeIsTumbling reports whether native step buckets answer a range
// metric: only when the range equals the step, where one VictoriaLogs bucket is
// exactly one Loki window, and the backend can place bucket edges on the
// request's windows (tumblingBucketsAligned). With range < step a bucket also
// holds the lines between windows, which Loki never counts, and with range >
// step the windows overlap; both use the anchored window evaluator.
//
// Grafana Logs Drilldown requests keep their earlier routing, where range <=
// step is native: their hits and hybrid paths build, coarsen and zero-fill a
// bucket-start axis that every panel of the page shares.
func (p *Proxy) statsRangeIsTumbling(r *http.Request, window, step time.Duration) bool {
	if step <= 0 || window <= 0 || window > step {
		return false
	}
	if isGrafanaDrilldownRequest(r) {
		return true
	}
	return window == step && p.tumblingBucketsAligned(r, window)
}

// tumblingBucketsAligned reports whether stats_query_range buckets of window
// can cover the request's evaluation windows: always when the backend honours
// the offset arg (VictoriaLogs v1.45+), otherwise only when the start is
// epoch-aligned to window, like slidingStatsBucket. An unknown version (probe
// pending or failed) counts as no offset support.
func (p *Proxy) tumblingBucketsAligned(r *http.Request, window time.Duration) bool {
	if p.supportsStatsRangeOffset() {
		return true
	}
	startNs, ok := parseLokiTimeToUnixNano(r.FormValue("start"))
	return ok && window > 0 && startNs%int64(window) == 0
}

func (p *Proxy) handleStatsCompatInstant(w http.ResponseWriter, r *http.Request, originalLogql, logsqlQuery string) bool {
	if p.handleTemplateMetricInstant(w, r, originalLogql, logsqlQuery) {
		return true
	}
	if isMultiStageStatsQuery(logsqlQuery) && rangeAggregationHasOwnGrouping(originalLogql) {
		return false
	}
	spec, ok := parseStatsCompatSpec(logsqlQuery)
	if !ok {
		return false
	}
	spec.UserParserStages = logqlUsesParserStage(originalLogql)
	if !isManualRangeStatsFunc(spec.Func) {
		return false
	}
	spec.OrigGroupBy = parseOriginalByLabels(originalLogql)
	origSpec, hasOrigSpec := parseOriginalRangeMetricSpec(originalLogql)

	manualFunc := normalizeManualMetricFunction(spec, origSpec)
	if manualFunc == "" {
		return false
	}
	// Instant queries with parser stages and explicit drop-error: use native VL stats.
	// VL correctly evaluates [time-range, time] for instant queries; the drop-error opt-in
	// means parse-failed lines are intentionally excluded — count-all semantics are acceptable.
	if manualFunc != "quantile" && spec.UserParserStages && hasOrigSpec && hasDropErrorOnlyPostParserStage(origSpec.BaseQuery) {
		return false
	}
	// Instant queries have no step: the range window is the entire lookback interval,
	// not a sliding window. VL native stats correctly evaluates [time-range, time].
	// Only rate_counter still requires the manual path (counter-reset semantics).
	// Exception: parser-stage queries without explicit drop-error still use the manual path
	// so that bare outer aggregations (sum without by()) correctly collapse all streams into
	// one series via ByExplicit=true. Native VL stats returns per-stream series for such
	// queries; the manual path aggregates them into the expected single series.
	if spec.UserParserStages {
		// Parser+no-drop-error → always manual for correct stream-collapse semantics.
	} else if !manualQuantileRoutable(spec, manualFunc) &&
		!shouldUseManualRangeMetricCompat(spec.BaseQuery, manualFunc, true) {
		return false
	}
	if !hasOrigSpec || origSpec.Window <= 0 {
		p.writeError(w, http.StatusBadRequest, "invalid range metric query")
		return true
	}
	if metricFuncRequiresUnwrap(origSpec.Func) && (!origSpec.HasUnwrap || strings.TrimSpace(origSpec.UnwrapField) == "") {
		p.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func)))
		return true
	}
	// A bare outer aggregation without by() collapses all streams into one empty-label
	// series in Loki. Set ByExplicit=true so buildManualMetricLabels returns {} and
	// collectRangeMetricSamples produces a single series — not one per stream.
	applyLokiSeriesDecomposition(&spec, originalLogql, manualFunc)
	return p.proxyManualRangeMetricInstant(w, r, spec, origSpec, manualFunc)
}

// hasOuterAggregationWithoutBy reports whether logql starts with a bare outer aggregation
// (sum, avg, max, min, count, …) that carries no by() or without() grouping modifier.
// Loki evaluates such expressions as a single series with no label dimensions.
func hasOuterAggregationWithoutBy(logql string) bool {
	logql = strings.TrimSpace(logql)
	logql = stripOuterLabelReplace(logql)
	loc := outerAggregationRE.FindStringIndex(logql)
	if loc == nil || loc[0] != 0 || loc[1] >= len(logql) {
		return false
	}
	// Guard against prefix collisions: outerAggregationRE matches "count" as a prefix of
	// "count_over_time". The text after the aggregation keyword (+ optional by/without
	// clause) must start with "(" to be a genuine outer aggregation operator.
	if !strings.HasPrefix(strings.TrimSpace(logql[loc[1]:]), "(") {
		return false
	}
	matched := strings.ToLower(logql[:loc[1]])
	return !strings.Contains(matched, " by") && !strings.Contains(matched, " without")
}

// parseTopKWrapper detects a top-level topk(K, expr) or bottomk(K, expr) wrapper.
// Returns k, whether descending (true=topk, false=bottomk), ok=true only when
// topk/bottomk is outermost with a valid positive integer K.
func parseTopKWrapper(logql string) (k int, descending bool, ok bool) {
	if strings.TrimSpace(logql) == "" {
		return 0, false, false
	}
	parsed, err := logqlpkg.Parse(strings.TrimSpace(logql))
	if err != nil {
		return 0, false, false
	}
	va, isVA := parsed.(*logqlpkg.VectorAggregation)
	if !isVA || !va.HasParam {
		return 0, false, false
	}
	switch va.Op {
	case logqlpkg.VectorTopK:
		if int(va.Param) <= 0 {
			return 0, false, false
		}
		return int(va.Param), true, true
	case logqlpkg.VectorBottomK:
		if int(va.Param) <= 0 {
			return 0, false, false
		}
		return int(va.Param), false, true
	}
	return 0, false, false
}

// shouldUseManualRangeMetricCompat reports whether the given metric function
// must be aggregated in the proxy (manual path) rather than offloaded to
// VictoriaLogs /select/logsql/stats_query_range.
//
// rangeEqualsStep must be true when the LogQL range window equals the query
// step. When true, VL's native rate() — which buckets by the step interval —
// is semantically identical to LogQL rate()[range]. Pass false to keep the
// sliding-window manual path for cases where range != step.
// manualQuantileRoutable reports whether a quantile query must be evaluated
// HERE rather than pushed to VictoriaLogs.
//
// VL's `quantile()` returns an actual sample (nearest rank); LogQL interpolates
// between the two order statistics around `q*(n-1)`, exactly as Prometheus does.
// Measured against Loki 3.7.1 over the ten samples 109…199: q=0.95 → Loki 194.5,
// VL 199; q=0.5 → Loki 154, VL 149. They agree only when the two neighbouring
// samples happen to be equal, so the quantile is computed here from the raw
// values with Loki's formula (quantileFloat64).
//
// A two-stage translation (an outer aggregation over the quantile) hides the
// field inside a second stats clause that this spec cannot parse; those keep
// their existing route.
func manualQuantileRoutable(spec statsCompatSpec, manualFunc string) bool {
	if manualFunc != "quantile" {
		return false
	}
	_, field, ok := parseStatsQuantileSpec(spec.Field)
	// A two-stage translation leaves the rest of the pipeline inside `field`
	// ("duration_ms) as __lvp_inner | stats max(...)"), which parses but names
	// nothing; routing that here yields an empty result.
	return ok && field != "" && !strings.ContainsAny(field, " |()\"'")
}

func shouldUseManualRangeMetricCompat(baseQuery, manualFunc string, rangeEqualsStep bool) bool {
	manualFunc = strings.TrimSpace(manualFunc)
	// Loki interpolates between adjacent ranked samples. VL's quantile uses a
	// different rank selection, and its range endpoint uses tumbling buckets.
	// Use the existing exact sample evaluator for both instant and range queries.
	if manualFunc == "rate_counter" || manualFunc == "quantile" {
		return true
	}

	// For sliding windows (range != step) VL native stats_query_range buckets by the
	// step interval (tumbling windows) while LogQL evaluates each point over [T-range, T].
	// When the data distribution is non-uniform the two diverge. Route to the manual
	// log-fetch path for correct sliding-window semantics.
	// When range == step windows are non-overlapping and native VL stats is equivalent,
	// including for queries that use parser stages (| unpack_json, | unpack_logfmt): VL stats_query_range
	// natively supports inline filter pipelines and parser stages.
	switch manualFunc {
	case "rate", "bytes_rate", "count_over_time", "bytes_over_time":
		return !rangeEqualsStep
	}

	if !queryUsesParserStages(baseQuery) {
		return false
	}

	// Parser stages present — native VL stats is safe for unwrap-based aggregations
	// (parse failures self-filter via absent fields) and for non-sliding windows.
	switch manualFunc {
	case "avg", "sum", "min", "max", "quantile", "stddev", "stdvar", "first", "last":
		return false
	default:
		return true
	}
}

// proxyManualRangeMetricRange evaluates a range metric in the proxy. Like Loki,
// it emits a sample only for steps whose window (t-range, t] holds log lines,
// for every client: absent steps stay absent (no zero-fill), which also keeps
// absent series out of topk/bottomk ranking.
func (p *Proxy) proxyManualRangeMetricRange(w http.ResponseWriter, r *http.Request, spec statsCompatSpec, origSpec originalRangeMetricSpec, manualFunc string) bool {
	// The first translated stats clause may group by stream before the outer
	// sum. For additive log metrics, combine the raw counts/bytes before window
	// evaluation and keep the native stats fast path for aggregate-all queries.
	if isSumAllLogRange(r.FormValue("query")) {
		spec.GroupBy, spec.OrigGroupBy = nil, nil
		spec.ByExplicit = true
	}
	startTS, err := parseTimestamp(r.FormValue("start"))
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "invalid start timestamp: "+err.Error())
		return true
	}
	endTS, err := parseTimestamp(r.FormValue("end"))
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "invalid end timestamp: "+err.Error())
		return true
	}
	step := parseLokiDuration(formatVLStep(r.FormValue("step")))
	if step <= 0 {
		step = time.Minute
	}
	field, quantile, fieldErr := p.resolveManualMetricField(spec, origSpec, manualFunc)
	if fieldErr != nil {
		p.writeError(w, http.StatusBadRequest, fieldErr.Error())
		return true
	}
	if field == "" {
		p.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func)))
		return true
	}

	// Fast path: count_over_time / rate / bytes_over_time / bytes_rate with
	// explicit groupBy — use VL's stats_query_range endpoint which returns
	// pre-aggregated Prometheus buckets, avoiding reading every raw log entry.
	// Conditions: (1) field is __count__ or __bytes__, (2) groupBy has no _stream
	// sentinel (stats endpoint can group by stream labels; sentinel means caller
	// needs VL to enumerate all distinct streams — skip), (3) labels are explicit
	// (non-empty groupBy or byExplicit aggregate-all).
	var statsAggFunc string
	switch field {
	case "__count__":
		statsAggFunc = "count() as c"
	case "__bytes__":
		// Retain empty log lines without scanning raw logs: byte sum zero
		// alone cannot distinguish an absent bucket from a present empty line.
		statsAggFunc = "sum_len(_msg) as c, count() as __sample_count"
	}
	// Bucket edges must coincide with every evaluation window edge. When no
	// bounded bucket grid exists, the exact raw-sample evaluator answers.
	// fetchStart is the left edge of the first bucket (or raw fetch), and
	// sampleShift moves bucket labels onto the window they hold.
	fetchStart, sampleShift := startTS.Add(-origSpec.Window), time.Duration(0)
	bucket, bucketsOK := p.slidingStatsBucket(startTS, step, origSpec.Window)
	if origSpec.Window < step {
		// Windows shorter than the step are disjoint. Keep only lines inside one,
		// so a bucket per step, (t-step, t], holds exactly the window (t-range, t]
		// and a raw fetch reads only window lines. gcd(step, range) buckets would
		// grow with every step that range does not divide (a 604.8s step and a
		// 5m range need 2.4s buckets: 252k per series over 7 days).
		spec.BaseQuery += windowPhaseFilter(startTS, step, origSpec.Window)
		fetchStart, sampleShift = startTS.Add(-step), step-origSpec.Window
		bucket, bucketsOK = p.slidingStatsBucket(startTS, step, step)
	}
	if !bucketsOK {
		statsAggFunc = ""
	}
	// The Loki-stored line bytes and/or Loki's max_line_size drop, on the
	// non-parser fast path only: the drilldown parser-stage route strips the
	// query down to existence checks and counts, where neither applies.
	statsSpec, statsAggFuncRecord := spec, statsAggFunc
	if pipes, bytesField := p.recordStatsPipes(field == "__bytes__", origSpec.BaseQuery); pipes != "" {
		statsSpec.BaseQuery += " " + pipes
		if bytesField {
			statsAggFuncRecord = "sum(" + translator.RecordBytesField + ") as c, count() as __sample_count"
		}
	}
	// Drilldown burst coalescer: groups ~30 per-field field-presence count_over_time
	// queries into a single fused VL conditional-stats call. Detects byExplicit
	// aggregate-all queries with a | filter field != "" pattern.
	// extractCommonBase strips | json / | logfmt + the field filter so VL uses its
	// pre-indexed column index (| json before count() if returns empty in VL).
	if p.drilldownCoalescer != nil && sampleShift == 0 && origSpec.Window >= step && statsAggFunc == "count() as c" && spec.ByExplicit && len(spec.GroupBy) == 0 {
		if base, field, ok := extractCommonBase(spec.BaseQuery); ok {
			orgID := r.Header.Get("X-Scope-OrgID")
			bKey := burstKey{
				scope:   p.contextScopeFingerprint(r.Context()),
				orgID:   orgID,
				base:    base,
				startNs: startTS.Add(-origSpec.Window).UnixNano(),
				endNs:   endTS.UnixNano(),
				stepNs:  int64(bucket),
			}
			fireFn := p.fusedFieldHits(orgID, base, startTS.Add(-origSpec.Window), endTS, bucket)
			if series, coalErr := p.drilldownCoalescer.Submit(r.Context(), bKey, field, fireFn); coalErr == nil {
				p.writeHitsRangeMetricMatrix(w, manualFunc, series, startTS, endTS, step, origSpec.Window)
				return true
			}
			// Fall through on error — coalescer failure is non-fatal.
		}
	}
	// Anchored buckets hold every (t-range, t] window whatever range and step
	// are, so per-stream series (range != step) and parser stages use them too.
	// With parser stages the stats query keeps them: VictoriaLogs groups by the
	// parsed fields and counts every line, as the raw evaluator does.
	streamBuckets := origSpec.Window != step
	if series, ok, capErr := p.collectStatsFastPathHits(r.Context(), statsSpec, statsAggFuncRecord, fetchStart, endTS, bucket, streamBuckets, false); ok {
		if capErr != nil && !p.serveSeriesCapPartial(w, r, capErr) {
			return true
		}
		p.writeHitsRangeMetricMatrix(w, manualFunc, shiftSeriesSamples(series, sampleShift), startTS, endTS, step, origSpec.Window)
		return true
	}
	if series, ok, capErr := p.collectParserStageStatsFastPathHits(r.Context(), spec, statsAggFunc, fetchStart, endTS, bucket); ok {
		if capErr != nil && !p.serveSeriesCapPartial(w, r, capErr) {
			return true
		}
		p.writeHitsRangeMetricMatrix(w, manualFunc, shiftSeriesSamples(series, sampleShift), startTS, endTS, step, origSpec.Window)
		return true
	}
	if series, ok, capErr := p.collectStatsFastPathHits(r.Context(), spec, statsAggFunc, fetchStart, endTS, bucket, streamBuckets, true); ok {
		if capErr != nil && !p.serveSeriesCapPartial(w, r, capErr) {
			return true
		}
		p.writeHitsRangeMetricMatrix(w, manualFunc, shiftSeriesSamples(series, sampleShift), startTS, endTS, step, origSpec.Window)
		return true
	}

	fetchEnd := endTS
	if manualFunc == "quantile" || isLogRangeWindowFunc(manualFunc) {
		// VL's raw-query end is exclusive; Loki includes the evaluation time.
		fetchEnd = fetchEnd.Add(time.Nanosecond)
	}
	series, err := p.collectRangeMetricSamples(r.Context(), spec.BaseQuery, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, field, origSpec.UnwrapConv, startTS.Add(-origSpec.Window), fetchEnd)
	if err != nil {
		p.writeError(w, badRequestStatusOr(err, statusForRangeMetricCollectError(err)), err.Error())
		return true
	}

	if capErr := p.seriesCapError(len(series), "manual_range_metric"); capErr != nil {
		if !p.serveSeriesCapPartial(w, r, capErr) {
			return true
		}
		// A Drilldown partial keeps the busiest N.
		series = capSeriesByTotalCount(series, p.resolvedMaxStatsQuerySeries())
	}
	// collectRangeMetricSamples returns RAW log entries.
	result, err := buildManualRangeMetricMatrixContext(r.Context(), manualFunc, quantile, series, startTS, endTS, step, origSpec.Window, p.resolvedMaxStatsQuerySeries())
	if err != nil {
		p.writeError(w, http.StatusServiceUnavailable, err.Error())
		return true
	}
	if spec.OuterAggAcrossSeries != "" {
		result = reduceLokiSeriesAcrossSeries(result, spec.OuterAggAcrossSeries, spec.OuterAggBy, spec.OuterAggWithout)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter -- Content-Type set above; proxy returns pre-built JSON
	return true
}

// maxStatsBucketResponseBytes bounds one stats_query_range bucket response of
// the window evaluator; a variable so tests can exercise the overflow paths.
var maxStatsBucketResponseBytes int64 = 64 << 20

// windowPhaseFilter returns LogsQL pipes keeping only the lines inside one of
// the evaluation windows (t-window, t], t = start+k*step, of a range metric
// whose window is shorter than its step. The phase of a line is its distance
// past the window start preceding it, modulo the step: a line is in a window
// when 0 < phase <= window. VictoriaLogs evaluates math in float64, so a line
// within a few hundred nanoseconds of a window edge may fall on either side.
func windowPhaseFilter(start time.Time, step, window time.Duration) string {
	anchor := start.Add(-window).UnixNano()
	return " | math ((_time - " + strconv.FormatInt(anchor, 10) + ") % " + strconv.FormatInt(int64(step), 10) +
		") as __lvp_window_phase | filter __lvp_window_phase:>0 __lvp_window_phase:<=" + strconv.FormatInt(int64(window), 10)
}

// shiftSeriesSamples moves every bucket label and present bucket forward by
// shift, in place: a (t-step, t] bucket of windowPhaseFilter lines is labelled
// t-step and holds the window (t-window, t], which the evaluator reads from
// labels in [t-window, t).
func shiftSeriesSamples(series map[string]manualSeriesSamples, shift time.Duration) map[string]manualSeriesSamples {
	if shift == 0 {
		return series
	}
	for key, entry := range series {
		for i := range entry.Samples {
			entry.Samples[i].ts += int64(shift)
		}
		for i := range entry.PresentBuckets {
			entry.PresentBuckets[i] += int64(shift)
		}
		series[key] = entry
	}
	return series
}

// writeHitsRangeMetricMatrix writes the bucket matrix and returns the HTTP status.
func (p *Proxy) writeHitsRangeMetricMatrix(w http.ResponseWriter, manualFunc string, series map[string]manualSeriesSamples, start, end time.Time, step, window time.Duration) int {
	result, err := buildHitsRangeMetricMatrix(manualFunc, series, start, end, step, window)
	if err != nil {
		p.writeError(w, http.StatusServiceUnavailable, err.Error())
		return http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter -- Content-Type set above; proxy returns pre-built JSON
	return http.StatusOK
}

func isSumAllLogRange(query string) bool {
	expr, err := logqlpkg.Parse(query)
	if err != nil {
		return false
	}
	agg, ok := expr.(*logqlpkg.VectorAggregation)
	if !ok || agg.Op != logqlpkg.VectorSum || (agg.Grouping != nil && (agg.Grouping.Without || len(agg.Grouping.Labels) != 0)) {
		return false
	}
	ra, ok := agg.Inner.(*logqlpkg.RangeAggregation)
	if !ok {
		return false
	}
	switch ra.Op {
	case logqlpkg.RangeRate, logqlpkg.RangeCountOverTime, logqlpkg.RangeBytesRate, logqlpkg.RangeBytesOverTime:
	default:
		return false
	}
	lq, ok := ra.Inner.(*logqlpkg.LogQuery)
	if !ok {
		return false
	}
	for _, stage := range lq.Pipeline {
		if _, ok := stage.(*logqlpkg.UnwrapStage); ok {
			return false
		}
	}
	return true
}

func (p *Proxy) proxyManualRangeMetricInstant(w http.ResponseWriter, r *http.Request, spec statsCompatSpec, origSpec originalRangeMetricSpec, manualFunc string) bool {
	evalTS, err := parseTimestamp(r.FormValue("time"))
	if err != nil {
		evalTS = time.Now()
	}
	field, quantile, fieldErr := p.resolveManualMetricField(spec, origSpec, manualFunc)
	if fieldErr != nil {
		p.writeError(w, http.StatusBadRequest, fieldErr.Error())
		return true
	}
	if field == "" {
		p.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func)))
		return true
	}

	fetchEnd := evalTS
	if manualFunc == "quantile" || isLogRangeWindowFunc(manualFunc) {
		fetchEnd = fetchEnd.Add(time.Nanosecond)
	}
	series, err := p.collectRangeMetricSamples(r.Context(), spec.BaseQuery, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, field, origSpec.UnwrapConv, evalTS.Add(-origSpec.Window), fetchEnd)
	if err != nil {
		p.writeError(w, badRequestStatusOr(err, statusForRangeMetricCollectError(err)), err.Error())
		return true
	}

	if capErr := p.seriesCapError(len(series), "manual_instant_metric"); capErr != nil {
		if !p.serveSeriesCapPartial(w, r, capErr) {
			return true
		}
		series = capSeriesByTotalCount(series, p.resolvedMaxStatsQuerySeries())
	}
	// collectRangeMetricSamples returns RAW log entries.
	result, err := buildManualRangeMetricVectorContext(r.Context(), manualFunc, quantile, series, evalTS, origSpec.Window, p.resolvedMaxStatsQuerySeries())
	if err != nil {
		p.writeError(w, http.StatusServiceUnavailable, err.Error())
		return true
	}
	if spec.OuterAggAcrossSeries != "" {
		result = reduceLokiSeriesAcrossSeries(result, spec.OuterAggAcrossSeries, spec.OuterAggBy, spec.OuterAggWithout)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(result) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter -- Content-Type set above; proxy returns pre-built JSON
	return true
}

// collectStatsFastPathHits handles count_over_time / rate / bytes_* queries with an
// explicit groupBy — served from VL's stats_query_range endpoint. withParser selects
// queries with parser stages (kept in the stats query, so parsed by() fields group as
// in the raw evaluator) instead of queries without them. Per-stream grouping (the
// _stream sentinel of bare range metrics) is served only without parser stages and
// when streamBuckets is set.
// Returns nil, false when the fast path is not applicable or VL returns an error.
func (p *Proxy) collectStatsFastPathHits(ctx context.Context, spec statsCompatSpec, statsAggFunc string, windowStart, end time.Time, step time.Duration, streamBuckets, withParser bool) (map[string]manualSeriesSamples, bool, error) {
	if statsAggFunc == "" || queryUsesParserStages(spec.BaseQuery) != withParser {
		return nil, false, nil
	}
	for _, g := range spec.GroupBy {
		if g == "_stream" && (!streamBuckets || withParser) {
			return nil, false, nil
		}
	}
	if len(spec.GroupBy) == 0 && !spec.ByExplicit {
		return nil, false, nil
	}
	singleField := len(spec.GroupBy) == 1 && spec.GroupBy[0] != "_stream" && !spec.ByExplicit
	var (
		series map[string]manualSeriesSamples
		err    error
	)
	if singleField && end.Sub(windowStart) >= 2*time.Hour {
		// Over hours a field such as pod churns into thousands of values, and the
		// full bucket response can take seconds only to overflow: rank first.
		series, err = p.collectTopValueRangeMetricHits(ctx, spec, statsAggFunc, windowStart, end, step)
	} else {
		series, err = p.collectRangeMetricHits(ctx, spec.BaseQuery, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, statsAggFunc, windowStart, end, step)
		if errors.Is(err, errBodyTooLarge) && singleField {
			// Too many series for one bucket response: keep the busiest values.
			series, err = p.collectTopValueRangeMetricHits(ctx, spec, statsAggFunc, windowStart, end, step)
		}
	}
	if err != nil {
		if capErr := seriesCapOnly(err); capErr != nil {
			return series, true, capErr // the busiest N, for a Drilldown partial
		}
		return nil, false, nil
	}
	return series, true, nil
}

// seriesCapOnly keeps a series-cap refusal and drops every other error: the
// stats fast paths are optimisations whose other failures fall back to the raw
// scan, but a query over the cap must not be retried as a raw scan of every
// row — that scan is the OOM shape the cap exists to prevent, and it would
// end in the same refusal.
func seriesCapOnly(err error) error {
	var overCap *maxSeriesError
	if errors.As(err, &overCap) {
		return overCap
	}
	return nil
}

// maxTopValueFilterBytes bounds the in() filter of collectTopValueRangeMetricHits,
// leaving room for the rest of the query under VictoriaLogs' default
// -search.maxQueryLen of 16384 bytes.
const maxTopValueFilterBytes = 12 << 10

// collectTopValueRangeMetricHits answers a single-field grouped bucket query in
// two phases: one stats_query ranks the field values by line count over the
// whole fetch window, up to the operator's -max-stats-query-series, then the
// bucket query runs, restricted to those values when the ranking was cut. The
// in() filter keeps the busiest values that fit maxTopValueFilterBytes. Lines
// without the field stay in when they rank. The series of the kept values are
// exact.
func (p *Proxy) collectTopValueRangeMetricHits(ctx context.Context, spec statsCompatSpec, statsAggFunc string, windowStart, end time.Time, step time.Duration) (map[string]manualSeriesSamples, error) {
	field := quoteLogsQLIdent(spec.GroupBy[0])
	limit := p.resolvedMaxStatsQuerySeries()
	params := url.Values{}
	params.Set("query", spec.BaseQuery+" | stats by ("+field+") count() as _c | sort by (_c desc) | limit "+strconv.Itoa(limit+1))
	params.Set("start", windowStart.UTC().Format(time.RFC3339Nano))
	params.Set("end", end.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano))
	params.Set("time", end.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano))
	resp, err := p.vlPost(ctx, "/select/logsql/stats_query", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := readBodyLimited(resp.Body, maxUpstreamErrorBodyBytes)
		return nil, p.redactedBackendStatusError("stats_query backend", resp.StatusCode, body)
	}
	body, err := readBodyLimited(resp.Body, 4<<20)
	if err != nil {
		return nil, err
	}
	values := drilldownTopValuesFromMatrix(body, spec.GroupBy[0], limit)
	if len(values) == 0 {
		// No labelled value in the window: the unfiltered query is small.
		return p.collectRangeMetricHits(ctx, spec.BaseQuery, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, statsAggFunc, windowStart, end, step)
	}
	if len(values) < limit {
		// Every value ranked (the empty group may be one of them): no filter.
		return p.collectRangeMetricHits(ctx, spec.BaseQuery, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, statsAggFunc, windowStart, end, step)
	}
	values = values[:limit]
	filter := buildVLInFilter(spec.GroupBy[0], values)
	for len(filter) > maxTopValueFilterBytes && len(values) > 1 {
		values = values[:len(values)*maxTopValueFilterBytes/len(filter)]
		filter = buildVLInFilter(spec.GroupBy[0], values)
	}
	if drilldownTopValuesHaveEmpty(body, spec.GroupBy[0]) {
		filter = "(" + filter + " or " + field + `:"")`
	}
	return p.collectRangeMetricHits(ctx, spec.BaseQuery+" | filter "+filter, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, statsAggFunc, windowStart, end, step)
}

// collectParserStageStatsFastPathHits handles parser-stage GroupBy count queries
// (e.g. Drilldown field histograms with | json | delete __error__) by stripping
// the parser stages and retrying via stats_query_range against VL's column index.
// Safe only when all remaining filters after stripping are field-existence checks.
// Returns nil, false when inapplicable, on error, or when VL returns 0 series
// (non-indexed JSON fields still need parser stages to evaluate correctly).
func (p *Proxy) collectParserStageStatsFastPathHits(ctx context.Context, spec statsCompatSpec, statsAggFunc string, windowStart, end time.Time, step time.Duration) (map[string]manualSeriesSamples, bool, error) {
	if statsAggFunc == "" || !spec.UserParserStages || len(spec.GroupBy) == 0 {
		return nil, false, nil
	}
	if !strings.Contains(spec.BaseQuery, "| delete __error__") {
		return nil, false, nil
	}
	for _, g := range spec.GroupBy {
		if g == "_stream" {
			return nil, false, nil
		}
	}
	strippedBase := strings.TrimSpace(drilldownParserPipeRE.ReplaceAllString(spec.BaseQuery, ""))
	if strippedBase == spec.BaseQuery || !allFiltersAreExistenceChecks(strippedBase) {
		return nil, false, nil
	}
	series, err := p.collectRangeMetricHits(ctx, strippedBase, spec.GroupBy, spec.OrigGroupBy, spec.ByExplicit, statsAggFunc, windowStart, end, step)
	if err != nil {
		if capErr := seriesCapOnly(err); capErr != nil {
			return series, true, capErr
		}
		return nil, false, nil
	}
	if len(series) == 0 {
		return nil, false, nil
	}
	return series, true, nil
}

func (p *Proxy) resolveManualMetricField(spec statsCompatSpec, origSpec originalRangeMetricSpec, manualFunc string) (string, float64, error) {
	switch manualFunc {
	case "rate", "count_over_time":
		return "__count__", 0, nil
	case "bytes_over_time", "bytes_rate":
		return "__bytes__", 0, nil
	}

	if manualFunc == "quantile" {
		phi, field, ok := parseStatsQuantileSpec(spec.Field)
		if !ok {
			return "", 0, fmt.Errorf("invalid quantile query")
		}
		field = p.labelTranslator.ToVL(field)
		if strings.TrimSpace(field) == "" {
			return "", 0, fmt.Errorf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func))
		}
		return field, phi, nil
	}

	if origSpec.UnwrapField != "" {
		return p.labelTranslator.ToVL(origSpec.UnwrapField), 0, nil
	}
	field := strings.TrimSpace(spec.Field)
	if field == "" {
		return "", 0, nil
	}
	return p.labelTranslator.ToVL(field), 0, nil
}

// slidingStatsBucket returns gcd(step, window): the widest bucket for which every
// evaluation window (t-window, t], t = start+k*step, is an exact union of buckets
// anchored at start-window. There is no bucket-count budget: VictoriaLogs returns
// only non-empty buckets, so a response never holds more points than the log
// lines the raw evaluator would transfer, and collectRangeMetricHits already
// bounds the response bytes (an oversized response falls back to the raw
// evaluator). ok is false below a 1ms bucket, where float response timestamps
// cannot be snapped reliably, and when the backend cannot anchor bucket edges to
// the request (stats_query_range offset, VictoriaLogs v1.45+) and the anchor is
// not epoch-aligned; callers then use the raw-sample evaluator.
func (p *Proxy) slidingStatsBucket(start time.Time, step, window time.Duration) (time.Duration, bool) {
	bucket, rest := step, window
	for rest > 0 {
		bucket, rest = rest, bucket%rest
	}
	if bucket < time.Millisecond {
		return 0, false
	}
	if !p.supportsStatsRangeOffset() && start.Add(-window).UnixNano()%int64(bucket) != 0 {
		return 0, false
	}
	return bucket, true
}

// setSlidingStatsRangeParams requests buckets of hitStep whose edges sit at
// start+k*hitStep. With offset support each bucket is (edge, edge+hitStep],
// Loki's left-open, right-closed range boundary: VictoriaLogs buckets cover
// [T, T+step) with edges at k*step-offset, so edges are shifted by 1ns. The end
// is exclusive in VictoriaLogs and inclusive in Loki, hence end+1ns.
func (p *Proxy) setSlidingStatsRangeParams(params url.Values, start, end time.Time, hitStep time.Duration) {
	params.Set("start", start.UTC().Format(time.RFC3339Nano))
	params.Set("end", end.Add(time.Nanosecond).UTC().Format(time.RFC3339Nano))
	if hitStep%time.Second == 0 {
		params.Set("step", strconv.FormatInt(int64(hitStep/time.Second), 10)+"s")
	} else {
		params.Set("step", strconv.FormatInt(int64(hitStep), 10)+"ns")
	}
	if p.supportsStatsRangeOffset() {
		shift := ((start.UnixNano()+1)%int64(hitStep) + int64(hitStep)) % int64(hitStep)
		params.Set("offset", strconv.FormatInt(-shift, 10)+"ns")
	}
}

// snapSlidingBucketTimestamp maps a stats_query_range timestamp (float seconds)
// to the left edge of its bucket on the start+k*hitStep grid. The float form
// cannot carry the 1ns edge shift or exact nanoseconds, so the nearest edge wins.
func snapSlidingBucketTimestamp(v *fj.Value, start time.Time, hitStep time.Duration) (int64, bool) {
	sec, err := v.Float64()
	if err != nil || hitStep <= 0 {
		return 0, false
	}
	return snapSlidingBucketNanos(int64(math.Round(sec*1e9)), start, hitStep), true
}

// snapSlidingBucketNanos maps a bucket timestamp in nanoseconds, which may carry
// the 1ns edge shift, to the nearest edge of the start+k*hitStep grid.
func snapSlidingBucketNanos(ts int64, start time.Time, hitStep time.Duration) int64 {
	anchor, size := start.UnixNano(), int64(hitStep)
	offset := ts - anchor + size/2
	k := offset / size
	if offset%size < 0 {
		k--
	}
	return anchor + k*size
}

// collectRangeMetricHits calls VL's /select/logsql/stats_query_range endpoint and
// returns pre-bucketed samples (ts=bucket left edge ns on the start+k*hitStep
// grid, value=bucket_value). This avoids reading all raw log entries for
// count_over_time / rate / bytes_rate queries.
//
// statsAggFunc is the VL stats aggregation clause appended after "| stats [by (...)]",
// e.g. "count() as c" or "sum_len(_msg) as c".
//
// Only applicable when the output label set is fully determined by groupBy, i.e.
// len(groupBy) > 0 or byExplicit == true (so we don't need _stream expansion).
func (p *Proxy) collectRangeMetricHits(
	ctx context.Context,
	baseQuery string,
	groupBy, origGroupBy []string,
	byExplicit bool,
	statsAggFunc string,
	start, end time.Time,
	hitStep time.Duration,
) (map[string]manualSeriesSamples, error) {
	if hitStep <= 0 {
		hitStep = time.Minute
	}

	// Build LogsQL stats query so VL returns pre-aggregated bucket values.
	// stats_query_range understands stream labels (stored in _stream), unlike /hits.
	var statsQuery string
	if len(groupBy) > 0 && !byExplicit {
		statsQuery = baseQuery + " | stats by (" + strings.Join(groupBy, ", ") + ") " + statsAggFunc
	} else {
		statsQuery = baseQuery + " | stats " + statsAggFunc
	}

	params := url.Values{}
	params.Set("query", statsQuery)
	p.setSlidingStatsRangeParams(params, start, end, hitStep)

	// Acquire concurrency slot. The Drilldown Fields page fires ~30 of these
	// in parallel; without a cap all 30 hit VL simultaneously, causing a CPU storm.
	// Block until a slot is free or the request is cancelled.
	if sem := p.statsQueryRangeSem; sem != nil {
		select {
		case <-sem:
			defer func() { sem <- struct{}{} }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	resp, err := p.vlPost(ctx, "/select/logsql/stats_query_range", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := readBodyLimited(resp.Body, maxUpstreamErrorBodyBytes)
		return nil, p.redactedBackendStatusError("stats_query_range backend", resp.StatusCode, body)
	}

	body, err := readBodyLimited(resp.Body, maxStatsBucketResponseBytes)
	if err != nil {
		return nil, err
	}

	// Build VL→Loki label name mapping from groupBy↔origGroupBy.
	vlToLoki := make(map[string]string, len(groupBy))
	for i, vlName := range groupBy {
		if i < len(origGroupBy) {
			vlToLoki[vlName] = origGroupBy[i]
		} else {
			vlToLoki[vlName] = vlName
		}
	}

	// Parse Prometheus range vector response:
	// {"status":"success","data":{"result":[{"metric":{...},"values":[[ts,"v"],...]}]}}
	v, parseErr := fj.ParseBytes(body)
	if parseErr != nil {
		return nil, fmt.Errorf("parse stats_query_range response: %w", parseErr)
	}
	if status := string(v.GetStringBytes("status")); status != "success" {
		return nil, fmt.Errorf("stats_query_range non-success status: %s", status)
	}

	results := v.GetArray("data", "result")
	// Cap to maxStatsQuerySeries to bound response size for high-cardinality
	// by() clauses (e.g. churn-heavy pod names, *_id fields where each value
	// appears 1-2× in the window). Default 500 matches maxDrilldownSeries
	// (the cap the Drilldown-specific paths use) and aligns with Loki's
	// default max_query_series for the same purpose. The previous default
	// of 5000 returned 10× more sparse series than Drilldown can render
	// (the plugin's "Show all N" badge is literally the returned series
	// count) and made charts look like scattered single-point spikes
	// instead of meaningful top-N curves. See memory
	// [[drilldown-high-card-fields-known-limit]] for the deep investigation.
	// Keep the busiest maxSeries by total count (not the alphabetically-first
	// maxSeries VL returns) so the chart shows signal, not the noise floor.
	withPresence := strings.Contains(statsAggFunc, ", count() as __sample_count")
	var capErr error
	if !withPresence {
		// Over the cap this keeps the busiest N and reports it: Loki answers a
		// plain client with 400, a Drilldown request with the partial + Warning.
		results, capErr = p.capStatsSeriesReported(results, "range_metric_hits")
	}
	// Stream-grouped series carry the labels the raw evaluator derives from
	// _stream and level.
	streamGrouped := false
	for _, g := range groupBy {
		streamGrouped = streamGrouped || g == "_stream"
	}
	seriesMap := make(map[string]manualSeriesSamples, len(results))
	for _, res := range results {
		metricObj := res.GetObject("metric")
		var metric map[string]string
		if streamGrouped {
			metric = p.buildMetricSeriesEntry(string(metricObj.Get("_stream").GetStringBytes()), strings.TrimSpace(string(metricObj.Get("level").GetStringBytes())), groupBy, byExplicit, origGroupBy).translated
		} else {
			metric = make(map[string]string)
			metricObj.Visit(func(k []byte, mv *fj.Value) {
				key := string(k)
				if key == "__name__" {
					return
				}
				// Loki never keeps an empty label value; VictoriaLogs groups an
				// absent field as "".
				value := string(mv.GetStringBytes())
				if value == "" {
					return
				}
				lokiKey, ok := vlToLoki[key]
				if !ok {
					lokiKey = p.labelTranslator.ToLoki(key)
				}
				metric[lokiKey] = value
			})
		}
		seriesKey := canonicalLabelsKey(metric)
		if withPresence && string(res.GetStringBytes("metric", "__name__")) == "__sample_count" {
			entry := seriesMap[seriesKey]
			entry.Metric = metric
			addPresentBuckets(&entry, res.GetArray("values"), start, hitStep)
			seriesMap[seriesKey] = entry
			continue
		}

		values := res.GetArray("values")
		samples := make([]rangeMetricSample, 0, len(values))
		for _, pair := range values {
			arr := pair.GetArray()
			if len(arr) < 2 {
				continue
			}
			ts, tsOK := snapSlidingBucketTimestamp(arr[0], start, hitStep)
			if !tsOK {
				continue
			}
			valStr := string(arr[1].GetStringBytes())
			val, valErr := strconv.ParseFloat(valStr, 64)
			if valErr != nil {
				continue
			}
			samples = append(samples, rangeMetricSample{ts: ts, value: val})
		}

		if existing, ok := seriesMap[seriesKey]; ok {
			existing.Samples = append(existing.Samples, samples...)
			sort.Slice(existing.Samples, func(i, j int) bool { return existing.Samples[i].ts < existing.Samples[j].ts })
			seriesMap[seriesKey] = existing
		} else {
			seriesMap[seriesKey] = manualSeriesSamples{Metric: metric, Samples: samples}
		}
	}
	if withPresence {
		// Cap complete logical series, retaining both byte values and presence.
		if capErr = p.seriesCapError(len(seriesMap), "range_metric_hits"); capErr != nil {
			seriesMap = capSeriesByTotalCount(seriesMap, p.resolvedMaxStatsQuerySeries())
		}
	}
	return seriesMap, capErr
}

func addPresentBuckets(entry *manualSeriesSamples, values []*fj.Value, start time.Time, hitStep time.Duration) {
	if entry.PresentBuckets == nil {
		entry.PresentBuckets = make([]int64, 0, len(values))
	}
	for _, pair := range values {
		arr := pair.GetArray()
		if len(arr) < 2 {
			continue
		}
		ts, tsOK := snapSlidingBucketTimestamp(arr[0], start, hitStep)
		count, countErr := strconv.ParseFloat(string(arr[1].GetStringBytes()), 64)
		if tsOK && countErr == nil && count > 0 {
			entry.PresentBuckets = append(entry.PresentBuckets, ts)
		}
	}
	// VictoriaLogs returns ascending buckets; merged streams can interleave.
	present := entry.PresentBuckets
	if !sort.SliceIsSorted(present, func(i, j int) bool { return present[i] < present[j] }) {
		sort.Slice(present, func(i, j int) bool { return present[i] < present[j] })
	}
}

// metricSeriesCacheEntry holds the pre-computed labels and key for a metric series.
// Cached per (_stream, level) composite within a single collectRangeMetricSamples
// call: entries sharing the same stream identity produce identical series, so the
// expensive label-copy + translation + key-build runs once per distinct stream.
type metricSeriesCacheEntry struct {
	metricLabels map[string]string // pre-translation, needed for parsed-label slow path
	translated   map[string]string // after labelTranslator
	key          string
}

// statusForRangeMetricCollectError maps a collection failure to a status. Hitting
// the row cap is the CLIENT's query being too broad for this path, not a backend
// fault, so it must not read as 502 — an operator chasing a 502 looks at the
// backend, which is healthy.
func statusForRangeMetricCollectError(err error) int {
	var truncated *rawRowScanTruncatedError
	if errors.As(err, &truncated) {
		return http.StatusBadRequest
	}
	// The memory guards are the same kind of answer: the CLIENT's query is too
	// broad for this path, not a backend fault, so they must not read as 502
	// either — an operator chasing a 502 looks at the backend, which is healthy.
	var overBudget *manualScanBudgetError
	if errors.As(err, &overBudget) {
		return http.StatusBadRequest
	}
	var tooManySeries *manualScanSeriesError
	if errors.As(err, &tooManySeries) {
		return http.StatusBadRequest
	}
	var overCap *maxSeriesError
	if errors.As(err, &overCap) {
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

// defaultManualRangeMetricRowLimit caps the raw-row scan of the manual
// compatibility path. It is a PROXY-SIDE count now (see collectRangeMetricSamples):
// the scan stops when it is exceeded, and no `limit` — and therefore no sort — is
// asked of VictoriaLogs. 10,000 was the ceiling while the cap had to be a VL
// `limit`, and it refused dashboard panels Loki answers; the number that was
// dangerous as a sorted limit is safe as a streamed count — but it is NOT what
// bounds memory. The fold retains a sample per row until the scan finishes, so
// the real bound is the shared budget in manual_scan_budget.go, which every
// concurrent scan draws from.
const defaultManualRangeMetricRowLimit = 1_000_000

// rawRowScanTruncatedError reports that the manual path hit its row cap, so any
// number it could return would be short by an unknown amount.
type rawRowScanTruncatedError struct{ limit int }

func (e *rawRowScanTruncatedError) Error() string {
	return fmt.Sprintf(
		"manual range metric row limit exceeded (%d): the query needs more raw log rows than this instance scans and the result would be silently incomplete. "+
			"Narrow the time range or the stream selector, group by a label the backend can see so the "+
			"aggregation runs there, or raise -manual-range-metric-row-limit if this instance can afford the scan",
		e.limit)
}

func (p *Proxy) collectRangeMetricSamples(ctx context.Context, baseQuery string, groupBy, origGroupBy []string, byExplicit bool, field, unwrapConv string, start, end time.Time) (map[string]manualSeriesSamples, error) {
	params := url.Values{}
	params.Set("start", formatVLTimestamp(start.UTC().Format(time.RFC3339Nano)))
	params.Set("end", formatVLTimestamp(end.UTC().Format(time.RFC3339Nano)))
	// This path reads RAW ROWS and folds them client-side. The cap is a LIMIT
	// PIPE, not a `limit` query argument: VictoriaLogs executes the argument by
	// sorting the whole match (`| sort by (_time) desc limit N`), which at
	// N=1,000,000 over a busy namespace OOM-killed both 4Gi VLSingle instances
	// five times on 10.09.2026, while the pipe streams an arbitrary subset. One
	// extra row tells a complete response at the cap from a truncated one;
	// truncation is reported rather than folded into a plausible number.
	rowLimit, err := p.manualMetricRowBudget()
	if err != nil {
		return nil, err
	}
	params.Set("query", baseQuery+" | limit "+strconv.Itoa(rowLimit+1))

	resp, err := p.vlPost(ctx, "/select/logsql/query", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := readBodyLimited(resp.Body, maxUpstreamErrorBodyBytes)
		return nil, p.redactedBackendStatusError("backend returned", resp.StatusCode, body)
	}

	// The fold RETAINS one sample per accepted row until the whole scan is done,
	// so the row cap alone bounds nothing across concurrent requests. Draw the
	// retained samples from a shared budget and refuse — loudly — when it is gone.
	reservation := p.newManualScanReservation()
	defer reservation.release()
	seriesLimit := p.resolvedMaxStatsQuerySeries()

	// seriesCache caches per (_stream + "|" + level) within this request.
	// Avoids repeated label-map allocation for the dominant case where thousands
	// of log lines share the same stream identity (same series).
	seriesCache := make(map[string]*metricSeriesCacheEntry, 32)
	seriesMap := make(map[string]manualSeriesSamples)
	includeParsedLabels := queryUsesParserStages(baseQuery)

	fjp := vlFJParserPool.Get()
	defer vlFJParserPool.Put(fjp)

	// Stream the response line by line — avoids io.ReadAll + bytes.Split which
	// would buffer the entire configured row budget plus overflow probe in memory.
	limited := &io.LimitedReader{R: resp.Body, N: maxBufferedBackendBodyBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

	rows := 0
	dedup := p.newRowDedup()
	for scanner.Scan() {
		if err := checkManualMetricRead(ctx, limited); err != nil {
			return nil, err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		rows++
		if rows > rowLimit {
			// Stop reading immediately: the body is closed by the deferred call, so
			// VictoriaLogs stops producing rather than streaming the whole match.
			p.log.Warn("manual range-metric scan refused", "reason", "row cap", "limit", rowLimit)
			return nil, &rawRowScanTruncatedError{limit: rowLimit}
		}

		v, parseErr := fjp.ParseBytes(line)
		if parseErr != nil {
			continue
		}

		rawTS := string(v.GetStringBytes("_time"))
		if rawTS == "" {
			continue
		}
		normTS, ok := formatEntryTimestamp(rawTS)
		if !ok {
			continue
		}
		ts, err := strconv.ParseInt(normTS, 10, 64)
		if err != nil {
			continue
		}
		if ts < 1e12 {
			ts *= int64(time.Second)
		}
		if p.rowOverMaxLineSizeFJ(v) || dedup.dupFJ(v) {
			continue
		}

		sampleValue, ok := p.extractManualSampleValueFJ(v, field, unwrapConv)
		if !ok {
			continue
		}

		streamStr := string(v.GetStringBytes("_stream"))
		levelStr := strings.TrimSpace(string(v.GetStringBytes("level")))

		var seriesEntry *metricSeriesCacheEntry

		if !includeParsedLabels || len(groupBy) == 0 {
			// Hot path: series identity depends only on _stream + level.
			// Build once per unique (stream, level) pair and reuse across all matching lines.
			cacheKey := streamStr + "|" + levelStr
			bare := !byExplicit && len(origGroupBy) == 0
			if bare {
				cacheKey += p.promotionCacheKey(v)
			}
			seriesEntry = seriesCache[cacheKey]
			if seriesEntry == nil {
				seriesEntry = p.buildMetricSeriesEntry(streamStr, levelStr, groupBy, byExplicit, origGroupBy)
				if bare {
					// A bare range aggregation is keyed the way Loki keys it: the
					// collector's labels, no derived level (round 13, class G).
					p.completeStreamIdentity(seriesEntry.translated, fjFieldGetter(nil, v), nil)
					seriesEntry.key = canonicalLabelsKey(seriesEntry.translated)
				}
				seriesCache[cacheKey] = seriesEntry
			}
		} else {
			// Slow path: by(...) includes parsed fields extracted per entry.
			// Extend the cache key with the extracted field values so entries with
			// the same parsed-field values still hit the cache.
			cacheKey := p.buildParsedGroupByCacheKey(streamStr, levelStr, v, groupBy)
			seriesEntry = seriesCache[cacheKey]
			if seriesEntry == nil {
				base := p.buildMetricSeriesEntry(streamStr, levelStr, groupBy, byExplicit, origGroupBy)
				// Copy base metric labels and inject per-entry parsed fields.
				metricLabels := make(map[string]string, len(base.metricLabels))
				for k, val := range base.metricLabels {
					metricLabels[k] = val
				}
				// Only inject parsed labels that appear in the explicit by(...) list.
				// Adding ALL parsed fields (old behaviour) creates one series per unique
				// JSON-object combination — O(N) series for N distinct log entries.
				// Loki groups by stream labels only when no by(...) is present; parsed
				// fields become metric dimensions only when explicitly named in by(...).
				addGroupByParsedLabelsFJ(metricLabels, v, groupBy, origGroupBy)
				translatedParsed := p.labelTranslator.TranslateLabelsMap(metricLabels)
				seriesEntry = &metricSeriesCacheEntry{
					metricLabels: metricLabels,
					translated:   translatedParsed,
					key:          canonicalLabelsKey(translatedParsed),
				}
				seriesCache[cacheKey] = seriesEntry
			}
		}

		current, seen := seriesMap[seriesEntry.key]
		if !seen {
			if len(seriesMap) >= seriesLimit {
				// Every new series adds a label map and a translated copy of it, which
				// a high-cardinality group-by multiplies past anything the samples cost.
				err := &manualScanSeriesError{limit: seriesLimit}
				p.log.Warn("manual range-metric scan refused", "reason", "series limit", "limit", seriesLimit)
				return nil, err
			}
			current.Metric = seriesEntry.translated
		}
		if !reservation.account() {
			err := &manualScanBudgetError{budget: defaultManualScanSampleBudget}
			p.log.Warn("manual range-metric scan refused",
				"reason", "shared retained-sample budget exhausted",
				"budget_samples", defaultManualScanSampleBudget, "rows_scanned", rows)
			return nil, err
		}
		current.Samples = append(current.Samples, rangeMetricSample{ts: ts, value: sampleValue})
		seriesMap[seriesEntry.key] = current
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("scanning VL response: %w", scanErr)
	}
	if err := checkManualMetricRead(ctx, limited); err != nil {
		return nil, err
	}

	for key, series := range seriesMap {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		sort.Slice(series.Samples, func(i, j int) bool { return series.Samples[i].ts < series.Samples[j].ts })
		seriesMap[key] = series
	}

	return seriesMap, nil
}

// buildMetricSeriesEntry constructs the label maps and series key for a given
// (_stream, level) pair. Called once per distinct stream identity per request.
func (p *Proxy) buildMetricSeriesEntry(streamStr, levelStr string, groupBy []string, byExplicit bool, origGroupBy []string) *metricSeriesCacheEntry {
	rawStreamLabels := parseStreamLabels(streamStr)
	streamLabels := make(map[string]string, len(rawStreamLabels))
	for k, v := range rawStreamLabels {
		streamLabels[k] = v
	}
	// A bare range aggregation (no by/without in the LogQL) is keyed by the
	// stream alone; the translator's default `by (_stream, level)` grouping is
	// its own device, and the derived level is not a Loki stream label
	// (round 13, class G).
	bare := !byExplicit && len(origGroupBy) == 0
	dropLevel := bare && p.bareIdentityDropsLevel()
	if levelStr != "" && !dropLevel {
		streamLabels["level"] = levelStr
		streamLabels["detected_level"] = levelStr
	}
	if strings.TrimSpace(streamLabels["detected_level"]) == "" && !dropLevel {
		streamLabels["detected_level"] = "unknown"
	}
	ensureSyntheticServiceName(streamLabels)

	var metricLabels map[string]string
	if bare {
		metricLabels = buildManualMetricLabels(streamLabels, nil, false)
	} else {
		metricLabels = buildManualMetricLabels(streamLabels, groupBy, byExplicit)
	}

	// Rename VL-translated groupBy keys back to their original Loki names.
	// Example: VL "level" was produced by translating Loki "detected_level";
	// the response metric must carry "detected_level" to match what Drilldown
	// requested in "sum(...) by (detected_level)".
	if len(origGroupBy) == len(groupBy) {
		for i, vlKey := range groupBy {
			if lokiKey := origGroupBy[i]; lokiKey != vlKey {
				if val, ok := metricLabels[vlKey]; ok {
					delete(metricLabels, vlKey)
					metricLabels[lokiKey] = val
				} else if val, ok := streamLabels[lokiKey]; ok {
					// VL form not found in metric (e.g. "service.name" absent for
					// Loki-push data); fall back to the underscore stream label name.
					metricLabels[lokiKey] = val
				}
			}
		}
	}

	translated := p.labelTranslator.TranslateLabelsMap(metricLabels)
	return &metricSeriesCacheEntry{
		metricLabels: metricLabels,
		translated:   translated,
		key:          canonicalLabelsKey(translated),
	}
}

// buildParsedGroupByCacheKey builds a cache key for the slow path (parsed labels).
// It extends the (_stream, level) base with the values of each groupBy field found
// in the log entry, so entries with identical parsed-field values still reuse the
// pre-built label map.
func (p *Proxy) buildParsedGroupByCacheKey(streamStr, levelStr string, v *fj.Value, groupBy []string) string {
	var b strings.Builder
	b.Grow(len(streamStr) + 2 + len(levelStr) + len(groupBy)*32)
	b.WriteString(streamStr)
	b.WriteByte('|')
	b.WriteString(levelStr)
	for _, key := range groupBy {
		if isVLInternalField(key) || key == "_stream_id" || key == "_stream" {
			continue
		}
		fv := parsedGroupByFieldFJ(v, key)
		if fv == nil {
			continue
		}
		val, ok := stringifyFJValue(fv)
		if !ok {
			continue
		}
		b.WriteByte('|')
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(val)
	}
	return b.String()
}

// extractManualSampleValueFJ is the fastjson variant of extractManualSampleValue.
// Zero heap allocation for the __count__ and __bytes__ hot paths.
func (p *Proxy) extractManualSampleValueFJ(v *fj.Value, field, unwrapConv string) (float64, bool) {
	switch field {
	case "__count__":
		return 1, true
	case "__bytes__":
		return p.rowLineBytesFJ(v), true
	}

	raw := p.lookupFJField(v, p.manualValueCandidateFields(field))
	if raw == nil {
		return 0, false
	}

	if unwrapConv == "" {
		return parseFloatValueFJ(raw)
	}
	s, ok := stringifyFJValue(raw)
	if !ok {
		return 0, false
	}
	return convertUnwrapValue(s, unwrapConv)
}

// lookupFJField returns the first non-nil field from v matching any key in keys.
func (p *Proxy) lookupFJField(v *fj.Value, keys []string) *fj.Value {
	for _, key := range keys {
		if fv := v.Get(key); fv != nil {
			return fv
		}
	}
	return nil
}

// parseFloatValueFJ extracts a float64 from a fastjson value without interface{} boxing.
func parseFloatValueFJ(v *fj.Value) (float64, bool) {
	switch v.Type() {
	case fj.TypeNumber:
		f, err := v.Float64()
		return f, err == nil
	case fj.TypeString:
		f, err := strconv.ParseFloat(strings.TrimSpace(string(v.GetStringBytes())), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// addGroupByParsedLabelsFJ injects the by(...) fields that only exist after a
// parser stage (| json, | extract) into the series labels.
//
// groupBy holds VL field names; origGroupBy holds the Loki label names the
// client actually asked for, positionally aligned. The value must be stored
// under the Loki name: buildMetricSeriesEntry has already renamed the VL key
// (e.g. VL "level" -> Loki "detected_level"), so writing the VL name here
// re-adds the pre-rename label and the response carries BOTH — one more
// grouping dimension than Loki returns, which renames every Grafana series.
func addGroupByParsedLabelsFJ(metricLabels map[string]string, v *fj.Value, groupBy, origGroupBy []string) {
	aligned := len(origGroupBy) == len(groupBy)
	for i, key := range groupBy {
		if isVLInternalField(key) || key == "_stream_id" {
			continue
		}
		outKey := key
		if aligned && strings.TrimSpace(origGroupBy[i]) != "" {
			outKey = origGroupBy[i]
		}
		if _, exists := metricLabels[outKey]; exists {
			continue
		}
		fv := parsedGroupByFieldFJ(v, key)
		if fv == nil {
			continue
		}
		value, ok := stringifyFJValue(fv)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" {
			metricLabels[outKey] = value
		}
	}
}

// parsedGroupByFieldFJ reads a by() field off a VL row. A nested JSON key is
// `a_b` to Loki's `| json` and `a.b` to unpack_json, so an underscore name the
// row lacks is retried under its dotted spelling (round 12, the manual path's
// half of `sum by (ExceptionDetails_Topic)`).
func parsedGroupByFieldFJ(v *fj.Value, key string) *fj.Value {
	if fv := v.Get(key); fv != nil {
		return fv
	}
	if dottedAliasRE.MatchString(key) {
		return v.Get(strings.ReplaceAll(key, "_", "."))
	}
	return nil
}

// logqlUsesParserStage reports whether the CLIENT's LogQL carries a parser
// stage. Quoted spans are blanked first, so a line filter such as
// `|= "| json "` is read as data rather than as a pipeline stage.
//
// This is the structural counterpart to queryUsesParserStages: it looks at what
// the client wrote, so nothing the translator injects can be mistaken for it.
func logqlUsesParserStage(logql string) bool {
	return logqlParserStageRE.MatchString(stripQuotedSpans(logql))
}

var logqlParserStageRE = regexp.MustCompile(`\|\s*(json|logfmt|pattern|regexp|unpack)\b`)

// queryUsesParserStages reports whether a TRANSLATED query contains parser
// pipes. It answers a question about the response's SHAPE (which fields exist),
// not about Loki's error-exclusion semantics — for that use
// statsCompatSpec.UserParserStages, which is derived from the client's query.
func queryUsesParserStages(baseQuery string) bool {

	// `| unpack_logfmt` exposes pre-parsed fields without transforming the
	// log line — VL's stats_query_range handles it natively in tens of ms.
	// Excluding it from the "parser stages" check lets queries with a
	// `detected_level="..."` filter (which the translator rewrites to
	// `... | unpack_logfmt | filter level:="..."`) reach the stats fast
	// path instead of falling back to a 5–16s client-side log scan that
	// returned 143k unaggregated series for high-cardinality groupBy.
	if strings.Contains(baseQuery, "| unpack_json") {
		return true
	}
	if strings.Contains(baseQuery, "| extract ") {
		return true
	}
	if strings.Contains(baseQuery, "| extract_regexp ") {
		return true
	}
	return false
}

// addGroupByParsedLabels injects only the labels named in groupBy from the
// parsed log entry. This matches Loki's behaviour: without an explicit by(...)
// clause, rate/count_over_time groups by stream labels only; parsed-field values
// only become metric dimensions when the caller explicitly names them in by(...).
func addGroupByParsedLabels(metricLabels map[string]string, entry map[string]interface{}, groupBy []string) {
	for _, key := range groupBy {
		if isVLInternalField(key) || key == "_stream_id" {
			continue
		}
		if _, exists := metricLabels[key]; exists {
			continue
		}
		if raw, ok := entry[key]; ok {
			if value, ok := stringifyEntryValue(raw); ok {
				value = strings.TrimSpace(value)
				if value != "" {
					metricLabels[key] = value
				}
			}
		}
	}
}

func addParsedEntryLabels(metricLabels map[string]string, entry map[string]interface{}, unwrapField string) {
	if metricLabels == nil {
		return
	}
	excluded := map[string]struct{}{}
	addExcludedField(excluded, unwrapField)
	addExcludedField(excluded, strings.ReplaceAll(unwrapField, ".", "_"))
	addExcludedField(excluded, strings.ReplaceAll(unwrapField, "_", "."))

	for key, raw := range entry {
		if isVLInternalField(key) || key == "_stream_id" {
			continue
		}
		if _, skip := excluded[key]; skip {
			continue
		}
		value, ok := stringifyEntryValue(raw)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := metricLabels[key]; exists {
			continue
		}
		metricLabels[key] = value
	}
}

func addExcludedField(excluded map[string]struct{}, key string) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	excluded[key] = struct{}{}
}

type manualSeriesSamples struct {
	Metric  map[string]string
	Samples []rangeMetricSample
	// PresentBuckets distinguishes real zero-byte lines from absent buckets: the
	// ascending left edges of buckets holding lines. Non-nil (possibly empty) only
	// for byte sums; raw log samples retain their compact shape.
	PresentBuckets []int64
}

func buildManualMetricLabels(streamLabels map[string]string, groupBy []string, byExplicit bool) map[string]string {
	if byExplicit && len(groupBy) == 0 {
		// Explicit "by ()" — one series total, no label dimensions.
		return map[string]string{}
	}
	if len(groupBy) == 0 {
		labels := make(map[string]string, len(streamLabels))
		for k, v := range streamLabels {
			labels[k] = v
		}
		return labels
	}

	// "_stream" is a sentinel added by addStatsByStreamClause meaning "group by the
	// full stream identity". The streamLabels map already holds the expanded key/value
	// pairs from _stream, so looking up "_stream" directly always misses. Expand it
	// into all stream labels so that applyWithoutGrouping can remove specific keys
	// rather than collapsing every series into one {} bucket.
	streamExpand := false
	for _, key := range groupBy {
		if key == "_stream" {
			streamExpand = true
			break
		}
	}

	labels := make(map[string]string, len(streamLabels))
	if streamExpand {
		for k, v := range streamLabels {
			labels[k] = v
		}
	}
	for _, key := range groupBy {
		if key == "_stream" {
			continue
		}
		if value, ok := streamLabels[key]; ok {
			labels[key] = value
		}
	}
	return labels
}

func (p *Proxy) manualValueCandidateFields(field string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	add(field)
	add(p.labelTranslator.ToVL(field))
	add(strings.ReplaceAll(field, "_", "."))
	return out
}

func parseFloatValue(raw interface{}) (float64, bool) {
	switch value := raw.(type) {
	case float64:
		return value, true
	case json.Number:
		f, err := value.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return f, err == nil
	default:
		f, err := strconv.ParseFloat(strings.TrimSpace(asString(raw)), 64)
		return f, err == nil
	}
}

// resolvedMaxStatsQuerySeries returns the per-request series cap for metric
// stats queries: the configured -max-stats-query-series, or the built-in
// default of 500 (matches maxDrilldownSeries and Loki's stock max_query_series).
func (p *Proxy) resolvedMaxStatsQuerySeries() int {
	if p != nil && p.maxStatsQuerySeries > 0 {
		return p.maxStatsQuerySeries
	}
	return 500
}

// maxSeriesError is Loki's own answer to a query producing more series than
// `max_query_series` allows — the message is Loki's verbatim, and it travels
// as a 400. A capped result was served as a complete one until round 11: a
// whole-cluster `count_over_time` answering 500 of its 5091 series, HTTP 200,
// empty `warnings`, nothing in the log — indistinguishable from a cluster that
// has 500 series.
type maxSeriesError struct{ limit, matched int }

func (e *maxSeriesError) Error() string {
	return fmt.Sprintf("maximum of series (%d) reached for a single query", e.limit)
}

// seriesCapError refuses a result of `matched` series when it exceeds the cap
// (`-max-stats-query-series`, default 500 = Loki's stock max_query_series),
// logging the surface that hit it. nil when the result fits.
func (p *Proxy) seriesCapError(matched int, surface string) error {
	maxSeries := p.resolvedMaxStatsQuerySeries()
	if matched <= maxSeries {
		return nil
	}
	if p != nil && p.log != nil {
		p.log.Warn("stats series cap exceeded",
			"surface", surface,
			"matched", matched,
			"limit", maxSeries,
			"flag", "-max-stats-query-series")
	}
	return &maxSeriesError{limit: maxSeries, matched: matched}
}

// capStatsSeriesReported reports a stats result over the series cap. It
// returns the busiest N series TOGETHER with the error: a Drilldown request is
// served that partial result (with a Warning header), a dashboard panel gets
// Loki's 400 — reading the trimmed result as the whole population is the
// silent truncation of round 11.
func (p *Proxy) capStatsSeriesReported(results []*fj.Value, surface string) ([]*fj.Value, error) {
	if err := p.seriesCapError(len(results), surface); err != nil {
		return capStatsResultsByTotalCount(results, p.resolvedMaxStatsQuerySeries()), err
	}
	return results, nil
}

// serveSeriesCapPartial decides what a series-cap error means for THIS request:
// a Drilldown request keeps the busiest N (already trimmed by the caller) and
// gets Loki's partial-results Warning; it returns true so the caller carries on.
// Any other request is answered with the 400 and false.
func (p *Proxy) serveSeriesCapPartial(w http.ResponseWriter, r *http.Request, capErr error) bool {
	if isGrafanaDrilldownRequest(r) {
		w.Header().Set("Warning", `199 - "`+capErr.Error()+`; returning partial results"`)
		return true
	}
	p.writeError(w, http.StatusBadRequest, capErr.Error())
	return false
}

// capStatsResultsByTotalCount keeps only the maxSeries VL stats results with the
// highest summed bucket value, dropping the long tail. VL's stats_query_range
// returns results in LABEL (alphabetical) order, so a plain results[:maxSeries]
// slice keeps the alphabetically-first series — which for high-cardinality
// fields (churn-heavy pod names, *_id) is the NOISE FLOOR: ~344/500 pods with
// count==1 and only a handful with a meaningful count. Ranking by total count
// instead keeps the BUSIEST series, so the Drilldown chart shows the real
// signal (continuous lines for the top contributors) rather than scattered
// single-point spikes. For count_over_time the per-bucket values are counts and
// for bytes_* they are byte sums, so total value is the genuine busy-ness
// metric; rate ranks identically (rate = count/window is monotonic in count).
// Returns the input unchanged when it already fits or maxSeries<=0. Ties on
// total break on the metric JSON (ascending) for determinism.
// See memory [[drilldown-high-card-fields-known-limit]].
func capStatsResultsByTotalCount(results []*fj.Value, maxSeries int) []*fj.Value {
	if maxSeries <= 0 || len(results) <= maxSeries {
		return results
	}
	type scored struct {
		idx   int
		total float64
		key   string
	}
	ranked := make([]scored, len(results))
	for i, res := range results {
		var total float64
		for _, pair := range res.GetArray("values") {
			arr := pair.GetArray()
			if len(arr) < 2 {
				continue
			}
			if val, err := strconv.ParseFloat(string(arr[1].GetStringBytes()), 64); err == nil {
				total += val
			}
		}
		ranked[i] = scored{idx: i, total: total, key: res.Get("metric").String()}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].total != ranked[j].total {
			return ranked[i].total > ranked[j].total
		}
		return ranked[i].key < ranked[j].key
	})
	out := make([]*fj.Value, maxSeries)
	for i := 0; i < maxSeries; i++ {
		out[i] = results[ranked[i].idx]
	}
	return out
}

// capSeriesByTotalCount is the map-based analogue of capStatsResultsByTotalCount
// for paths that have already assembled a manualSeriesSamples map (e.g. the raw
// log-scan path via collectRangeMetricSamples → buildManualRangeMetricMatrix).
// Keeps the maxSeries series with the highest total sample value. Returns the
// input unchanged when it already fits or maxSeries<=0.
func capSeriesByTotalCount(series map[string]manualSeriesSamples, maxSeries int) map[string]manualSeriesSamples {
	if maxSeries <= 0 || len(series) <= maxSeries {
		return series
	}
	type scored struct {
		key   string
		total float64
	}
	ranked := make([]scored, 0, len(series))
	for key, s := range series {
		var total float64
		for _, smp := range s.Samples {
			total += smp.value
		}
		ranked = append(ranked, scored{key: key, total: total})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].total != ranked[j].total {
			return ranked[i].total > ranked[j].total
		}
		return ranked[i].key < ranked[j].key
	})
	capped := make(map[string]manualSeriesSamples, maxSeries)
	for i := 0; i < maxSeries; i++ {
		capped[ranked[i].key] = series[ranked[i].key]
	}
	return capped
}

func buildManualRangeMetricMatrix(functionName string, quantile float64, series map[string]manualSeriesSamples, start, end time.Time, step, window time.Duration, maxSeries int) []byte {
	// Legacy callers explicitly requested busiest-series truncation. Production
	// uses the error-returning Context entrypoint and must never silently truncate.
	series = capSeriesByTotalCount(series, maxSeries)
	result, _ := buildManualRangeMetricMatrixContext(context.Background(), functionName, quantile, series, start, end, step, window, maxSeries)
	return result
}

func buildManualRangeMetricMatrixContext(ctx context.Context, functionName string, quantile float64, series map[string]manualSeriesSamples, start, end time.Time, step, window time.Duration, maxSeries int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxSeries > 0 && len(series) > maxSeries {
		return nil, fmt.Errorf("manual metric series limit exceeded (%d); narrow the query", maxSeries)
	}
	ctx = binaryEvaluationContext(ctx)
	if end.Before(start) {
		return encodeBinarySeriesContext(ctx, nil, "matrix", maxBufferedBackendBodyBytes)
	}
	if step <= 0 || end.Sub(start)/step >= 1000000 {
		return nil, fmt.Errorf("invalid or excessive manual metric evaluation points")
	}

	perSeries := make(map[string]*binaryMatchedSeries)
	keys := make([]string, 0, len(series))
	sorted := make(map[string]bool, len(series))
	for key, entry := range series {
		keys = append(keys, key)
		samples := entry.Samples
		sorted[key] = sort.SliceIsSorted(samples, func(i, j int) bool { return samples[i].ts < samples[j].ts })
	}
	sort.Strings(keys)

	for t := start; !t.After(end); t = t.Add(step) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		windowStart := t.Add(-window).UnixNano()
		windowEnd := t.UnixNano()
		for _, key := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			seriesEntry := series[key]
			samples := seriesEntry.Samples
			if sorted[key] {
				// Narrow time-ordered samples to [windowStart, windowEnd]; the
				// aggregator applies the exact window bounds to that slice.
				lo := sort.Search(len(samples), func(i int) bool { return samples[i].ts >= windowStart })
				hi := lo + sort.Search(len(samples)-lo, func(i int) bool { return samples[lo+i].ts > windowEnd })
				samples = samples[lo:hi]
			}
			value, ok := aggregateManualWindow(functionName, quantile, samples, windowStart, windowEnd, window.Seconds())
			if !ok {
				continue
			}
			if err := checkBinaryOutputSample(ctx); err != nil {
				return nil, err
			}

			dst := perSeries[key]
			if dst == nil {
				if err := checkBinaryOutputLabels(ctx, seriesEntry.Metric); err != nil {
					return nil, err
				}
				dst = &binaryMatchedSeries{labels: seriesEntry.Metric}
				perSeries[key] = dst
			}

			dst.points = append(dst.points, []any{float64(t.Unix()), strconv.FormatFloat(value, 'f', -1, 64)})
		}
	}

	return encodeBinarySeriesContext(ctx, perSeries, "matrix", maxBufferedBackendBodyBytes)
}

// buildHitsRangeMetricMatrix builds a Prometheus matrix response from pre-bucketed
// counts returned by collectRangeMetricHits. Buckets are labelled by their left
// edge on a grid that contains every window edge, so the window (T-window, T] of
// step point T is the sum of all buckets whose label falls in [T-window, T).
// Supports count_over_time/bytes_over_time (sum) and rate/bytes_rate (sum/window_s).
//
// Like Loki, a step whose window holds no log line is absent rather than zero.
// Series with PresentBuckets (byte sums) use them to keep windows that contain
// only empty lines. Per-series prefix sums keep each step O(log buckets), so
// finer buckets do not multiply the work by the window length.
//
// The encoded response is bounded by maxBufferedBackendBodyBytes, like the raw
// evaluator's output; an estimate above it returns an error instead.
func buildHitsRangeMetricMatrix(manualFunc string, series map[string]manualSeriesSamples, start, end time.Time, step, window time.Duration) ([]byte, error) {
	if end.Before(start) || step <= 0 {
		return marshalManualMetricResponse("matrix", []map[string]interface{}{}), nil
	}
	encodedBytes := 0
	windowNS := window.Nanoseconds()
	windowSec := window.Seconds()

	keys := make([]string, 0, len(series))
	for key := range series {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	expectedBuckets := int(end.Sub(start)/step) + 1
	if expectedBuckets > 32768 { // pre-size cap; appends grow beyond it
		expectedBuckets = 32768
	}

	results := make([]map[string]interface{}, 0, len(keys))
	for _, key := range keys {
		seriesEntry := series[key]
		samples := seriesEntry.Samples
		if !sort.SliceIsSorted(samples, func(i, j int) bool { return samples[i].ts < samples[j].ts }) {
			// Coalesced results are shared between requests: sort a copy.
			samples = append([]rangeMetricSample(nil), samples...)
			sort.Slice(samples, func(i, j int) bool { return samples[i].ts < samples[j].ts })
		}
		prefix := make([]float64, len(samples)+1)
		for i, sample := range samples {
			prefix[i+1] = prefix[i] + sample.value
		}
		present := seriesEntry.PresentBuckets // ascending; nil without presence data

		for k, v := range seriesEntry.Metric {
			encodedBytes += len(k) + len(v) + 6
		}
		var points [][]interface{}
		for t := start; !t.After(end); t = t.Add(step) {
			tNS := t.UnixNano()
			windowStartNS := tNS - windowNS
			lo := sort.Search(len(samples), func(i int) bool { return samples[i].ts >= windowStartNS })
			hi := sort.Search(len(samples), func(i int) bool { return samples[i].ts >= tNS })
			sum := prefix[hi] - prefix[lo]
			hasLines := sum != 0
			if present != nil {
				pLo := sort.Search(len(present), func(i int) bool { return present[i] >= windowStartNS })
				hasLines = pLo < len(present) && present[pLo] < tNS
			}
			if !hasLines {
				continue
			}
			value := sum
			if manualFunc == "rate" || manualFunc == "bytes_rate" {
				value = sum / windowSec
			}
			if points == nil {
				points = make([][]interface{}, 0, expectedBuckets)
			}
			formatted := strconv.FormatFloat(value, 'f', -1, 64)
			// `[1700000000,"<value>"],`: a timestamp of at most 20 bytes plus punctuation.
			if encodedBytes += len(formatted) + 26; encodedBytes > maxBufferedBackendBodyBytes {
				return nil, fmt.Errorf("manual metric response exceeds %d bytes", maxBufferedBackendBodyBytes)
			}
			points = append(points, []interface{}{float64(t.Unix()), formatted})
		}
		if points != nil {
			results = append(results, map[string]interface{}{
				"metric": seriesEntry.Metric,
				"values": points,
			})
		}
	}
	return marshalManualMetricResponse("matrix", results), nil
}

func buildManualRangeMetricVector(functionName string, quantile float64, series map[string]manualSeriesSamples, evalTime time.Time, window time.Duration) []byte {
	result, _ := buildManualRangeMetricVectorContext(context.Background(), functionName, quantile, series, evalTime, window)
	return result
}

func buildManualRangeMetricVectorContext(ctx context.Context, functionName string, quantile float64, series map[string]manualSeriesSamples, evalTime time.Time, window time.Duration, maxSeries ...int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(maxSeries) > 0 && maxSeries[0] > 0 && len(series) > maxSeries[0] {
		return nil, fmt.Errorf("manual metric series limit exceeded (%d); narrow the query", maxSeries[0])
	}
	ctx = binaryEvaluationContext(ctx)
	keys := make([]string, 0, len(series))
	for key := range series {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	windowStart := evalTime.Add(-window).UnixNano()
	windowEnd := evalTime.UnixNano()
	results := make(map[string]*binaryMatchedSeries)

	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		seriesEntry := series[key]
		value, ok := aggregateManualWindow(functionName, quantile, seriesEntry.Samples, windowStart, windowEnd, window.Seconds())
		if !ok {
			continue
		}
		if err := checkBinaryOutputSample(ctx); err != nil {
			return nil, err
		}
		if err := checkBinaryOutputLabels(ctx, seriesEntry.Metric); err != nil {
			return nil, err
		}
		results[key] = &binaryMatchedSeries{labels: seriesEntry.Metric, points: [][]any{{float64(evalTime.Unix()), strconv.FormatFloat(value, 'f', -1, 64)}}}
	}

	return encodeBinarySeriesContext(ctx, results, "vector", maxBufferedBackendBodyBytes)
}

func marshalManualMetricResponse(resultType string, result []map[string]interface{}) []byte {
	if result == nil {
		result = []map[string]interface{}{}
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"status": "success",
		"data": map[string]interface{}{
			"resultType": resultType,
			"result":     result,
		},
	})
	return payload
}

// manualWindowValues collects the samples inside the LogQL range vector
// (windowStart, windowEnd]. The lower bound is exclusive for EVERY range
// function, not just the log-line ones: Loki's range_vector.go skips
// `sample.Timestamp <= start` in both batchRangeVectorIterator.load and
// streamRangeVectorIterator.load, and newRangeVectorIterator picks between
// them on window overlap (selRange >= step), never on the function.
func manualWindowValues(samples []rangeMetricSample, windowStart, windowEnd int64) []float64 {
	values := make([]float64, 0, len(samples))
	for _, sample := range samples {
		if sample.ts <= windowStart || sample.ts > windowEnd {
			continue
		}
		values = append(values, sample.value)
	}
	return values
}

func aggregateManualWindow(functionName string, quantile float64, samples []rangeMetricSample, windowStart, windowEnd int64, windowSeconds float64) (float64, bool) {
	// Slice-dependent functions: build filtered slice, then aggregate.
	switch functionName {
	case "quantile", "stddev", "stdvar", "rate_counter":
		values := manualWindowValues(samples, windowStart, windowEnd)
		if len(values) == 0 {
			return 0, false
		}
		switch functionName {
		case "quantile":
			return quantileFloat64(values, quantile), true
		case "stddev":
			return stddevFloat64(values), true
		case "stdvar":
			v := stddevFloat64(values)
			return v * v, true
		case "rate_counter":
			if windowSeconds <= 0 {
				return 0, false
			}
			if len(values) == 1 {
				return 0, true
			}
			return rateCounterWindow(values, windowSeconds), true
		}
	}

	// Inline accumulator path — no heap allocation for common aggregations.
	var (
		count    int
		sum      float64
		minVal   float64
		maxVal   float64
		firstVal float64
		lastVal  float64
		hasFirst bool
	)
	// Every range vector is (start, end] — see manualWindowValues.
	for _, sample := range samples {
		if sample.ts <= windowStart || sample.ts > windowEnd {
			continue
		}
		v := sample.value
		count++
		sum += v
		if !hasFirst {
			firstVal = v
			minVal = v
			maxVal = v
			hasFirst = true
		} else {
			if v < minVal {
				minVal = v
			}
			if v > maxVal {
				maxVal = v
			}
		}
		lastVal = v
	}

	if count == 0 {
		return 0, false
	}

	switch functionName {
	case "count_over_time":
		return float64(count), true
	case "rate":
		if windowSeconds <= 0 {
			return 0, false
		}
		return float64(count) / windowSeconds, true
	case "bytes_over_time", "sum":
		return sum, true
	case "bytes_rate":
		if windowSeconds <= 0 {
			return 0, false
		}
		return sum / windowSeconds, true
	case "avg":
		return sum / float64(count), true
	case "min":
		return minVal, true
	case "max":
		return maxVal, true
	case "first":
		return firstVal, true
	case "last":
		return lastVal, true
	default:
		return 0, false
	}
}

func sumFloat64(values []float64) float64 {
	var out float64
	for _, value := range values {
		out += value
	}
	return out
}

func stddevFloat64(values []float64) float64 {
	mean := sumFloat64(values) / float64(len(values))
	var variance float64
	for _, value := range values {
		diff := value - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	return math.Sqrt(variance)
}

func quantileFloat64(values []float64, phi float64) float64 {
	if phi < 0 {
		return math.Inf(-1)
	}
	if phi > 1 {
		return math.Inf(1)
	}
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	if len(ordered) == 1 {
		return ordered[0]
	}
	rank := phi * float64(len(ordered)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return ordered[lower]
	}
	weight := rank - float64(lower)
	return ordered[lower]*(1-weight) + ordered[upper]*weight
}

func rateCounterWindow(values []float64, windowSeconds float64) float64 {
	var increase float64
	prev := values[0]
	for _, current := range values[1:] {
		if current >= prev {
			increase += current - prev
		} else {
			increase += current
		}
		prev = current
	}
	return increase / windowSeconds
}

// outerAggregationOverSeries returns the bare outer aggregation that must be
// applied ACROSS series, or "" when the range aggregation may instead be pooled
// into a single series.
//
// LogQL evaluates the range aggregation PER LABEL SET and only then applies the
// outer aggregation. Pooling every row into one series is a shortcut that holds
// exactly when the outer aggregation is a sum of additive per-series values —
// `sum(count_over_time(...))` is the same number either way. It does NOT hold
// for an order statistic: `max(quantile_over_time(0.95, …))` is the max of the
// per-series p95s, and pooling returns the p95 of everything, which is lower
// (measured on the T5 panel: 1488.7 pooled vs 1720 in Loki, −13.4%).
func outerAggregationOverSeries(originalLogql, manualFunc string) (agg string, by []string, ok bool) {
	name := outerAggregationName(originalLogql)
	switch name {
	case "sum", "min", "max", "avg", "count":
	default:
		// topk/bottomk/sort/stddev keep their existing post-processing.
		return "", nil, false
	}
	if name == "sum" && isAdditiveManualFunc(manualFunc) && len(parseOriginalWithoutLabels(originalLogql)) == 0 {
		// count/rate/bytes are ADDITIVE: pooling every row into one series is the
		// same number the outer sum would produce, and it is the cheaper path.
		// Any OTHER outer aggregation over them (max(rate(...))) is a reduction
		// across the per-series values and takes the decomposition below — as
		// does `sum without (…)`, whose grouping is "everything but".
		return "", nil, false
	}
	if without := parseOriginalWithoutLabels(originalLogql); len(without) > 0 {
		return name, without, true
	}
	return name, parseOriginalByLabels(originalLogql), true
}

// isAdditiveManualFunc reports whether the range aggregation sums per-row
// contributions, so pooling rows across series is exact.
func isAdditiveManualFunc(manualFunc string) bool {
	switch manualFunc {
	case "rate", "count_over_time", "bytes_over_time", "bytes_rate", "count", "bytes":
		return true
	}
	return false
}

// outerAggregationName returns the bare outer vector aggregation keyword of
// the LogQL (`sum`, `max`, `topk`, …) or "" when there is none.
func outerAggregationName(originalLogql string) string {
	trimmed := stripOuterLabelReplace(strings.TrimSpace(originalLogql))
	loc := outerAggregationRE.FindStringIndex(trimmed)
	if loc == nil || loc[0] != 0 || loc[1] >= len(trimmed) {
		return ""
	}
	// outerAggregationRE matches a bare keyword, and every one of them is also
	// the prefix of a RANGE aggregation: `min_over_time(...)` starts with `min`,
	// `count_over_time(...)` with `count`. Only a `(` (after an optional
	// by/without clause) makes it the outer operator.
	if !strings.HasPrefix(strings.TrimSpace(trimmed[loc[1]:]), "(") {
		return ""
	}
	name := strings.TrimSpace(trimmed[loc[0]:loc[1]])
	if i := strings.IndexAny(name, "( \t"); i > 0 {
		name = name[:i]
	}
	return name
}

// applyLokiSeriesDecomposition makes the manual path evaluate the range
// aggregation the way LogQL does — once per LABEL SET — and reduce the results
// with the outer aggregation afterwards. Pooling every row into one series is
// only equivalent for an additive aggregation; on an order statistic it answers
// a different question (the T5 panel: p95 of everything, 1488.7, where Loki
// takes the max of the per-series p95s, 1720).
func applyLokiSeriesDecomposition(spec *statsCompatSpec, originalLogql, manualFunc string) {
	agg, by, ok := outerAggregationOverSeries(originalLogql, manualFunc)
	if !ok {
		// A bare outer aggregation without by() collapses all streams into one
		// empty-label series in Loki, and pooling gets there directly. The
		// grouping on the translated LogsQL is then the translator's default
		// inner grouping (`_stream, level`), not anything the user asked for —
		// keeping it made `sum(rate({ns}[4h30m]))` answer seven per-pod series
		// with full labels instead of `{}` (round 11).
		if !spec.ByExplicit && hasOuterAggregationWithoutBy(originalLogql) &&
			(len(spec.GroupBy) == 0 || (outerAggregationName(originalLogql) == "sum" && isAdditiveManualFunc(manualFunc))) {
			spec.GroupBy, spec.OrigGroupBy = nil, nil
			spec.ByExplicit = true
		}
		return
	}
	spec.OuterAggAcrossSeries, spec.OuterAggBy = agg, by
	spec.OuterAggWithout = len(parseOriginalWithoutLabels(originalLogql)) > 0
	// Only the POOLING is switched off. The grouping labels stay: the raw-row
	// collector needs them to keep parser-derived dimensions in the series key
	// (it only materialises the fields named in by(...)), and dropping them
	// would leave the reduction below with labels that no longer exist.
	spec.ByExplicit = false
}

// reduceLokiSeriesAcrossSeries applies the outer aggregation LogQL runs over the
// per-series range-aggregation results, collapsing the matrix/vector to one
// series per `by` group (one unlabelled series when by is empty).
//
// groupedMetricLabels keeps only the grouping labels of a series.
func groupedMetricLabels(metric map[string]string, by []string, without bool) map[string]string {
	if without {
		out := make(map[string]string, len(metric))
		for k, v := range metric {
			if v != "" && !slices.Contains(by, k) {
				out[k] = v
			}
		}
		return out
	}
	if len(by) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(by))
	for _, name := range by {
		if v, ok := metric[name]; ok && v != "" {
			out[name] = v
		}
	}
	return out
}

func reduceLokiSeriesAcrossSeries(body []byte, agg string, by []string, without bool) []byte {
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}
	data, _ := resp["data"].(map[string]interface{})
	if data == nil {
		return body
	}
	result, _ := data["result"].([]interface{})
	if len(result) == 0 {
		return body
	}
	// A single series is NOT a no-op: the decomposition keeps the full label set
	// on it, and the outer aggregation still has to trim it to its by() labels
	// (to `{}` when it has none).

	type acc struct {
		val    float64
		count  int
		metric map[string]string
	}
	type key struct {
		ts    int64
		group string
	}
	byTS := map[key]*acc{}
	instant := false
	add := func(ts int64, v float64, metric map[string]string) {
		grouped := groupedMetricLabels(metric, by, without)
		k := key{ts: ts, group: canonicalLabelsKey(grouped)}
		a := byTS[k]
		if a == nil {
			byTS[k] = &acc{val: v, count: 1, metric: grouped}
			return
		}
		a.count++
		switch agg {
		case "min":
			if v < a.val {
				a.val = v
			}
		case "max":
			if v > a.val {
				a.val = v
			}
		default: // sum, avg, count
			a.val += v
		}
	}
	for _, raw := range result {
		s, _ := raw.(map[string]interface{})
		if s == nil {
			continue
		}
		metric := map[string]string{}
		if m, ok := s["metric"].(map[string]interface{}); ok {
			for k, v := range m {
				metric[k], _ = v.(string)
			}
		}
		if pt, ok := s["value"].([]interface{}); ok && len(pt) >= 2 {
			instant = true
			add(int64(parsePointValue(pt[0])), parsePointValue(pt[1]), metric)
			continue
		}
		values, _ := s["values"].([]interface{})
		for _, rawPt := range values {
			pt, _ := rawPt.([]interface{})
			if len(pt) < 2 {
				continue
			}
			add(int64(parsePointValue(pt[0])), parsePointValue(pt[1]), metric)
		}
	}

	keys := make([]key, 0, len(byTS))
	for k := range byTS {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].group != keys[j].group {
			return keys[i].group < keys[j].group
		}
		return keys[i].ts < keys[j].ts
	})

	type outSeries struct {
		metric map[string]string
		points []interface{}
	}
	order := make([]string, 0, 4)
	out := map[string]*outSeries{}
	for _, k := range keys {
		a := byTS[k]
		v := a.val
		switch agg {
		case "avg":
			v /= float64(a.count)
		case "count":
			v = float64(a.count)
		}
		os := out[k.group]
		if os == nil {
			os = &outSeries{metric: a.metric}
			out[k.group] = os
			order = append(order, k.group)
		}
		os.points = append(os.points, []interface{}{k.ts, strconv.FormatFloat(v, 'f', -1, 64)})
	}

	reduced := make([]interface{}, 0, len(order))
	for _, g := range order {
		os := out[g]
		series := map[string]interface{}{"metric": os.metric}
		if instant {
			if len(os.points) == 0 {
				continue
			}
			series["value"] = os.points[len(os.points)-1]
		} else {
			series["values"] = os.points
		}
		reduced = append(reduced, series)
	}
	data["result"] = reduced
	encoded, err := json.Marshal(resp)
	if err != nil {
		return body
	}
	return encoded
}

// promotionCacheKey appends the row's values of every field a label promotion
// reads, so the per-stream series cache stays correct when two rows of one
// _stream differ in a mapped label.
func (p *Proxy) promotionCacheKey(v *fj.Value) string {
	if len(p.labelPromotions) == 0 {
		return ""
	}
	var b strings.Builder
	get := fjFieldGetter(nil, v)
	for _, prom := range p.labelPromotions {
		for _, f := range prom.fields {
			b.WriteByte('|')
			b.WriteString(get(f))
		}
	}
	return b.String()
}
