package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
	fj "github.com/valyala/fastjson"
)

// LogQL's `| line_format` and `| label_format` carry arbitrary Go templates.
// The string translator can only rewrite the trivial `{{.field}}` shape into a
// LogsQL `| format` placeholder; conditionals, function pipes and `__line__`
// pass through verbatim, so VictoriaLogs emits the template TEXT as the line or
// as the label value. Every later stage then reads that garbage: a `| regexp`
// after a `| line_format` matches nothing, and `sum by (<formatted label>)`
// collapses every series into one.
//
// So a pipeline containing a template stage is evaluated HERE, entry by entry.
// VictoriaLogs is asked only for the stream selector plus the leading line
// filters — both index-backed and safe to push down — and internal/logql's
// Pipeline reproduces the rest with Loki's semantics.
//
// Trade-off: rows that later stages would have dropped still cross the wire.
// Pushing a template down as LogsQL `format`/`replace_regexp` pipes when it
// happens to be expressible is a possible optimisation; correctness first.

// templatePlan is the compiled proxy-side execution plan for one such query.
type templatePlan struct {
	pipeline   *logqlpkg.Pipeline
	baseLogsQL string // reduced LogsQL sent to VictoriaLogs
	// fallbackLogsQL carries only the leading line filters. The pushed-down
	// pipeline stages are an optimisation, and VictoriaLogs rejects a few of the
	// filters Loki accepts (a `\d`-style regex inside a `| filter` pipe), so a
	// backend 4xx retries with this narrower query rather than failing the panel.
	fallbackLogsQL string
}

// templatePlanFor builds a plan when logqlQuery's log pipeline contains a
// template stage. It returns (nil, nil) when the query needs no proxy-side
// evaluation, and an error when the query contains a template this proxy cannot
// evaluate — that error must reach the client as a 400 rather than silently
// falling back to emitting template text.
func (p *Proxy) templatePlanFor(ctx context.Context, logqlQuery string) (*templatePlan, error) {
	expr, err := logqlpkg.Parse(strings.TrimSpace(logqlQuery))
	if err != nil {
		return nil, nil //nolint:nilerr // unparseable queries keep their existing route
	}
	lq := innermostLogQuery(expr)
	if lq == nil || !logqlpkg.NeedsProxyEvaluation(lq.Pipeline) {
		return nil, nil
	}

	pipeline, err := logqlpkg.NewPipeline(lq.Pipeline)
	if err != nil {
		return nil, err
	}

	p.metrics.RecordTemplatePipelineQuery()

	// Push down everything up to the first stage the proxy must evaluate itself.
	// Only the leading line filters used to travel, so a query whose parser-stage
	// filter matches nothing still dragged every row of the selector across the
	// wire — and on a broad selector that trips the raw-row cap, turning an
	// EMPTY result into a 400 (Loki answers 0 rows). The stages pushed here are
	// the same ones a non-template query already delegates to VictoriaLogs.
	fallbackLogsQL, err := p.translateQueryWithContext(ctx,
		(&logqlpkg.LogQuery{Selector: lq.Selector, Pipeline: leadingLineFilters(lq.Pipeline)}).String())
	if err != nil {
		return nil, err
	}
	baseLogsQL, err := p.translateQueryWithContext(ctx,
		(&logqlpkg.LogQuery{Selector: lq.Selector, Pipeline: pushdownPrefix(lq.Pipeline)}).String())
	if err != nil {
		baseLogsQL = fallbackLogsQL
	}
	return &templatePlan{pipeline: pipeline, baseLogsQL: baseLogsQL, fallbackLogsQL: fallbackLogsQL}, nil
}

// innermostLogQuery unwraps aggregations down to the log query they range over.
// A binary expression has two of them, so it is left to its own per-side route.
func innermostLogQuery(expr logqlpkg.Expr) *logqlpkg.LogQuery {
	for {
		switch e := expr.(type) {
		case *logqlpkg.LogQuery:
			return e
		case *logqlpkg.VectorAggregation:
			expr = e.Inner
		case *logqlpkg.RangeAggregation:
			if e.Step != "" { // subquery: the inner expression is itself a metric
				return nil
			}
			expr = e.Inner
		default:
			return nil
		}
	}
}

// pushdownPrefix returns the leading stages VictoriaLogs can evaluate: every
// stage before the first one that needs proxy-side evaluation (a Go template or
// an `__error__` filter). Dropping rows earlier is safe — the proxy re-runs the
// WHOLE pipeline on what comes back.
func pushdownPrefix(stages []logqlpkg.Stage) []logqlpkg.Stage {
	for i, s := range stages {
		if logqlpkg.NeedsProxyEvaluation([]logqlpkg.Stage{s}) {
			return stages[:i]
		}
	}
	return stages
}

// leadingLineFilters returns the run of line filters at the head of the
// pipeline — the only stages that can be pushed down without changing what the
// proxy-side evaluator sees, because they read the raw line.
func leadingLineFilters(stages []logqlpkg.Stage) []logqlpkg.Stage {
	var out []logqlpkg.Stage
	for _, s := range stages {
		lf, ok := s.(*logqlpkg.LineFilterStage)
		if !ok {
			return out
		}
		out = append(out, lf)
	}
	return out
}

// templateEntry is one entry that survived the pipeline.
//
// labels is the flat post-pipeline set (what grouping and non-categorized
// responses use). stream/sm/parsed are the same values split the way Loki's
// categorize-labels encoding wants them: original stream labels stay in the
// stream map, VictoriaLogs' other row fields are structured metadata, and
// anything the pipeline itself produced is parsed.
type templateEntry struct {
	ts     int64 // unix nanoseconds
	line   string
	labels map[string]string
	stream map[string]string
	sm     map[string]string
	parsed map[string]string
}

// fetchTemplatePipelineEntries runs the reduced LogsQL against VictoriaLogs and
// returns the entries that survive the proxy-side pipeline.
// truncationFatal says whether hitting the raw-row cap must fail the query. An
// AGGREGATION over a truncated scan is silently wrong, so it does; a LOG query
// is already a "newest N lines" request (VictoriaLogs sorts by _time desc), so
// it does not.
// forward says the client asked for the OLDEST entries first. VictoriaLogs is
// free to return rows in any order, so the cap below would otherwise keep an
// arbitrary subset; the query carries an explicit sort matching the direction.
func (p *Proxy) fetchTemplatePipelineEntries(ctx context.Context, plan *templatePlan, start, end time.Time, truncationFatal, forward bool) ([]templateEntry, error) {
	entries, err := p.fetchTemplatePipelineEntriesQuery(ctx, plan, plan.baseLogsQL, start, end, truncationFatal, forward)
	// The pushed-down stages are an optimisation; VictoriaLogs rejecting them is
	// not a reason to fail a panel Loki answers.
	var rejected *templatePushdownRejectedError
	if err != nil && plan.fallbackLogsQL != "" && plan.fallbackLogsQL != plan.baseLogsQL &&
		errors.As(err, &rejected) {
		slog.WarnContext(ctx, "template pipeline pushdown rejected by backend, retrying with line filters only",
			"status", rejected.status)
		return p.fetchTemplatePipelineEntriesQuery(ctx, plan, plan.fallbackLogsQL, start, end, truncationFatal, forward)
	}
	return entries, err
}

func (p *Proxy) fetchTemplatePipelineEntriesQuery(ctx context.Context, plan *templatePlan, logsql string, start, end time.Time, truncationFatal, forward bool) ([]templateEntry, error) {
	params := url.Values{}
	rowLimit := p.rangeMetricRowLimit
	if rowLimit <= 0 {
		rowLimit = defaultManualRangeMetricRowLimit
	}
	// Bounded sort: the proxy-side row cap below stops READING at rowLimit, but
	// an unbounded `| sort` has already made VictoriaLogs materialise the whole
	// match before it emits the first row. Same ceiling, declared to the backend
	// — plus ONE row, because the cap below is detected by scanning PAST it. Ask
	// for exactly rowLimit and `rowsScanned > rowLimit` can never fire, so a
	// truncated aggregate would be served as a complete one.
	logsql += sortByTimePipe(forward, rowLimit+1)
	params.Set("query", logsql)
	params.Set("start", formatVLTimestamp(start.UTC().Format(time.RFC3339Nano)))
	params.Set("end", formatVLTimestamp(end.UTC().Format(time.RFC3339Nano)))
	// No HTTP `limit` argument: the cap is counted here as the rows stream, and
	// the memory this scan may hold is drawn from the shared retained-entry
	// budget. The backend-side bound is the `limit` on the sort pipe above.
	reservation := p.newManualScanReservation()
	defer reservation.release()

	resp, err := p.vlPost(ctx, "/select/logsql/query", params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := readBodyLimited(resp.Body, maxUpstreamErrorBodyBytes)
		err := p.redactedBackendStatusError("backend returned", resp.StatusCode, body)
		if resp.StatusCode < 500 {
			return nil, &templatePushdownRejectedError{status: resp.StatusCode, err: err}
		}
		return nil, err
	}

	fjp := vlFJParserPool.Get()
	defer vlFJParserPool.Put(fjp)

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)

	out := make([]templateEntry, 0, 256)
	rowsScanned := 0
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		rowsScanned++
		if rowsScanned > rowLimit {
			if truncationFatal {
				p.log.Warn("template pipeline scan refused", "reason", "row cap", "limit", rowLimit)
				return nil, &rawRowScanTruncatedError{limit: rowLimit}
			}
			break
		}
		v, parseErr := fjp.ParseBytes(raw)
		if parseErr != nil {
			continue
		}
		ts, ok := vlRowTimestampNanos(v)
		if !ok {
			continue
		}
		streamLabels, smFields := p.templateEntryFields(v)
		merged := make(map[string]string, len(streamLabels)+len(smFields))
		for k, val := range smFields {
			merged[k] = val
		}
		for k, val := range streamLabels {
			merged[k] = val
		}
		entry := logqlpkg.Entry{TS: time.Unix(0, ts), Line: string(v.GetStringBytes("_msg")), Labels: merged}
		if !plan.pipeline.Process(&entry) {
			continue
		}
		// Only an entry that SURVIVES costs memory until the fold. Charging rows
		// the parser, the timestamp check or the pipeline threw away spent the
		// shared budget on nothing and refused scans that fit it.
		if !reservation.account() {
			if truncationFatal {
				p.log.Warn("template pipeline scan refused",
					"reason", "shared retained-sample budget exhausted",
					"budget_samples", defaultManualScanSampleBudget,
					"rows_scanned", rowsScanned, "entries_retained", len(out))
				return nil, &manualScanBudgetError{budget: defaultManualScanSampleBudget}
			}
			break
		}
		te := templateEntry{ts: ts, line: entry.Line, labels: entry.Labels}
		te.stream, te.sm, te.parsed = splitTemplateLabels(entry.Labels, streamLabels, smFields)
		out = append(out, te)
	}
	if scanErr := scanner.Err(); scanErr != nil {
		return nil, fmt.Errorf("scanning VL response: %w", scanErr)
	}
	return out, nil
}

// splitTemplateLabels classifies the post-pipeline label set. A key that still
// holds its original value belongs where it came from; everything else — a new
// label, or one a parser or label_format rewrote — is a PARSED field, which is
// exactly Loki's rule for the categorize-labels encoding.
func splitTemplateLabels(final, streamLabels, smFields map[string]string) (stream, sm, parsed map[string]string) {
	stream = make(map[string]string, len(streamLabels))
	sm = make(map[string]string, len(smFields))
	parsed = make(map[string]string, 4)
	for k, v := range final {
		switch {
		case streamLabels[k] == v:
			stream[k] = v
		case smFields[k] == v:
			sm[k] = v
		default:
			parsed[k] = v
		}
	}
	return stream, sm, parsed
}

// templateEntryFields splits a VictoriaLogs row into the Loki-named stream
// labels and the row's other fields (Loki's structured metadata).
func (p *Proxy) templateEntryFields(v *fj.Value) (streamLabels, smFields map[string]string) {
	labels := make(map[string]string, 8)
	if obj, err := v.Object(); err == nil {
		obj.Visit(func(key []byte, val *fj.Value) {
			k := string(key)
			if k == "_msg" || k == "_time" || k == "_stream" || isVLInternalField(k) {
				return
			}
			sv := string(val.GetStringBytes())
			if sv == "" {
				sv = strings.Trim(val.String(), `"`)
			}
			if strings.TrimSpace(sv) != "" {
				labels[k] = sv
			}
		})
	}
	smFields = p.labelTranslator.TranslateLabelsMap(labels)
	streamLabels = p.labelTranslator.TranslateLabelsMap(parseStreamLabels(string(v.GetStringBytes("_stream"))))
	for k := range streamLabels {
		delete(smFields, k)
	}
	return streamLabels, smFields
}

func vlRowTimestampNanos(v *fj.Value) (int64, bool) {
	rawTS := string(v.GetStringBytes("_time"))
	if rawTS == "" {
		return 0, false
	}
	normTS, ok := formatEntryTimestamp(rawTS)
	if !ok {
		return 0, false
	}
	ts, err := strconv.ParseInt(normTS, 10, 64)
	if err != nil {
		return 0, false
	}
	if ts < 1e12 {
		ts *= int64(time.Second)
	}
	return ts, true
}

// ─── log queries ────────────────────────────────────────────────────────────

// proxyTemplateLogQuery serves a `streams` query whose pipeline needs
// proxy-side template evaluation. It reports whether it wrote a response.
func (p *Proxy) proxyTemplateLogQuery(w http.ResponseWriter, r *http.Request, logqlQuery string, categorizedLabels bool) bool {
	plan, err := p.templatePlanFor(r.Context(), logqlQuery)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, err.Error())
		return true
	}
	if plan == nil {
		return false
	}

	start, err := parseTimestamp(r.FormValue("start"))
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "invalid start timestamp: "+err.Error())
		return true
	}
	end, err := parseTimestamp(r.FormValue("end"))
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "invalid end timestamp: "+err.Error())
		return true
	}

	backward := !strings.EqualFold(r.FormValue("direction"), "forward")
	entries, err := p.fetchTemplatePipelineEntries(r.Context(), plan, start, end, false, !backward)
	if err != nil {
		p.writeError(w, templateFetchErrorStatus(err), err.Error())
		return true
	}

	limit := p.maxLines
	if v := r.FormValue("limit"); v != "" {
		if n, convErr := strconv.Atoi(sanitizeLimit(v)); convErr == nil && n > 0 {
			limit = n
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		// Equal timestamps are NOT ordered here: SliceStable already preserves
		// their input order, and returning i<j makes the comparator inconsistent
		// (it would claim both i<j and j<i for a swapped pair).
		if backward {
			return entries[i].ts > entries[j].ts
		}
		return entries[i].ts < entries[j].ts
	})
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}

	emitStructuredMetadata := p.shouldEmitStructuredMetadata(r)
	writeLokiStreamQueryResponse(w, groupTemplateEntriesIntoStreams(entries, categorizedLabels, emitStructuredMetadata), categorizedLabels)
	return true
}

// groupTemplateEntriesIntoStreams collapses entries sharing a label set into one
// Loki stream, preserving the order they were given in.
//
// Under the categorize-labels encoding the stream map carries ONLY the original
// stream labels and the per-entry tuple carries structuredMetadata + parsed;
// without it Loki flattens everything into the stream map, which is what the
// proxy's other log paths do too.
func groupTemplateEntriesIntoStreams(entries []templateEntry, categorizedLabels, emitStructuredMetadata bool) []map[string]interface{} {
	order := make([]string, 0, 8)
	byKey := make(map[string]map[string]interface{}, 8)
	for _, e := range entries {
		labels := e.labels
		if categorizedLabels {
			labels = e.stream
		}
		key := canonicalLabelsKey(labels)
		stream, ok := byKey[key]
		if !ok {
			stream = map[string]interface{}{"stream": labels, "values": make([]interface{}, 0, 16)}
			byKey[key] = stream
			order = append(order, key)
		}
		values, _ := stream["values"].([]interface{})
		stream["values"] = append(values, buildStreamValue(
			strconv.FormatInt(e.ts, 10), e.line, e.sm, e.parsed, emitStructuredMetadata, categorizedLabels))
	}
	out := make([]map[string]interface{}, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

// ─── metric queries ─────────────────────────────────────────────────────────

// templateFetchErrorStatus maps a fetch failure to a status. Hitting the raw-row
// cap is the client's query being too broad for this path, not a backend fault.
// templatePushdownRejectedError marks a 4xx from VictoriaLogs on the pushed-down
// query, which the caller retries with fewer stages.
type templatePushdownRejectedError struct {
	status int
	err    error
}

func (e *templatePushdownRejectedError) Error() string { return e.err.Error() }
func (e *templatePushdownRejectedError) Unwrap() error { return e.err }

// StatusCode is the backend's own status: a rejected query is the CLIENT's
// query being unacceptable, so it must not surface as a 502.
func (e *templatePushdownRejectedError) StatusCode() int { return e.status }

func templateFetchErrorStatus(err error) int {
	var truncated *rawRowScanTruncatedError
	if errors.As(err, &truncated) {
		return http.StatusBadRequest
	}
	// The memory guard is the same kind of answer — the client's query is too
	// broad for this path, not a backend fault.
	var overBudget *manualScanBudgetError
	if errors.As(err, &overBudget) {
		return http.StatusBadRequest
	}
	var rejected *templatePushdownRejectedError
	if errors.As(err, &rejected) && rejected.status > 0 {
		return rejected.status
	}
	return statusFromUpstreamErr(err)
}

// errTemplateMetricUnsupported marks a metric shape the template path declines,
// so the caller can fall back to its normal routing.
var errTemplateMetricUnsupported = errors.New("template pipeline: unsupported metric shape")

// collectTemplatePipelineSamples turns the surviving entries into the same
// per-series sample map the manual range-metric path consumes, so rate(),
// count_over_time(), quantile_over_time() and friends keep their existing —
// correct, window-divided — evaluation in buildManualRangeMetric{Matrix,Vector}.
func (p *Proxy) collectTemplatePipelineSamples(
	ctx context.Context,
	plan *templatePlan,
	spec statsCompatSpec,
	field, unwrapConv string,
	start, end time.Time,
) (map[string]manualSeriesSamples, error) {
	entries, err := p.fetchTemplatePipelineEntries(ctx, plan, start, end, true, false)
	if err != nil {
		return nil, err
	}

	seriesMap := make(map[string]manualSeriesSamples, 8)
	for i := range entries {
		e := &entries[i]
		value, ok := templateSampleValue(e, field, unwrapConv)
		if !ok {
			continue
		}
		metric := templateMetricLabels(e.labels, spec)
		key := canonicalLabelsKey(metric)
		current := seriesMap[key]
		if current.Metric == nil {
			current.Metric = metric
		}
		current.Samples = append(current.Samples, rangeMetricSample{ts: e.ts, value: value})
		seriesMap[key] = current
	}
	for key, series := range seriesMap {
		sort.Slice(series.Samples, func(i, j int) bool { return series.Samples[i].ts < series.Samples[j].ts })
		seriesMap[key] = series
	}
	return seriesMap, nil
}

// templateSampleValue mirrors extractManualSampleValueFJ over a post-pipeline entry.
func templateSampleValue(e *templateEntry, field, unwrapConv string) (float64, bool) {
	switch field {
	case "__count__":
		return 1, true
	case "__bytes__":
		return float64(len(e.line)), true
	}
	raw, ok := e.labels[field]
	if !ok {
		return 0, false
	}
	switch unwrapConv {
	case "duration":
		return parseDuration(raw)
	case "bytes":
		return parseBytes(raw)
	default:
		f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
		return f, err == nil
	}
}

// templateMetricLabels applies the query's by()/without() grouping to the
// post-pipeline label set.
func templateMetricLabels(labels map[string]string, spec statsCompatSpec) map[string]string {
	if spec.ByExplicit && len(spec.GroupBy) == 0 {
		return map[string]string{}
	}
	names := spec.GroupBy
	if len(spec.OrigGroupBy) == len(spec.GroupBy) && len(spec.OrigGroupBy) > 0 {
		names = spec.OrigGroupBy
	}
	if len(names) == 0 {
		out := make(map[string]string, len(labels))
		for k, v := range labels {
			if !strings.HasPrefix(k, "__") && v != "" {
				out[k] = v
			}
		}
		return out
	}
	out := make(map[string]string, len(names))
	for _, n := range names {
		// A label the user NAMED in by() identifies the series even when its value
		// is empty: Loki answers `{lf=""}`, and dropping the name made it `{}` —
		// the same numbers under a different series in Grafana. A label that is
		// ABSENT is a different thing again, and Loki omits that one, so the
		// comma-ok is load-bearing.
		if value, ok := labels[n]; ok {
			out[n] = value
		}
	}
	return out
}

// templateMetricPlan carries everything the manual metric builders need.
type templateMetricPlan struct {
	plan       *templatePlan
	spec       statsCompatSpec
	origSpec   originalRangeMetricSpec
	manualFunc string
	field      string
	quantile   float64
}

// buildTemplateMetricPlan prepares a metric query whose pipeline needs
// proxy-side template evaluation. ok=false means "not our case, keep routing".
func (p *Proxy) buildTemplateMetricPlan(ctx context.Context, originalLogql, logsqlQuery string) (*templateMetricPlan, bool, error) {
	plan, err := p.templatePlanFor(ctx, originalLogql)
	if err != nil {
		return nil, true, err
	}
	if plan == nil {
		return nil, false, nil
	}
	origSpec, hasOrigSpec := parseOriginalRangeMetricSpec(originalLogql)
	if !hasOrigSpec || origSpec.Window <= 0 {
		return nil, true, fmt.Errorf("invalid range metric query")
	}
	statsSpec, _ := parseStatsCompatSpec(logsqlQuery)
	manualFunc := normalizeManualMetricFunction(statsSpec, origSpec)
	if manualFunc == "" || !isManualRangeStatsFunc(manualFunc) && manualFunc != "count_over_time" && manualFunc != "bytes_over_time" && manualFunc != "bytes_rate" {
		return nil, true, fmt.Errorf("%w: %s", errTemplateMetricUnsupported, origSpec.Func)
	}

	// Grouping is applied to the POST-pipeline label set, so the labels are the
	// Loki names the user wrote — never the VL-translated ones.
	byLabels := parseOriginalByLabels(originalLogql)
	spec := statsCompatSpec{
		GroupBy:     byLabels,
		OrigGroupBy: byLabels,
		ByExplicit:  len(byLabels) == 0 && hasOuterAggregationWithoutBy(originalLogql),
		Func:        statsSpec.Func,
		Field:       statsSpec.Field,
	}
	// An outer aggregation over an ORDER STATISTIC runs across the per-label-set
	// series, not over one pooled series (see applyLokiSeriesDecomposition).
	applyLokiSeriesDecomposition(&spec, originalLogql, manualFunc)

	field, quantile, err := templateMetricField(statsSpec, origSpec, manualFunc)
	if err != nil {
		return nil, true, err
	}
	return &templateMetricPlan{
		plan: plan, spec: spec, origSpec: origSpec,
		manualFunc: manualFunc, field: field, quantile: quantile,
	}, true, nil
}

// templateMetricField mirrors resolveManualMetricField but keeps Loki label
// names, because the template pipeline produces Loki-named labels.
func templateMetricField(statsSpec statsCompatSpec, origSpec originalRangeMetricSpec, manualFunc string) (string, float64, error) {
	switch manualFunc {
	case "rate", "count_over_time":
		return "__count__", 0, nil
	case "bytes_over_time", "bytes_rate":
		return "__bytes__", 0, nil
	case "quantile":
		phi, field, ok := parseStatsQuantileSpec(statsSpec.Field)
		if !ok || strings.TrimSpace(origSpec.UnwrapField) == "" {
			return "", 0, fmt.Errorf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func))
		}
		_ = field
		return origSpec.UnwrapField, phi, nil
	}
	if strings.TrimSpace(origSpec.UnwrapField) == "" {
		return "", 0, fmt.Errorf("invalid aggregation %s without unwrap", unwrapErrorFuncName(origSpec.Func))
	}
	return origSpec.UnwrapField, 0, nil
}

// templateMetricRangeBody evaluates a range metric query over a template
// pipeline and returns the Loki-shaped matrix body.
func (p *Proxy) templateMetricRangeBody(r *http.Request, mp *templateMetricPlan) ([]byte, error) {
	startTS, err := parseTimestamp(r.FormValue("start"))
	if err != nil {
		return nil, fmt.Errorf("invalid start timestamp: %w", err)
	}
	endTS, err := parseTimestamp(r.FormValue("end"))
	if err != nil {
		return nil, fmt.Errorf("invalid end timestamp: %w", err)
	}
	step := parseLokiDuration(formatVLStep(r.FormValue("step")))
	if step <= 0 {
		step = time.Minute
	}
	series, err := p.collectTemplatePipelineSamples(
		r.Context(), mp.plan, mp.spec, mp.field, mp.origSpec.UnwrapConv,
		startTS.Add(-mp.origSpec.Window), endTS)
	if err != nil {
		return nil, err
	}
	// The template pipeline yields RAW log entries.
	body := buildManualRangeMetricMatrix(mp.manualFunc, mp.quantile, series,
		startTS, endTS, step, mp.origSpec.Window, p.resolvedMaxStatsQuerySeries(), false)
	if mp.spec.OuterAggAcrossSeries != "" {
		body = reduceLokiSeriesAcrossSeries(body, mp.spec.OuterAggAcrossSeries, mp.spec.OuterAggBy)
	}
	return body, nil
}

// templateMetricInstantBody evaluates an instant metric query over a template
// pipeline and returns the Loki-shaped vector body.
func (p *Proxy) templateMetricInstantBody(r *http.Request, mp *templateMetricPlan) ([]byte, error) {
	evalTS, err := parseTimestamp(r.FormValue("time"))
	if err != nil {
		evalTS = time.Now()
	}
	series, err := p.collectTemplatePipelineSamples(
		r.Context(), mp.plan, mp.spec, mp.field, mp.origSpec.UnwrapConv,
		evalTS.Add(-mp.origSpec.Window), evalTS)
	if err != nil {
		return nil, err
	}
	// The template pipeline yields RAW log entries.
	body := buildManualRangeMetricVector(mp.manualFunc, mp.quantile, series, evalTS, mp.origSpec.Window, false)
	if mp.spec.OuterAggAcrossSeries != "" {
		body = reduceLokiSeriesAcrossSeries(body, mp.spec.OuterAggAcrossSeries, mp.spec.OuterAggBy)
	}
	return body, nil
}

// handleTemplateMetricRange answers a range metric query over a template
// pipeline. It reports whether it wrote a response.
func (p *Proxy) handleTemplateMetricRange(w http.ResponseWriter, r *http.Request, originalLogql, logsqlQuery string) bool {
	return p.handleTemplateMetric(w, r, originalLogql, logsqlQuery, p.templateMetricRangeBody)
}

// handleTemplateMetricInstant answers an instant metric query over a template pipeline.
func (p *Proxy) handleTemplateMetricInstant(w http.ResponseWriter, r *http.Request, originalLogql, logsqlQuery string) bool {
	return p.handleTemplateMetric(w, r, originalLogql, logsqlQuery, p.templateMetricInstantBody)
}

func (p *Proxy) handleTemplateMetric(
	w http.ResponseWriter, r *http.Request, originalLogql, logsqlQuery string,
	build func(*http.Request, *templateMetricPlan) ([]byte, error),
) bool {
	mp, mine, err := p.buildTemplateMetricPlan(r.Context(), originalLogql, logsqlQuery)
	if !mine {
		return false
	}
	if err != nil {
		p.writeError(w, http.StatusBadRequest, err.Error())
		return true
	}
	body, err := build(r, mp)
	if err != nil {
		p.writeError(w, templateFetchErrorStatus(err), err.Error())
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body) // nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter -- pre-built JSON, Content-Type set above
	return true
}

// templateBinOpPrefix marks one side of a binary metric expression whose
// pipeline needs proxy-side template evaluation. The binary machinery works on
// TRANSLATED LogsQL strings, so the original LogQL is carried inside the marker
// — the same trick the translator uses for nested binary expressions.
const templateBinOpPrefix = "__lvp_tpl:"

// templateBinOpMarker returns a marker for expr when its pipeline carries a Go
// template, so `sum(count_over_time({...} | line_format … [6h])) or vector(0)`
// evaluates its left side here instead of in VictoriaLogs.
func (p *Proxy) templateBinOpMarker(expr logqlpkg.Expr) (string, bool) {
	lq := innermostLogQuery(expr)
	if lq == nil || !logqlpkg.NeedsProxyEvaluation(lq.Pipeline) {
		return "", false
	}
	return templateBinOpPrefix + base64.StdEncoding.EncodeToString([]byte(expr.String())), true
}

// templateBinOpBody resolves a marked binary-expression side.
func (p *Proxy) templateBinOpBody(r *http.Request, marker, vlEndpoint string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(marker, templateBinOpPrefix))
	if err != nil {
		return nil, fmt.Errorf("invalid template marker: %w", err)
	}
	originalLogql := string(raw)
	logsqlQuery, err := p.translateQueryWithContext(r.Context(), originalLogql)
	if err != nil {
		return nil, err
	}
	mp, mine, err := p.buildTemplateMetricPlan(r.Context(), originalLogql, logsqlQuery)
	if err != nil {
		return nil, err
	}
	if !mine {
		return nil, fmt.Errorf("%w: %s", errTemplateMetricUnsupported, originalLogql)
	}
	if vlEndpoint == "stats_query_range" {
		return p.templateMetricRangeBody(r, mp)
	}
	return p.templateMetricInstantBody(r, mp)
}
