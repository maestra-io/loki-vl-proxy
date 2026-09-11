package translator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// LabelExpandFunc maps a Loki label name to the ordered list of VL fields that
// back it. It returns nil (or a single-element slice) when the label has no
// fallback chain — callers then fall back to LabelTranslateFunc.
type LabelExpandFunc func(lokiLabel string) []string

// ComputedLabel describes a Loki label synthesised by joining the values of two
// or more other Loki labels, e.g. job = "<namespace>/<app>".
type ComputedLabel struct {
	LokiLabel string   `json:"loki_label" yaml:"loki_label"`
	Join      []string `json:"join" yaml:"join"`
	Sep       string   `json:"sep" yaml:"sep"`
}

// Separator returns the configured join separator, defaulting to "/".
func (c ComputedLabel) Separator() string {
	if c.Sep == "" {
		return "/"
	}
	return c.Sep
}

// Valid reports whether the spec can be used for matcher splitting.
func (c ComputedLabel) Valid() bool {
	return strings.TrimSpace(c.LokiLabel) != "" && len(c.Join) >= 2
}

// MappingOptions carries the label-mapping features this fork adds on top of the
// upstream 1:1 label translation. A nil *MappingOptions restores upstream
// behaviour exactly, which is why every function taking one must be nil-safe.
type MappingOptions struct {
	// Expand resolves a Loki label to an ordered VL field fallback chain.
	Expand LabelExpandFunc
	// Computed lists labels synthesised by joining other labels.
	Computed []ComputedLabel
	// DerivedLevelFields lists the VL fields that may carry a raw log level once
	// _msg has been unpacked. Empty disables level derivation.
	DerivedLevelFields []string
	// MaterializeChainLabels lists Loki labels that are GROUPED BY in this query
	// and are backed by a multi-field fallback chain. A matcher on such a label
	// expands to an OR over the chain, but a grouping cannot: VL would group by
	// a field literally named e.g. `app`, which does not exist, yielding
	// {app=""}. These labels get a coalesce chain that materialises the field.
	MaterializeChainLabels []string

	// MaterializeLevel appends the unpack + coalesce + normalise pipe chain so
	// VL exposes a real `level` field (needed for `sum by (level)`).
	MaterializeLevel bool

	// InferLevelFromText allows the normalisation chain to derive a level from
	// the LINE TEXT when no named field carries a recognised value. Only
	// `detected_level` is Loki's inferred label; `level` is a stored one, and
	// filling it in from the message invented series the store does not have.
	InferLevelFromText bool
}

func (m *MappingOptions) expand(lokiLabel string) []string {
	if m == nil || m.Expand == nil {
		return nil
	}
	fields := m.Expand(lokiLabel)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = sanitizeFieldIdentifier(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (m *MappingOptions) computedFor(lokiLabel string) (ComputedLabel, bool) {
	if m == nil {
		return ComputedLabel{}, false
	}
	for _, c := range m.Computed {
		if c.LokiLabel == lokiLabel && c.Valid() {
			return c, true
		}
	}
	return ComputedLabel{}, false
}

func (m *MappingOptions) derivesLevel() bool {
	return m != nil && len(m.DerivedLevelFields) > 0
}

// isDerivedLevelLabel reports whether the Loki label is served by the derived
// level pipeline rather than by a stored VL field.
func (m *MappingOptions) isDerivedLevelLabel(label string) bool {
	return m.derivesLevel() && (label == "level" || label == "detected_level")
}

// quoteVLField wraps a VL field name in double quotes when it is not a bare
// LogsQL identifier. Dotted and slashed names (kubernetes.pod_labels.app,
// kubernetes.pod_labels.app.kubernetes.io/name) must be quoted.
func quoteVLField(field string) string {
	if field == "" || strings.HasPrefix(field, `"`) {
		return field
	}
	bare := true
	for i := 0; i < len(field); i++ {
		c := field[i]
		ok := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			bare = false
			break
		}
	}
	if bare {
		return field
	}
	return `"` + strings.ReplaceAll(field, `"`, `\"`) + `"`
}

// chainFilter builds the LogsQL filter for a fallback chain.
//
// Positive matchers (=, =~) become a disjunction: an entry matches when ANY of
// the chained fields matches, mirroring "first non-empty field wins" on the
// result side. Negative matchers (!=, !~) become a conjunction: EVERY chained
// field must fail to match, which is the negation of the positive form.
func chainFilter(fields []string, op logsql.FieldOp, value string, negate bool) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, buildFieldFilterStr(quoteVLField(f), op, value, negate))
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	if negate {
		// Implicit AND — every field must not match.
		return "(" + strings.Join(parts, " ") + ")"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// chainEmptyFilter builds the filter for `label=""` / `label!=""` over a chain.
// label="" means "none of the chained fields is set"; label!="" means "at least
// one is set".
func chainEmptyFilter(fields []string, negate bool) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		q := quoteVLField(f)
		if negate {
			parts = append(parts, fmt.Sprintf(`%s:!""`, q))
		} else {
			parts = append(parts, "-"+q+":*")
		}
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	if negate {
		return "(" + strings.Join(parts, " OR ") + ")"
	}
	return "(" + strings.Join(parts, " ") + ")"
}

// levelSynonyms maps a canonical Loki level to the regexp alternation of raw
// values that map onto it. Matching is case-insensitive and anchored.
var levelSynonyms = map[string]string{
	"error":    "err|error|errors|fatal|critical|crit|emerg|panic|alert",
	"critical": "fatal|critical|crit|emerg|panic",
	"warn":     "warn|warning|warnings",
	"info":     "info|information|informational|notice",
	"debug":    "debug|trace|fine|verbose",
	"trace":    "trace",
	"unknown":  "unknown",
}

// anyLevelValuePattern matches every raw value Loki RECOGNISES as a level. A
// named field holding anything else is, to Loki, no level at all.
func anyLevelValuePattern() string {
	alts := make([]string, 0, len(levelSynonyms))
	for _, canonical := range []string{"error", "warn", "info", "debug", "trace", "critical", "unknown"} {
		if alt, ok := levelSynonyms[canonical]; ok {
			alts = append(alts, alt)
		}
	}
	return "(?i)^(" + strings.Join(alts, "|") + ")$"
}

// levelValuePattern returns the anchored, case-insensitive regexp that matches
// every raw level value mapping to the canonical value.
func levelValuePattern(value string) string {
	canonical := strings.ToLower(strings.TrimSpace(value))
	alt, ok := levelSynonyms[canonical]
	if !ok {
		alt = regexpQuoteLiteral(canonical)
	}
	return "(?i)^(" + alt + ")$"
}

// regexpQuoteLiteral escapes regexp metacharacters in a literal level value.
func regexpQuoteLiteral(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// derivedLevelFilter builds the LogsQL filter for a level matcher over the
// configured raw level fields. The caller is responsible for injecting the
// unpack pipes that make those fields available.
func (m *MappingOptions) derivedLevelFilter(value string, negate, isRe bool) string {
	if !m.derivesLevel() {
		return ""
	}
	pattern := value
	if isRe {
		// User-supplied label regexp: anchor it like Loki does.
		pattern = logsql.AnchorLabelMatcherRegex(value)
	} else {
		// levelValuePattern is generated already anchored.
		pattern = levelValuePattern(value)
	}
	parts := make([]string, 0, len(m.DerivedLevelFields))
	for _, f := range m.DerivedLevelFields {
		parts = append(parts, buildFieldFilterStr(quoteVLField(f), logsql.FieldOpRegexp, pattern, negate))
	}
	if len(parts) == 0 {
		return ""
	}
	if !negate && !isRe {
		// Loki falls back to the LINE TEXT when no level field carries a value,
		// so a panel filtering on detected_level="error" also returns the rows
		// whose only evidence is the word in the message. Reproduce that here,
		// guarded by "no named level field is present" so a real level always
		// wins — which is Loki's precedence too.
		if textPattern := LokiTextLevelPattern(value); textPattern != "" {
			// Guard on a RECOGNISED named value, not on any value at all: Loki falls
			// back to the line text when the level key holds something it does not
			// know (`"LogLevel":"Information"`), so an unrecognised value must not
			// suppress the heuristic.
			present := make([]string, 0, len(m.DerivedLevelFields))
			for _, f := range m.DerivedLevelFields {
				present = append(present, buildFieldFilterStr(quoteVLField(f), logsql.FieldOpRegexp, anyLevelValuePattern(), false))
			}
			parts = append(parts, "(NOT ("+strings.Join(present, " OR ")+") AND "+
				buildFieldFilterStr("_msg", logsql.FieldOpRegexp, textPattern, false)+")")
		}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	if negate {
		return "(" + strings.Join(parts, " ") + ")"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// levelUnpackPipes returns the pipe chain that exposes raw level fields from
// _msg. JSON is unpacked first, then logfmt, matching the proxy's read-path
// level detection order.
func levelUnpackPipes() []string {
	return []string{
		logsql.PipeUnpackJSON{From: "_msg"}.String(),
		logsql.PipeUnpackLogfmt{From: "_msg"}.String(),
	}
}

// levelNormalizePipes returns the pipe chain that turns the raw level fields
// into a single normalised `level` field so `sum by (level)` groups the way the
// read path labels entries. It does NOT include the unpack pipes — the caller
// adds only the ones the query does not already have.
func (m *MappingOptions) levelNormalizePipes() []string {
	if !m.derivesLevel() || !m.MaterializeLevel {
		return nil
	}
	var pipes []string
	// VictoriaLogs has no `coalesce` pipe, so first-non-empty-wins is built from
	// `| format if (<field>:*)` stages applied from the LOWEST priority field to
	// the highest: each matching stage overwrites `level`, so the last one to run
	// — the highest-priority field that is present — is the value that survives.
	for i := len(m.DerivedLevelFields) - 1; i >= 0; i-- {
		field := m.DerivedLevelFields[i]
		quoted := quoteVLField(field)
		// `level` itself stays in the chain: dropping it would let a
		// lower-priority field overwrite a level that was already present.
		pipes = append(pipes, "| format if ("+quoted+":*) \"<"+field+">\" as level")
	}
	// Loki derives the level from the LINE TEXT when no named field carries a
	// RECOGNISED value, and the logs path already does — the stats path did not,
	// so `sum by (detected_level) (...)` lost every entry whose only evidence was
	// the word in the message. One conditional extraction puts both paths on the
	// same rule; the capture takes the FIRST keyword in the line, which is Loki's
	// tie-break too.
	//
	// The guard is the absence of a RECOGNISED value, not of any value: a field
	// holding `custom` is no level at all to Loki, and guarding on `level:*` would
	// let it suppress the heuristic and group the entry under `custom`.
	if m.InferLevelFromText {
		pipes = append(pipes, "| extract_regexp if ("+
			buildFieldFilterStr("level", logsql.FieldOpRegexp, anyLevelValuePattern(), true)+") "+
			strconv.Quote(lokiTextLevelCapturePattern)+" from _msg")
	}
	if m.InferLevelFromText {
		// Loki's OWN canonical set for `detected_level`, measured on 3.7.1: it keeps
		// `trace` distinct from `debug` and `critical`/`fatal` distinct from
		// `error`, and labels anything it cannot place `unknown` rather than
		// leaving the label empty. The repo's synonym table folds all of those
		// together, which is right for a STORED level (that mapping predates this
		// and other paths depend on it) but wrong for the one Loki derives.
		for _, r := range lokiDetectedLevelReplacements {
			pipes = append(pipes, logsql.PipeReplaceRegexp{
				Field:       "level",
				Regex:       "(?i)^(" + r.alternation + ")$",
				Replacement: r.canonical,
			}.String())
		}
		// An entry Loki cannot place is `unknown`, not an empty label.
		pipes = append(pipes, `| format if (level:"") "unknown" as level`)
		return pipes
	}
	for _, canonical := range []string{"error", "warn", "info", "debug"} {
		pipes = append(pipes, logsql.PipeReplaceRegexp{
			Field:       "level",
			Regex:       levelValuePattern(canonical),
			Replacement: canonical,
		}.String())
	}
	return pipes
}

// lokiDetectedLevelReplacements is Loki's canonical `detected_level` mapping, in
// the order the stages run. `trace` and `critical`/`fatal` come FIRST: a later
// stage rewrites what an earlier one produced, and the repo's `debug` synonyms
// would otherwise swallow `trace`.
var lokiDetectedLevelReplacements = []struct{ canonical, alternation string }{
	{"trace", "trace"},
	{"critical", "critical|crit"},
	{"fatal", "fatal"},
	{"error", "err|error|errors|emerg|panic|alert"},
	{"warn", "warn|warning|warnings"},
	{"info", "info|information|informational|notice"},
	{"debug", "debug|fine|verbose"},
}

// groupingLabelFn wraps a label translation function so labels materialised by
// chainCoalescePipes are left alone: they name a field this query creates.
func (m *MappingOptions) groupingLabelFn(labelFn LabelTranslateFunc) LabelTranslateFunc {
	if m == nil || len(m.MaterializeChainLabels) == 0 {
		return labelFn
	}
	keep := make(map[string]struct{}, len(m.MaterializeChainLabels))
	for _, l := range m.MaterializeChainLabels {
		keep[l] = struct{}{}
	}
	return func(label string) string {
		if _, ok := keep[label]; ok {
			return label
		}
		if labelFn == nil {
			return label
		}
		return labelFn(label)
	}
}

// chainCoalescePipes materialises each grouped fallback-chain label into a real
// VL field, so `| stats by (<label>)` has something to group on.
//
// Same first-non-empty-wins construction as levelNormalizePipes: VictoriaLogs
// has no coalesce pipe, so the `| format if (<field>:*)` stages run from the
// LOWEST priority field to the highest and each present one overwrites, leaving
// the highest-priority present field as the value.
func (m *MappingOptions) chainCoalescePipes() []string {
	if m == nil || len(m.MaterializeChainLabels) == 0 {
		return nil
	}
	var pipes []string
	for _, label := range m.MaterializeChainLabels {
		chain := m.expand(label)
		if len(chain) < 2 {
			continue
		}
		for i := len(chain) - 1; i >= 0; i-- {
			quoted := quoteVLField(chain[i])
			pipes = append(pipes, "| format if ("+quoted+":*) \"<"+chain[i]+">\" as "+label)
		}
	}
	return pipes
}

// splitComputedValue splits a computed label value into one value per joined
// label. The last component absorbs any remaining separators, so
// job="ns/team/app" with join [namespace, app] yields ["ns", "team/app"].
func splitComputedValue(value string, spec ComputedLabel) []string {
	return strings.SplitN(value, spec.Separator(), len(spec.Join))
}

// hasFallbackChain reports whether the matcher's Loki label is backed by a
// multi-field fallback chain, in which case it can never be served by a VL
// native stream selector.
func hasFallbackChain(matcher string, mapping *MappingOptions) bool {
	label, _, _, ok := splitStreamMatcher(matcher)
	if !ok {
		return false
	}
	if _, isComputed := mapping.computedFor(label); isComputed {
		return true
	}
	return len(mapping.expand(label)) > 0
}

// splitStreamMatcher splits `label<op>"value"` into its parts.
func splitStreamMatcher(matcher string) (label, opStr, value string, ok bool) {
	matcher = strings.TrimSpace(matcher)
	for _, op := range streamMatcherOps {
		idx := strings.Index(matcher, op.logql)
		if idx > 0 {
			label = sanitizeFieldIdentifier(matcher[:idx])
			value = strings.Trim(strings.TrimSpace(matcher[idx+len(op.logql):]), "\"`")
			return label, op.logql, value, label != ""
		}
	}
	return "", "", "", false
}

// computedMatcherToFieldFilter expands a matcher on a computed label such as
// job="<namespace>/<app>" into the conjunction (or, when negated, the
// disjunction of negations) of the underlying label matchers.
//
// Regex operators are rejected with a 400-mapped ParseError: the joined value is
// not stored anywhere, so a regexp over it cannot be split into per-label
// regexps without changing semantics.
func computedMatcherToFieldFilter(matcher string, labelFn LabelTranslateFunc, mapping *MappingOptions) (bool, string, error) {
	label, opStr, value, ok := splitStreamMatcher(matcher)
	if !ok {
		return false, "", nil
	}
	spec, isComputed := mapping.computedFor(label)
	if !isComputed {
		return false, "", nil
	}
	if opStr == "=~" || opStr == "!~" {
		return true, "", &ParseError{Msg: fmt.Sprintf(
			"computed label %q supports only = and != — it is joined from %s at query time and has no stored value to match a regexp against; match the joined labels individually instead",
			label, strings.Join(spec.Join, "+")), Pos: -1}
	}
	negate := opStr == "!="
	values := splitComputedValue(value, spec)
	if len(values) != len(spec.Join) {
		// Emitting only the leading matchers would MATCH MORE than asked
		// ({job="ns"} would return every app in ns), while Loki returns nothing.
		return true, "", &ParseError{Msg: fmt.Sprintf(
			"computed label %q expects %d components separated by %q (joined from %s), got %q",
			label, len(spec.Join), spec.Separator(), strings.Join(spec.Join, "+"), value), Pos: -1}
	}
	parts := make([]string, 0, len(spec.Join))
	for i, joined := range spec.Join {
		if i >= len(values) {
			break
		}
		sub := fmt.Sprintf("%s=%q", joined, values[i])
		if negate {
			sub = fmt.Sprintf("%s!=%q", joined, values[i])
		}
		ff := streamMatcherToFieldFilter(sub, labelFn, mapping)
		if ff == "" {
			continue
		}
		parts = append(parts, ff)
	}
	if len(parts) == 0 {
		return true, "", nil
	}
	if len(parts) == 1 {
		return true, parts[0], nil
	}
	if negate {
		// De Morgan: NOT (a AND b) == (NOT a) OR (NOT b).
		return true, "(" + strings.Join(parts, " OR ") + ")", nil
	}
	return true, "(" + strings.Join(parts, " ") + ")", nil
}

// derivedLevelMatcherFilter converts {level="error"} / {detected_level=~"..."}
// into a filter over the configured raw level fields. The second return value
// reports whether the matcher was consumed; the caller injects the unpack pipes.
func derivedLevelMatcherFilter(matcher string, mapping *MappingOptions) (string, bool) {
	label, opStr, value, ok := splitStreamMatcher(matcher)
	if !ok || !mapping.isDerivedLevelLabel(label) {
		return "", false
	}
	if value == "" {
		// level="" keeps upstream's "no level at all" semantics.
		return "", false
	}
	negate := opStr == "!=" || opStr == "!~"
	isRe := opStr == "=~" || opStr == "!~"
	return mapping.derivedLevelFilter(value, negate, isRe), true
}

// stageIsDerivedLevelFilter reports whether a pipeline label-filter stage
// targets the derived level label.
func stageIsDerivedLevelFilter(stage string, mapping *MappingOptions) bool {
	if !mapping.derivesLevel() {
		return false
	}
	for _, entry := range logqlSingleFilterOps {
		if idx := strings.Index(stage, entry.logql); idx > 0 {
			return mapping.isDerivedLevelLabel(sanitizeFieldIdentifier(stage[:idx]))
		}
	}
	return false
}

// unpackPipeName returns the bare pipe name of an unpack pipe string, so a query
// that already carries `| unpack_json` is recognised as having it even though
// levelUnpackPipes emits the explicit `| unpack_json from _msg` form.
func unpackPipeName(pipe string) string {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(pipe), "|"))
	if idx := strings.Index(name, " "); idx > 0 {
		name = name[:idx]
	}
	return name
}

// hasPipeStage reports whether any already-emitted part is a pipe stage with the
// given name. Unlike a substring search over the joined query it cannot be
// fooled by a line filter whose VALUE happens to contain the stage text.
func hasPipeStage(parts []string, name string) bool {
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "|") {
			continue
		}
		if unpackPipeName(part) == name {
			return true
		}
	}
	return false
}

// hasExactStage reports whether an identical pipe stage was already emitted.
func hasExactStage(parts []string, stage string) bool {
	for _, part := range parts {
		if strings.TrimSpace(part) == stage {
			return true
		}
	}
	return false
}
