package proxy

import (
	"regexp"
	"strings"

	fj "github.com/valyala/fastjson"
)

// labelPromotion describes one Loki label lifted into the stream `labels` object
// of a query result.
//
// Grafana panels do `sum by (app)` and `| label_format` on labels that Loki
// would have carried as stream labels. When the backing VL field is not part of
// VL's stream index the proxy would only ever expose it as structured metadata,
// which those panels cannot see — so mapped and computed labels are promoted
// into the stream label set as well.
type labelPromotion struct {
	label  string   // Loki label name
	fields []string // ordered VL field chain (mapped labels)
	join   []string // Loki labels to concatenate (computed labels)
	sep    string   // separator for join
}

// buildLabelPromotions derives the promotion list from the configured mappings.
func buildLabelPromotions(lt *LabelTranslator, computed []ComputedLabel) []labelPromotion {
	var out []labelPromotion
	if lt != nil {
		for _, field := range lt.mappedFields {
			label := lt.vlToLoki[field]
			if label == "" {
				continue
			}
			already := false
			for _, p := range out {
				if p.label == label {
					already = true
					break
				}
			}
			if already {
				continue
			}
			chain := lt.ToVLFields(label)
			if len(chain) == 0 {
				continue
			}
			out = append(out, labelPromotion{label: label, fields: chain})
		}
	}
	for _, c := range computed {
		if c.Valid() {
			out = append(out, labelPromotion{label: c.LokiLabel, join: c.Join, sep: c.Separator()})
		}
	}
	return out
}

// applyLabelPromotions writes promoted labels into labels, reading VL field
// values through get. It returns true when it changed the map.
//
// Mapped labels resolve to the FIRST non-empty field of their chain, mirroring
// the LogsQL disjunction used on the query side. Computed labels are joined from
// labels already present (including labels promoted earlier in the list, so a
// computed label may depend on a mapped one).
func applyLabelPromotions(proms []labelPromotion, labels map[string]string, get func(string) string) bool {
	changed := false
	for _, prom := range proms {
		if strings.TrimSpace(labels[prom.label]) != "" {
			continue
		}
		var value string
		if len(prom.fields) > 0 {
			for _, field := range prom.fields {
				if v := strings.TrimSpace(get(field)); v != "" {
					value = v
					break
				}
			}
		} else {
			parts := make([]string, 0, len(prom.join))
			for _, src := range prom.join {
				v := strings.TrimSpace(labels[src])
				if v == "" {
					parts = nil
					break
				}
				parts = append(parts, v)
			}
			if len(parts) == len(prom.join) && len(parts) > 0 {
				value = strings.Join(parts, prom.sep)
			}
		}
		if value == "" {
			continue
		}
		labels[prom.label] = value
		changed = true
	}
	return changed
}

// withPromotedLabels returns the stream label set extended with promoted labels
// and a normalised level for this entry, plus its canonical key. The stream is
// re-keyed so entries differing only in a promoted label stay separate series.
// When nothing changes the input map and key are returned unchanged.
func (p *Proxy) withPromotedLabels(key string, labels map[string]string, msg string, rawLabels map[string]string, val *fj.Value) (string, map[string]string) {
	if p == nil || (len(p.labelPromotions) == 0 && len(p.derivedLevelFields) == 0) {
		return key, labels
	}
	extended := make(map[string]string, len(labels)+len(p.labelPromotions)+1)
	for k, v := range labels {
		extended[k] = v
	}
	applyLabelPromotions(p.labelPromotions, extended, fjFieldGetter(rawLabels, val))
	p.applyDerivedLevel(extended, msg)
	if sameStringMap(extended, labels) {
		return key, labels
	}
	return canonicalLabelsKey(extended), extended
}

// entryFieldGetter resolves a VL field name against the raw stream labels first
// and the decoded entry second.
func entryFieldGetter(rawLabels map[string]string, entry map[string]interface{}) func(string) string {
	return func(field string) string {
		if v, ok := rawLabels[field]; ok {
			return v
		}
		if v, ok := entry[field]; ok {
			if s, ok := stringifyEntryValue(v); ok {
				return s
			}
		}
		return ""
	}
}

// fjFieldGetter resolves a VL field name against the raw stream labels first and
// the fastjson-decoded entry second.
func fjFieldGetter(rawLabels map[string]string, val *fj.Value) func(string) string {
	return func(field string) string {
		if v, ok := rawLabels[field]; ok {
			return v
		}
		if val == nil {
			return ""
		}
		return string(val.GetStringBytes(field))
	}
}

// levelSubstringOrder is the substring fallback used when no structured level
// key is present in the message, matching the order the retired Vector
// aggregator used: the first match wins.
var levelSubstringOrder = []struct{ needle, level string }{
	{"debug", "debug"},
	{"warn", "warn"},
	{"error", "error"},
}

// normalizeLevelValue maps a raw level value onto Loki's canonical set.
// "information" → info, "warning" → warn, "err"/"fatal"/"critical" → error.
// Unknown values are lowercased and returned unchanged.
func normalizeLevelValue(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return ""
	case "info", "information", "informational", "notice":
		return "info"
	case "warn", "warning", "warnings":
		return "warn"
	case "error", "err", "errors", "fatal", "critical", "crit", "emerg", "panic", "alert":
		return "error"
	case "debug", "fine", "verbose":
		return "debug"
	case "trace":
		return "trace"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

// levelFromSubstring implements the substring fallback over a raw log line.
func levelFromSubstring(msg string) string {
	lower := strings.ToLower(msg)
	for _, c := range levelSubstringOrder {
		if strings.Contains(lower, c.needle) {
			return c.level
		}
	}
	return ""
}

// applyDerivedLevel normalises level/detected_level for a result entry when
// derived level is configured. It reproduces the ingest-time rule the retired
// Vector aggregator applied: a structured level key wins, otherwise the first
// of debug/warn/error found in the message body.
func (p *Proxy) applyDerivedLevel(labels map[string]string, msg string) {
	if p == nil || len(p.derivedLevelFields) == 0 || labels == nil {
		return
	}
	level := strings.TrimSpace(labels["level"])
	if level == "" {
		level = strings.TrimSpace(labels["detected_level"])
	}
	if level == "" {
		if v, ok := extractLevelFromMsg(msg); ok {
			level = v
		}
	}
	if level == "" {
		level = levelFromSubstring(msg)
	}
	if level == "" {
		return
	}
	normalized := normalizeLevelValue(level)
	labels["level"] = normalized
	labels["detected_level"] = normalized
}

// isMissingMsgPlaceholder matches VictoriaLogs' placeholder for records ingested
// without a _msg field ("missing _msg field; see https://docs.victoriametrics.com/…").
// Such a record has no original message, so the JSON reconstruction of the
// remaining fields is the only useful line.
func isMissingMsgPlaceholder(msg string) bool {
	return strings.TrimSpace(msg) == "" || strings.HasPrefix(msg, "missing _msg field")
}

// lineFieldSkip reports whether the log line should be returned verbatim from
// _msg instead of being reconstructed as a JSON object of the whole VL record.
// querySkip carries the upstream decision (a text-extraction parser in the query).
func (p *Proxy) lineFieldSkip(msg string, querySkip bool) bool {
	if querySkip {
		return true
	}
	if p == nil || !p.lineFieldMsg {
		return false
	}
	return !isMissingMsgPlaceholder(msg)
}

// sameStringMap reports whether two label maps hold identical entries.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// namedCaptureRE matches the named capture groups of a LogQL `| regexp` stage
// and the `<field>` placeholders of a `| pattern` stage.
var namedCaptureRE = regexp.MustCompile(`\(\?P?<([A-Za-z_][A-Za-z0-9_]*)>|<([A-Za-z_][A-Za-z0-9_]*)>`)

// namedCaptureFields returns the field names a `| regexp` or `| pattern` stage
// extracts. Those fields exist only after the query-time parser runs, so nothing
// in the log body identifies them — the response classifier needs the list to
// expose them as parsed labels rather than as structured metadata.
func namedCaptureFields(query string) map[string]struct{} {
	if !strings.Contains(query, "regexp") && !strings.Contains(query, "pattern") {
		return nil
	}
	var out map[string]struct{}
	for _, m := range namedCaptureRE.FindAllStringSubmatch(query, -1) {
		name := m[1]
		if name == "" {
			name = m[2]
		}
		if name == "" || name == "_" {
			continue
		}
		if out == nil {
			out = make(map[string]struct{}, 4)
		}
		out[name] = struct{}{}
	}
	return out
}
