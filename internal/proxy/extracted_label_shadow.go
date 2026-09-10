package proxy

import (
	"strings"
)

// LogQL gives an EXISTING stream label priority over one a parser extracts: a
// `| json` that finds a `namespace` field in the body does not overwrite the
// stream's `namespace`, it exposes the parsed value as `namespace_extracted`.
//
// VictoriaLogs has no such rule — `| unpack_json` writes the body's field over
// whatever the row carried — so `sum by (namespace) (count_over_time({namespace=
// "flux-system"}[1h]))` came back as 39 series (one per RECONCILED namespace in
// the log bodies) instead of one. guardExtractedLabelShadowing restores Loki's
// rule inside the pushed-down query: snapshot each grouped label before the
// parser, and put the snapshot back afterwards.
//
// A label the row did NOT carry keeps the extracted value, which is also Loki's
// behaviour: with no stream label to collide with, the parsed one is the label.
const shadowSnapshotPrefix = "__lvp_pre_"

var logsqlParserStages = []string{"| unpack_json", "| unpack_logfmt", "| extract_regexp", "| extract "}

// guardExtractedLabelShadowing rewrites a translated stats query so that the
// labels its `| stats by (...)` clause groups on survive a parser stage.
// Queries without a parser stage, or without a stats clause after it, are
// returned unchanged.
func (p *Proxy) guardExtractedLabelShadowing(logsqlQuery string) string {
	scanned := stripQuotedSpans(logsqlQuery)
	parserIdx := -1
	for _, stage := range logsqlParserStages {
		if i := strings.Index(scanned, stage); i >= 0 && (parserIdx < 0 || i < parserIdx) {
			parserIdx = i
		}
	}
	if parserIdx < 0 {
		return logsqlQuery
	}
	statsIdx := strings.Index(scanned, "| stats ")
	if statsIdx < 0 || statsIdx < parserIdx {
		return logsqlQuery
	}

	spec, ok := parseStatsCompatSpec(logsqlQuery)
	if !ok {
		return logsqlQuery
	}

	// The parser can only shadow a BARE field name. A mapped VictoriaLogs field
	// (`kubernetes.pod_namespace`) is dotted and quoted in the query, and no JSON
	// body field is named like that.
	var protect []string
	seen := map[string]bool{}
	for _, label := range spec.GroupBy {
		label = strings.Trim(strings.TrimSpace(label), `"`)
		if label == "" || seen[label] || strings.ContainsAny(label, `."'`) ||
			strings.HasPrefix(label, "__lvp_") || label == "_stream" || label == "_time" {
			continue
		}
		if base, isExtracted := strings.CutSuffix(label, "_extracted"); isExtracted && base != "" {
			// Grouping by `<label>_extracted` needs the BASE label protected —
			// that is where the parsed value lands.
			if !seen[base] {
				seen[base] = true
				protect = append(protect, base)
			}
			continue
		}
		seen[label] = true
		protect = append(protect, label)
	}
	if len(protect) == 0 {
		return logsqlQuery
	}

	var snapshot, restore strings.Builder
	for _, label := range protect {
		tmp := shadowSnapshotPrefix + label
		// The stream value can sit in the row under the label's own name
		// (Loki-push data) or under the VictoriaLogs field it is mapped from.
		// Lowest priority first, so the last write wins — the same order the
		// mapping's coalesce chain uses.
		snapshot.WriteString(` | format "<` + label + `>" as ` + tmp)
		chain := p.labelTranslator.ToVLFields(label)
		for i := len(chain) - 1; i >= 0; i-- {
			if chain[i] == label {
				continue
			}
			snapshot.WriteString(` | format if (` + quoteLogsQLIdent(chain[i]) + `:*) "<` + chain[i] + `>" as ` + tmp)
		}
		// `<label>_extracted` is Loki's name for the value the parser found; it
		// is only worth materialising when the query asks for it.
		if strings.Contains(scanned, label+"_extracted") {
			restore.WriteString(` | format if (` + tmp + `:*) "<` + label + `>" as ` + label + `_extracted`)
		}
		restore.WriteString(` | format if (` + tmp + `:*) "<` + tmp + `>" as ` + label)
	}

	// Find the END of the parser stage — the next pipe, or the stats clause.
	parserEnd := strings.Index(scanned[parserIdx+1:], "|")
	if parserEnd < 0 {
		return logsqlQuery
	}
	parserEnd += parserIdx + 1

	return logsqlQuery[:parserIdx] + snapshot.String() + " " +
		strings.TrimSpace(logsqlQuery[parserIdx:parserEnd]) + restore.String() + " " +
		strings.TrimSpace(logsqlQuery[parserEnd:])
}
