package translator

import (
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

func round14Mapping() *MappingOptions {
	return &MappingOptions{
		DerivedLevelFields:  []string{"loglevel", "LogLevel", "level", "Level", "severity", "severity_text", "lvl"},
		BytesSource:         "record",
		RecordExcludeFields: []string{"kubernetes.*"},
	}
}

func round14Translate(t *testing.T, m *MappingOptions, logql string) string {
	t.Helper()
	out, err := TranslateLogQLWithMapping(logql, nil, nil, logsql.Capabilities{}, m)
	if err != nil {
		t.Fatalf("%s: %v", logql, err)
	}
	return out
}

// Round 14, E004: after a parser stage `level` is the PARSED field. Loki's
// logfmt/pattern/regexp read the line only, so the level the collector split
// out of a JSON line is not among their output and `| logfmt | level="error"`
// finds nothing on `{"level":"error","message":"Reconciler error"}` (Loki 0,
// proxy was 2). The stored level fields are dropped before such a parser and
// the filter reads the plain field; `| json` reads the split-out field, which
// IS the parsed one; without a parser the derived-level chain stays.
func TestRound14_LevelFilterAfterParserReadsParsedField(t *testing.T) {
	m := round14Mapping()
	logfmt := round14Translate(t, m, `{namespace="flux-system"} | decolorize | logfmt | level="error"`)
	if !strings.Contains(logfmt, `| decolorize | delete loglevel, LogLevel, level, Level, severity, severity_text, lvl | unpack_logfmt | filter level:="error"`) {
		t.Fatalf("logfmt: %s", logfmt)
	}
	if strings.Contains(logfmt, "keep_original_fields") || strings.Contains(logfmt, "(?i)") {
		t.Fatalf("logfmt must not carry the derived-level chain: %s", logfmt)
	}
	pattern := round14Translate(t, m, `{namespace="flux-system"} | pattern "<a> <_>" | level=~"error|fatal"`)
	if !strings.Contains(pattern, `| delete loglevel, LogLevel, level, Level, severity, severity_text, lvl | extract "<a> <_>" | filter level:~`) || strings.Contains(pattern, "(?i)^(err|") {
		t.Fatalf("pattern: %s", pattern)
	}
	jsonQ := round14Translate(t, m, `{namespace="flux-system"} | json | level="error"`)
	if !strings.HasSuffix(jsonQ, `| unpack_json | filter level:="error"`) || strings.Contains(jsonQ, "delete") {
		t.Fatalf("json: %s", jsonQ)
	}
	bare := round14Translate(t, m, `{namespace="flux-system"} | level="error"`)
	if !strings.Contains(bare, "unpack_json from _msg keep_original_fields") || !strings.Contains(bare, `level:~"(?i)^(err|error|errors|emerg|panic|alert)$"`) {
		t.Fatalf("no parser must keep the derived chain: %s", bare)
	}
	if detected := round14Translate(t, m, `{namespace="flux-system"} | logfmt | detected_level="error"`); !strings.Contains(detected, "(?i)^(err|") {
		t.Fatalf("detected_level is Loki's own label, not a parsed field: %s", detected)
	}
}

// Round 14, A021/A120: RecordBytesPipes is the byte-exact re-derivation of
// the Loki-stored line (measured 555/545/130/480 on 16.09.2026); bytes
// functions sum it, the max_line_size drop filters on it — and only for
// queries VictoriaLogs already evaluates per row.
func TestRound14_RecordPipes(t *testing.T) {
	m := round14Mapping()
	const pipes = "| pack_json as __lvp_l | pack_json fields (_time, _stream, _stream_id, kubernetes.*) as __lvp_x | len(__lvp_l) as __lvp_a | len(__lvp_x) as __lvp_b | math __lvp_a - __lvp_b + 88 as __lvp_bytes | delete __lvp_l, __lvp_x, __lvp_a, __lvp_b"
	if got := RecordBytesPipes([]string{"kubernetes.*"}); got != pipes {
		t.Fatalf("RecordBytesPipes = %s", got)
	}
	if got := round14Translate(t, m, `bytes_over_time({namespace="flux-system"}[1h])`); got != `"kubernetes.pod_namespace":="flux-system" `+pipes+` | stats sum(__lvp_bytes)` && got != `namespace:="flux-system" `+pipes+` | stats sum(__lvp_bytes)` {
		t.Fatalf("bytes_over_time: %s", got)
	}
	if got := round14Translate(t, m, `sum by (app) (bytes_rate({app="x"} |= "a" [5m]))`); !strings.Contains(got, pipes+" | stats by (app) sum(__lvp_bytes) as __lvp_inner") {
		t.Fatalf("bytes_rate: %s", got)
	}
	if got := round14Translate(t, m, `count_over_time({app="x"}[5m])`); strings.Contains(got, "pack_json") {
		t.Fatalf("count without a filter must not pay for the record: %s", got)
	}

	m.LokiMaxLineSize = 524288
	if got := round14Translate(t, m, `sum by (tenant_id) (count_over_time({product="tenant"} |= "Message size too large" | json [1m]))`); !strings.Contains(got, `| unpack_json `+pipes+` | filter __lvp_bytes:<=524288 | delete __lvp_bytes | stats by (tenant_id) count()`) {
		t.Fatalf("size filter on a scanning count: %s", got)
	}
	if got := round14Translate(t, m, `count_over_time({product="tenant"}[1m])`); strings.Contains(got, "pack_json") {
		t.Fatalf("bare stream count must skip the size filter: %s", got)
	}
	if got := round14Translate(t, m, `bytes_over_time({product="tenant"} | json [1m])`); !strings.Contains(got, pipes+` | filter __lvp_bytes:<=524288 | stats sum(__lvp_bytes)`) {
		t.Fatalf("bytes with the size filter keeps the field for the sum: %s", got)
	}

	m.BytesSource = "line"
	m.LokiMaxLineSize = 0
	if got := round14Translate(t, m, `bytes_over_time({namespace="flux-system"}[1h])`); !strings.HasSuffix(got, "| stats sum_len(_msg)") {
		t.Fatalf("line mode: %s", got)
	}
}
