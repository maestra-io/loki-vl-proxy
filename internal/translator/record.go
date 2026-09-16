package translator

import (
	"regexp"
	"strconv"
	"strings"
)

// Loki stored the line the collector shipped, not the message: the vector
// http_server wrapper — every non-stream field of the record JSON-encoded,
// `_msg` under `message`, plus `path`, `source_type` and a nine-digit
// `timestamp`. VictoriaLogs holds the same fields split out. The pipes below
// re-derive the stored line's size on VictoriaLogs' side, for
// `bytes_over_time` (-bytes-over-time-source=record) and for Loki's
// ingest-time line-size rejection (-loki-max-line-size). The Go-side count
// for rows the proxy scans itself lives in proxy/loki_record.go; the two were
// measured byte-exact against Loki on flux-operator (555/545), spark (130)
// and nexus (480) rows on 16.09.2026.

// RecordWrapperBytes is what the wrapper adds on top of the packed fields:
// `"message"` in place of `"_msg"` (+3),
// `,"path":"/","source_type":"http_server","timestamp":"<30 chars>"` (+84),
// and the brace/comma the pack_json difference does not count (+1).
const RecordWrapperBytes = 88

// RecordBytesField is the LogsQL field the pipe chain leaves behind.
const RecordBytesField = "__lvp_bytes"

// RecordInternalFields are the VL fields pack_json emits that never reached
// the Loki line.
var RecordInternalFields = []string{"_time", "_stream", "_stream_id"}

// RecordBytesPipes returns the LogsQL pipes that compute the Loki line size
// of every row into __lvp_bytes without touching any other field: pack the
// whole row, pack the fields the wrapper never carried, take the difference;
// a row whose _msg is itself the JSON line (the collector lifted nothing) was
// stored as that line, so its size is len(_msg). Grouping by the excluded
// fields afterwards keeps working.
func RecordBytesPipes(exclude []string) string {
	x := append(append([]string(nil), RecordInternalFields...), exclude...)
	return "| pack_json as __lvp_l | pack_json fields (" + strings.Join(x, ", ") + ") as __lvp_x" +
		" | len(__lvp_l) as __lvp_a | len(__lvp_x) as __lvp_b" +
		" | math __lvp_a - __lvp_b + " + strconv.Itoa(RecordWrapperBytes) + " as " + RecordBytesField +
		// A row whose _msg IS the JSON line (nothing lifted) was stored as
		// that line: its size is len(_msg), not the wrapper.
		" | len(_msg) as __lvp_m | format if (_msg:~\"^[{]\") \"<__lvp_m>\" as " + RecordBytesField +
		" | delete __lvp_l, __lvp_x, __lvp_a, __lvp_b, __lvp_m"
}

// recordPipes returns the pipes a metric translation appends to its log
// query, and whether bytes functions must sum RecordBytesField instead of
// sum_len(_msg). Loki's max_line_size drop applies only where VictoriaLogs
// already does per-row work — a line filter or a parser — so a bare stream
// count stays a cheap block-level count.
// ponytail: the size filter is a pack_json per matched row; a bare
// count_over_time over a whole namespace would pay it on every row for a
// handful of oversized lines nobody counts.
func (m *MappingOptions) recordPipes(isBytes bool, logql string) (pipes string, bytesField bool) {
	if m == nil {
		return "", false
	}
	bytesOn := isBytes && m.BytesSource == "record"
	sizeOn := m.LokiMaxLineSize > 0 && queryScansRows(logql)
	if !bytesOn && !sizeOn {
		return "", false
	}
	pipes = RecordBytesPipes(m.RecordExcludeFields)
	if sizeOn {
		pipes += " | filter " + RecordBytesField + ":<=" + strconv.Itoa(m.LokiMaxLineSize)
	}
	if !bytesOn {
		pipes += " | delete " + RecordBytesField
	}
	return pipes, bytesOn
}

// RecordPipes is recordPipes for callers outside the package.
func (m *MappingOptions) RecordPipes(isBytes bool, logql string) (string, bool) {
	return m.recordPipes(isBytes, logql)
}

var rowScanRE = regexp.MustCompile(`\|=|\|~|!~|\|>|!>|!=\s*"|!=\s*` + "`" + `|\|\s*(json|logfmt|pattern|regexp|unpack)\b`)

// queryScansRows reports whether the log query carries a line filter, a
// label filter or a parser — anything VictoriaLogs evaluates per row.
func queryScansRows(logql string) bool {
	q := strings.TrimSpace(logql)
	if strings.HasPrefix(q, "{") {
		if end := strings.Index(q, "}"); end >= 0 {
			q = q[end+1:]
		}
	}
	return rowScanRE.MatchString(q)
}
