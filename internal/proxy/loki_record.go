package proxy

import (
	"hash/maphash"
	"strings"

	fj "github.com/valyala/fastjson"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/translator"
)

// Loki stored the line the collector shipped, not the message: the vector
// http_server wrapper — every non-stream field of the record JSON-encoded
// with sorted keys, `_msg` under `message`, plus `path`, `source_type` and a
// nine-digit `timestamp`. VictoriaLogs holds the same fields split out, so a
// byte count (`bytes_over_time`) or Loki's ingest-time line-size limit needs
// the line re-assembled. The Go-side count (raw-row paths) and the LogsQL
// pipe chain (native stats paths) live together here so they agree; both
// were measured byte-exact against Loki on flux-operator (555/545), spark
// (130) and nexus (480) rows on 16.09.2026.

// lokiRecordWrapperBytes is translator.RecordWrapperBytes: `"message"` in
// place of `"_msg"` (+3), `,"path":"/","source_type":"http_server",
// "timestamp":"<30 chars>"` (+84), and the brace/comma the pack_json
// difference does not count (+1).
const lokiRecordWrapperBytes = translator.RecordWrapperBytes

// recordFieldExcluded reports whether a VL field is outside the Loki line:
// a VL internal or one of the configured exclusions (`kubernetes.*`).
func recordFieldExcluded(key string, exclude []string) bool {
	switch key {
	case "_time", "_stream", "_stream_id":
		return true
	}
	for _, pat := range exclude {
		if strings.HasSuffix(pat, "*") {
			if strings.HasPrefix(key, pat[:len(pat)-1]) {
				return true
			}
		} else if key == pat {
			return true
		}
	}
	return false
}

// jsonQuotedLen is len(json-encoded s) as vector (serde_json) writes it: the
// two quotes, short escapes for \" \\ \n \r \t \b \f, \u00XX for the other
// control bytes, everything else verbatim.
func jsonQuotedLen(s string) int {
	n := 2
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f':
			n += 2
		case c < 0x20:
			n += 6
		default:
			n++
		}
	}
	return n
}

// msgIsJSONLine reports a row whose _msg is itself the JSON line: the
// collector lifted nothing, Loki stored that line as is.
func msgIsJSONLine(msg []byte) bool {
	return len(msg) > 0 && msg[0] == '{'
}

// lokiRecordLineLenFJ is the Loki line size of a VL row (fastjson form).
func lokiRecordLineLenFJ(v *fj.Value, exclude []string) int {
	if msg := v.GetStringBytes("_msg"); msgIsJSONLine(msg) {
		return len(msg)
	}
	obj, err := v.Object()
	if err != nil {
		return 0
	}
	n, count := 0, 0
	obj.Visit(func(k []byte, val *fj.Value) {
		key := string(k)
		if recordFieldExcluded(key, exclude) {
			return
		}
		sv, ok := stringifyFJValue(val)
		if !ok {
			return
		}
		count++
		n += recordFieldLen(key, sv)
	})
	return recordLineTotal(n, count)
}

// lokiRecordLineLenMap is lokiRecordLineLenFJ for the map-decoded row.
func lokiRecordLineLenMap(entry map[string]interface{}, exclude []string) int {
	if msg, _ := stringifyEntryValue(entry["_msg"]); msgIsJSONLine([]byte(msg)) {
		return len(msg)
	}
	n, count := 0, 0
	for key, val := range entry {
		if recordFieldExcluded(key, exclude) {
			continue
		}
		sv, ok := stringifyEntryValue(val)
		if !ok {
			continue
		}
		count++
		n += recordFieldLen(key, sv)
	}
	return recordLineTotal(n, count)
}

func recordFieldLen(key, value string) int {
	if key == "_msg" {
		key = "message"
	}
	return jsonQuotedLen(key) + 1 + jsonQuotedLen(value)
}

func recordLineTotal(fieldBytes, count int) int {
	if count == 0 {
		return 0
	}
	// braces + commas between fields + the wrapper minus the "_msg"→"message"
	// delta recordFieldLen already applied.
	return 2 + fieldBytes + (count - 1) + (lokiRecordWrapperBytes - 3 - 1)
}

// recordStatsPipes returns the pipes a proxy-built stats query appends to
// the translated log query (Loki-stored line bytes and/or Loki's
// max_line_size drop) and whether a bytes function sums __lvp_bytes.
func (p *Proxy) recordStatsPipes(isBytes bool, logql string) (string, bool) {
	if p == nil {
		return "", false
	}
	p.configMu.RLock()
	opts := p.buildMappingOptions(logql)
	p.configMu.RUnlock()
	return opts.RecordPipes(isBytes, logql)
}

// rowLineBytesFJ is the sample value of bytes_over_time / bytes_rate for a
// row: the stored line under -bytes-over-time-source=record, else len(_msg).
func (p *Proxy) rowLineBytesFJ(v *fj.Value) float64 {
	if p != nil && p.bytesSourceRecord {
		return float64(lokiRecordLineLenFJ(v, p.recordExcludeFields))
	}
	return float64(len(v.GetStringBytes("_msg")))
}

func (p *Proxy) rowLineBytesMap(entry map[string]interface{}, msg string) float64 {
	if p != nil && p.bytesSourceRecord {
		return float64(lokiRecordLineLenMap(entry, p.recordExcludeFields))
	}
	return float64(len(msg))
}

// rowOverMaxLineSize reports whether Loki would have rejected the row at
// ingest (-loki-max-line-size).
func (p *Proxy) rowOverMaxLineSizeFJ(v *fj.Value) bool {
	return p != nil && p.lokiMaxLineSize > 0 && lokiRecordLineLenFJ(v, p.recordExcludeFields) > p.lokiMaxLineSize
}

func (p *Proxy) rowOverMaxLineSizeMap(entry map[string]interface{}) bool {
	return p != nil && p.lokiMaxLineSize > 0 && lokiRecordLineLenMap(entry, p.recordExcludeFields) > p.lokiMaxLineSize
}

// rowDedup collapses rows with the same stream, timestamp and line, as Loki's
// ingester does (an exact duplicate of an entry already in the stream is
// dropped). The line is the whole stored record — every field, not `_msg`
// alone: two rows with one message but different fields were two Loki lines.
// One per scan; nil when -dedupe-exact-duplicates=false.
// ponytail: 64-bit maphash keys folded field by field (order-free), ~40 B per
// retained row; a hash collision drops a genuine line, at 2^-64 per pair
// that is accepted.
type rowDedup struct {
	seen map[uint64]struct{}
	h    maphash.Hash
}

func (p *Proxy) newRowDedup() *rowDedup {
	if p == nil || !p.dedupeExactDuplicates {
		return nil
	}
	d := &rowDedup{seen: make(map[uint64]struct{}, 256)}
	d.h.SetSeed(maphash.MakeSeed())
	return d
}

func (d *rowDedup) field(key, value []byte) uint64 {
	d.h.Reset()
	_, _ = d.h.Write(key)
	_ = d.h.WriteByte(0)
	_, _ = d.h.Write(value)
	return d.h.Sum64()
}

// record marks the folded key and reports whether it was already seen.
func (d *rowDedup) record(k uint64) bool {
	if _, ok := d.seen[k]; ok {
		return true
	}
	d.seen[k] = struct{}{}
	return false
}

func (d *rowDedup) dupFJ(v *fj.Value) bool {
	if d == nil {
		return false
	}
	obj, err := v.Object()
	if err != nil {
		return false
	}
	var k uint64
	obj.Visit(func(key []byte, val *fj.Value) {
		if string(key) == "_stream_id" {
			return
		}
		sv, ok := stringifyFJValue(val)
		if !ok {
			return
		}
		k += d.field(key, []byte(sv))
	})
	return d.record(k)
}

func (d *rowDedup) dupMap(entry map[string]interface{}) bool {
	if d == nil {
		return false
	}
	var k uint64
	for key, val := range entry {
		if key == "_stream_id" {
			continue
		}
		sv, ok := stringifyEntryValue(val)
		if !ok {
			continue
		}
		k += d.field([]byte(key), []byte(sv))
	}
	return d.record(k)
}
