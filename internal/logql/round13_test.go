package logql

import (
	"strings"
	"testing"
	"time"
)

// Round 13, N2 (logs form): the parser re-assembles a label-filter stage from
// tokens, and a double-quoted string token was wrapped in bare quotes with its
// UNESCAPED value — `"\\d{4}"` in the LogQL became `"\d{4}"` in the stage text,
// which the evaluator's readQuoted unescaped a second time into `d{4}`.
// `{…} | json | message=~"\\d{4}-…" | line_format …` then kept 0 of Loki's
// 1000 rows while the backtick form kept every one.
func TestRound13_DoubleQuotedRegexpLabelFilterSurvivesReassembly(t *testing.T) {
	for _, q := range []string{
		"{a=\"b\"} | json | message=~\"\\\\d{4} WARN\" | line_format \"{{.message}}\"",
		"{a=\"b\"} | json | message=~`\\d{4} WARN` | line_format \"{{.message}}\"",
	} {
		expr, err := Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		lq := expr.(*LogQuery)
		var raw string
		for _, s := range lq.Pipeline {
			if lf, ok := s.(*LabelFilterStage); ok {
				raw = lf.Raw
			}
		}
		if strings.Contains(raw, `"\d`) {
			t.Fatalf("%s: stage text lost the escape: %q", q, raw)
		}
		p, err := NewPipeline(lq.Pipeline)
		if err != nil {
			t.Fatal(err)
		}
		e := &Entry{TS: time.Now(), Line: `{"message":"2026 WARN"}`, Labels: map[string]string{}}
		if !p.Process(e) {
			t.Fatalf("%s: the matching row was dropped", q)
		}
	}
	// The reassembled text is a valid LogQL literal: parsing it again yields
	// the same stage, and an escaped quote or backslash survives the trip.
	got := quoteLogQLString(`a"b\c` + "\n")
	if got != `"a\"b\\c\n"` {
		t.Fatalf("quoteLogQLString = %s", got)
	}
}

// Round 13, class J: the collector split the JSON line into fields and left
// the message text in _msg. Loki, holding the whole line, parses it, so
// `| json | __error__ != ""` matched nothing there — and EVERY line here
// (26017 of 26017). An entry flagged SplitJSON records no JSONParserErr; a
// plain-text line still does.
func TestRound13_JSONStageOnCollectorSplitLineIsNotAnError(t *testing.T) {
	expr, err := Parse(`{a="b"} | json | __error__ != ""`)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPipeline(expr.(*LogQuery).Pipeline)
	if err != nil {
		t.Fatal(err)
	}
	split := &Entry{TS: time.Now(), Line: "Save mutation: done", Labels: map[string]string{"Category": "Mailings"}, SplitJSON: true}
	if p.Process(split) {
		t.Fatalf("a collector-split line must not carry __error__: %v", split.Labels)
	}
	plain := &Entry{TS: time.Now(), Line: "Save mutation: done", Labels: map[string]string{}}
	if !p.Process(plain) || plain.Labels[errorLabel] != "JSONParserErr" {
		t.Fatalf("a plain-text line is still a parser error: %v", plain.Labels)
	}
}
