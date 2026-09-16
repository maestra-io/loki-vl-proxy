package logql

import (
	"testing"
	"time"
)

func round14Pipeline(t *testing.T, query string) *Pipeline {
	t.Helper()
	expr, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse(%q): %v", query, err)
	}
	lq, ok := expr.(*LogQuery)
	if !ok {
		t.Fatalf("expected a log query, got %T", expr)
	}
	p, err := NewPipeline(lq.Pipeline)
	if err != nil {
		t.Fatalf("NewPipeline(%q): %v", query, err)
	}
	p.DerivedLevelFields = []string{"loglevel", "LogLevel", "level", "Level", "severity", "severity_text", "lvl"}
	return p
}

func round14Entry() *Entry {
	return &Entry{
		TS: time.Unix(1789041600, 0).UTC(), Line: "Reconciler error", SplitJSON: true,
		Labels: map[string]string{"namespace": "flux-system", "level": "error", "controller": "helmrelease"},
	}
}

// Round 14, E004 on the proxy's own evaluator: a row whose JSON the collector
// split carries the stored `level`. After `| logfmt` (which reads only the
// line, "Reconciler error") Loki has no `level`, so `| level="error"` drops
// the line; after `| json` the split-out field IS the parsed one and the
// line passes; a genuine logfmt line re-extracts its level after the drop.
func TestRound14_ParserDropsStoredLevelBeforeFilter(t *testing.T) {
	if round14Pipeline(t, `{namespace="flux-system"} | logfmt | level="error"`).Process(round14Entry()) {
		t.Fatal("| logfmt | level=\"error\" must not match a split-JSON row via its stored level")
	}
	if !round14Pipeline(t, `{namespace="flux-system"} | json | level="error"`).Process(round14Entry()) {
		t.Fatal("| json | level=\"error\" must read the split-out level")
	}
	e := round14Entry()
	e.Line = `level=error msg="disk full"`
	e.SplitJSON = false
	delete(e.Labels, "level")
	if !round14Pipeline(t, `{namespace="flux-system"} | logfmt | level="error"`).Process(e) {
		t.Fatal("a real logfmt line keeps its parsed level")
	}
	// Without the proxy's derived-level configuration `level` is a stored
	// (stream) label, as upstream has it, and the parser leaves it alone.
	p := round14Pipeline(t, `{namespace="flux-system"} | logfmt | level="error"`)
	p.DerivedLevelFields = nil
	if !p.Process(round14Entry()) {
		t.Fatal("upstream mode: the stored level is a stream label and stays")
	}
}
