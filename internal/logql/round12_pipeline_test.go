package logql

import (
	"reflect"
	"testing"
)

// Round 12, class E: Loki's `| pattern` is not a regexp. Each capture runs
// up to the FIRST occurrence of the literal after it, and a mismatch stops the
// walk keeping what was captured so far — a capture whose following literal is
// absent takes the rest of the line. Measured against Loki 3.7.1 on the nexus
// lifecycle logs: `Launch Task 'X' #81799` against `<task>;<_>;<project>;<_>`
// yields task="Launch Task 'X' #81799" and no project.
func TestPattern_LokiPartialMatchSemantics(t *testing.T) {
	cases := []struct {
		pattern, line string
		want          map[string]string
	}{
		{"<task>;<_>;<project>;<_>", `ProjectShutdownTask;2026-09-10T20:59:05Z;lendswap;"Job defined"`,
			map[string]string{"task": "ProjectShutdownTask", "project": "lendswap"}},
		{"<task>;<_>;<project>;<_>", "Launch Task 'X' #81799",
			map[string]string{"task": "Launch Task 'X' #81799"}},
		{"<task>;<_>;<project>;<_>", "a;b",
			map[string]string{"task": "a"}},
		// A leading literal must be a prefix: no captures otherwise.
		{"GET <path> <_>", "POST /x 200", map[string]string{}},
		{"GET <path> <_>", "GET /x 200", map[string]string{"path": "/x"}},
		// A trailing literal that is missing still hands the rest to the capture.
		{"<a> done", "work done", map[string]string{"a": "work"}},
		{"<a> done", "work", map[string]string{"a": "work"}},
		// The FIRST occurrence of the literal bounds the capture, and a
		// trailing capture takes everything left.
		{"<a>-<b>", "x-y-z", map[string]string{"a": "x", "b": "y-z"}},
		{`<_>method '<method>' request handler called<_>`, `2026 method 'GET' request handler called ok`,
			map[string]string{"method": "GET"}},
	}
	for _, tc := range cases {
		m, err := compilePattern(tc.pattern)
		if err != nil {
			t.Fatalf("%q: %v", tc.pattern, err)
		}
		got := map[string]string{}
		m.match(tc.line, got)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("pattern %q line %q: got %v want %v", tc.pattern, tc.line, got, tc.want)
		}
	}
	for _, bad := range []string{"no captures", "<a><b>"} {
		if _, err := compilePattern(bad); err == nil {
			t.Errorf("%q must be rejected as Loki rejects it", bad)
		}
	}

	// Through the pipeline: the partial capture is a real label.
	p, err := NewPipeline([]Stage{&ParserStage{Type: ParserPattern, Param: "<task>;<_>;<project>;<_>"}})
	if err != nil {
		t.Fatal(err)
	}
	e := &Entry{Line: "Launch Task 'X' #81799", Labels: map[string]string{"app": "nexus"}}
	if !p.Process(e) || e.Labels["task"] != "Launch Task 'X' #81799" || e.Labels["project"] != "" {
		t.Fatalf("labels %v", e.Labels)
	}
}

// Round 12, class A, proxy-side half: the pushed-down LogsQL already reads the
// configured fields, so the re-run of the line filter on the fetched rows must
// read them too, or a row VictoriaLogs matched in `Scopes` is dropped here.
func TestPipeline_LineFilterReadsConfiguredFields(t *testing.T) {
	p, err := NewPipeline([]Stage{
		&LineFilterStage{Op: LineFilterContains, Value: "needle"},
		&LineFilterStage{Op: LineFilterExcludes, Value: "poison"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.LineFilterFields = []string{"_msg", "Scopes", "State.*"}
	keep := func(labels map[string]string, line string) bool {
		return p.Process(&Entry{Line: line, Labels: labels})
	}
	if !keep(map[string]string{"Scopes": "[needle]"}, "plain") {
		t.Error("a match in a configured field must keep the row")
	}
	if !keep(map[string]string{"State_Foo": "needle"}, "plain") {
		t.Error("the wildcard prefix must match the sanitised label spelling")
	}
	if keep(map[string]string{"Category": "needle"}, "plain") {
		t.Error("an unconfigured field must not match")
	}
	if keep(map[string]string{"Scopes": "poison"}, "needle here") {
		t.Error("a negative filter drops a row matching in any configured field")
	}
	p.LineFilterFields = nil
	if keep(map[string]string{"Scopes": "[needle]"}, "plain") {
		t.Error("without configured fields only the line is read")
	}
}
