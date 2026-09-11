package translator

import (
	"strings"
	"testing"
)

// `|=` and `!=` are SUBSTRING matches in LogQL, not regexps. Handing their value
// to LogsQL's `~` unescaped made every metacharacter live — measured against Loki
// 3.7.1 on an eight-line fixture: `|= "manifests."` returned 3 where Loki returned
// 1, `|= "a+b"` returned 0 where Loki returned 1, and `|= "\x1b"` matched a line
// Loki does not. Only `|~`/`!~` carry a pattern the user wrote as one.
func TestTranslate_PlainLineFilterIsASubstringNotARegexp(t *testing.T) {
	for _, tc := range []struct{ query, want string }{
		{`{ns="x"} |= "manifests."`, `ns:="x" ~"manifests\\."`},
		{`{ns="x"} |= "a+b"`, `ns:="x" ~"a\\+b"`},
		{`{ns="x"} != "a.b"`, `ns:="x" NOT ~"a\\.b"`},
		{`{ns="x"} |= "a" or "b.c"`, `ns:="x" (~"a" OR ~"b\\.c")`},
		// A real pattern is left alone.
		{`{ns="x"} |~ "a.b"`, `ns:="x" ~"a.b"`},
		{`{ns="x"} !~ "a.b"`, `ns:="x" NOT ~"a.b"`},
	} {
		got, err := TranslateLogQL(tc.query)
		if err != nil {
			t.Fatalf("%s: %v", tc.query, err)
		}
		if got != tc.want {
			t.Errorf("%s ->\n got %s\nwant %s", tc.query, got, tc.want)
		}
	}
}

// LogQL's whitespace insignificance is broader than one space before a paren:
// `topk (5, …)` and `topk(5,  …)` are the same query, and without canonicalising
// them the translator fell through to the bare-text branch and shipped the query
// TEXT to VictoriaLogs as a search phrase, which it answers with a parse error.
func TestNormalizeCallWhitespace_CollapsesRunsOutsideQuotes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`topk (5, sum(rate({app="a"}[1m])))`, `topk(5, sum(rate({app="a"}[1m])))`},
		{`topk(5,  sum by (ns)  (rate({app="a"}[1m])))`, `topk(5, sum by (ns) (rate({app="a"}[1m])))`},
		{`sum  by  (ns)  (count_over_time({app="a"}[1m]))`, `sum by (ns) (count_over_time({app="a"}[1m]))`},
		// Quoted spans keep their text verbatim.
		{"{ns=\"x\"} |= `sum  (x)`", "{ns=\"x\"} |= `sum  (x)`"},
	} {
		if got := NormalizeCallWhitespace(tc.in); got != tc.want {
			t.Errorf("%q ->\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

// A metric expression that fails to translate must NOT be shipped to the backend
// as a search phrase: VictoriaLogs answers with a parse error naming the proxy's
// own output, an error about a query nobody wrote.
func TestTranslate_NeverShipsAMetricExpressionAsAPhrase(t *testing.T) {
	_, err := TranslateLogQL(`topk(5, __not_a_real_function__({app="a"}[1m]))`)
	if err == nil {
		t.Fatal("an untranslatable metric expression must fail here, not downstream")
	}
	if strings.Contains(err.Error(), `"topk`) {
		t.Fatalf("the error should name the problem, not quote the query: %v", err)
	}
	// A subquery is deliberately left to the proxy, which evaluates it itself.
	if _, err := TranslateLogQL(`sum(max_over_time(rate({app="nginx"}[5m])[1h:5m])) by (app)`); err != nil {
		t.Fatalf("a subquery must keep its passthrough: %v", err)
	}
}

// Loki derives the level from the LINE TEXT when no named field carries a
// recognised value. The logs path did; the stats path did not, so
// `sum by (detected_level) (...)` lost every entry whose only evidence was the
// word in the message.
func TestLevelNormalizePipes_CarryTheLineTextRule(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level", "LogLevel"}, MaterializeLevel: true}
	pipes := strings.Join(m.levelNormalizePipes(), " ")
	if !strings.Contains(pipes, "extract_regexp if (NOT (level:*))") {
		t.Fatalf("no guarded line-text extraction in the stats chain:\n%s", pipes)
	}
	if !strings.Contains(pipes, "(?P<level>trace|debug|info|warning|warn|error|err|critical|fatal)") {
		t.Fatalf("the extraction does not carry the measured keyword set:\n%s", pipes)
	}
	// The extraction must run BEFORE the normalisation stages, or `warning`/`err`
	// never reach their canonical form.
	if strings.Index(pipes, "extract_regexp") > strings.Index(pipes, "replace_regexp") {
		t.Fatalf("extraction runs after normalisation:\n%s", pipes)
	}
}
