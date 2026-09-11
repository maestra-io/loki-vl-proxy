package translator

import (
	"regexp"
	"strings"
	"testing"
)

// `|= "a" or "b"` becomes one parenthesised alternation so a negative filter's
// single NOT covers every alternative. Before the fix the translator stopped at
// the first value and the leftover `or "b"` reached the pipe-stage parser.
func TestTranslate_LineFilterOrList(t *testing.T) {
	for _, tc := range []struct{ query, want string }{
		{"{ns=\"x\"} |= `a` or `b`", `ns:="x" (~"a" OR ~"b")`},
		{"{ns=\"x\"} != `a` or `b`", `ns:="x" NOT (~"a" OR ~"b")`},
		{`{ns="x"} |~ "a" or "b" or "c"`, `ns:="x" (~"a" OR ~"b" OR ~"c")`},
		{`{ns="x"} |= "a"`, `ns:="x" ~"a"`},
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

// Whitespace between a function name and its `(` is insignificant in LogQL, and
// Grafana stores panels that way. The translator matched on `sum(`-shaped
// prefixes, so `sum (count_over_time (…))` stopped being recognised as a metric
// query, fell through to the raw-log branch and emitted LogsQL the backend then
// rejected with a parse error on the proxy's own output.
func TestTranslate_WhitespaceBeforeCallParen(t *testing.T) {
	tight, err := TranslateLogQL(`sum(count_over_time({namespace="trow-system"}[1m]))`)
	if err != nil {
		t.Fatalf("tight: %v", err)
	}
	loose, err := TranslateLogQL(`sum (count_over_time ({namespace="trow-system"}[1m]))`)
	if err != nil {
		t.Fatalf("loose: %v", err)
	}
	if tight != loose {
		t.Fatalf("whitespace changed the translation:\n tight %s\n loose %s", tight, loose)
	}
	if strings.Contains(loose, "sort by (_time") {
		t.Fatalf("spaced aggregation fell through to the raw-log branch: %s", loose)
	}
	// A `sum (` inside a quoted span is data, not a call.
	quoted, err := TranslateLogQL("{ns=\"x\"} |= `sum (x)`")
	if err != nil {
		t.Fatalf("quoted: %v", err)
	}
	// The literal survives — escaped, because `|=` is a substring filter and its
	// parens must not become a regexp group.
	if !strings.Contains(quoted, `sum \\(x\\)`) {
		t.Fatalf("quoted text was rewritten: %s", quoted)
	}
}

// Loki derives detected_level from the LINE TEXT when no level field carries a
// recognised value. Measured against Loki 3.7.1 over 391 lines, 0 mismatches.
func TestLokiTextLevel(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"      Error: A task was canceled.", "error"},
		{"something ERROR happened", "error"},
		{"a warning was raised", "warn"},
		{"WARN: disk almost full", "warn"},
		{"critical failure", "critical"},
		{"FATAL crash", "fatal"},
		{"trace id 12345", "trace"},
		{`{"message":"      Error: A task was canceled..."}`, "error"},
		{"AA[error]BB", "error"},
		{`AA"error"BB`, "error"},
		// Delimiters Loki does NOT accept, and words that merely contain a keyword.
		{"user terrorized the db", ""},
		{"debugging the thing", ""},
		{"AA<error>BB", ""},
		{"AA:error:BB", ""},
		{"a_error_b", ""},
		{"informational text", ""},
		{"the operation failed", ""},
		{"plain message with no level at all", ""},
		// First keyword in the line wins.
		{"AA info BB error CC", "info"},
		{"AA error BB info CC", "error"},
	} {
		if got := LokiTextLevel(tc.line); got != tc.want {
			t.Errorf("LokiTextLevel(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// The pushed-down filter must carry the same text heuristic, guarded by "no named
// level field is present" so a real level still wins.
func TestDerivedLevelFilter_FallsBackToLineText(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level", "LogLevel"}}
	got := m.derivedLevelFilter("error", false, false)
	if !strings.Contains(got, `_msg:~`) {
		t.Fatalf("no line-text alternative in %s", got)
	}
	// The guard is the absence of a RECOGNISED value, not of any value: Loki falls
	// back to the line text when the level key holds something it does not know.
	if !strings.Contains(got, `NOT (level:~"`+anyLevelValuePattern()+`" OR LogLevel:~"`+anyLevelValuePattern()+`")`) {
		t.Fatalf("text fallback is not guarded by the absence of a RECOGNISED level: %s", got)
	}
	// A negated matcher keeps the old shape — the heuristic has no negative form.
	if neg := m.derivedLevelFilter("error", true, false); strings.Contains(neg, "_msg:~") {
		t.Fatalf("negated matcher must not gain the text fallback: %s", neg)
	}
}

// An UNRECOGNISED named value must not suppress the line-text heuristic — Loki
// reads `"LogLevel":"Information"` as unknown and then looks at the line.
func TestAnyLevelValuePattern_CoversEveryRecognisedValue(t *testing.T) {
	re := regexp.MustCompile(anyLevelValuePattern())
	for _, v := range []string{"error", "ERR", "Fatal", "warning", "info", "notice", "debug", "trace", "unknown"} {
		if !re.MatchString(v) {
			t.Errorf("%q should be a recognised level value", v)
		}
	}
	// "information"/"notice" ARE in this repo's synonym table (levelSynonyms), so
	// they count as recognised here — the guard has to match the very set the
	// pushdown filter itself matches on, or the two disagree about what a level is.
	for _, v := range []string{"", "banana", "err0r", "informative"} {
		if re.MatchString(v) {
			t.Errorf("%q should NOT be a recognised level value", v)
		}
	}
}
