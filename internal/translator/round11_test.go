package translator

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// Round 11, defect 3.
//
// `detected_level =~ "err.*|warn"` was translated as `field:~"^(?:^(?:err.*|warn)$)$"`
// over every raw level field: the regexp was anchored by the label-filter
// translator and again by derivedLevelFilter, and it was matched against the
// RAW values, not against the level Loki derives. Loki evaluates the regexp
// against its canonical `detected_level`, so the filter must expand to the
// positive form of every canonical level the regexp matches.
func TestDerivedLevelFilter_RegexpMatchesCanonicalLevels(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level", "LogLevel"}}

	got := m.derivedLevelFilter("err.*|warn", false, true)
	if strings.Contains(got, "^(?:^") {
		t.Fatalf("regexp anchored twice: %s", got)
	}
	if strings.Contains(got, "err.*|warn") {
		t.Fatalf("user regexp reached the raw fields instead of the canonical levels: %s", got)
	}
	for _, lvl := range []string{"error", "warn"} {
		if !strings.Contains(got, lokiDetectedLevelPattern(lvl)) {
			t.Errorf("canonical level %q matched by the regexp is missing from %s", lvl, got)
		}
	}
	if strings.Contains(got, lokiDetectedLevelPattern("info")) {
		t.Errorf("info does not match err.*|warn, yet it is in %s", got)
	}
	// The text fallback travels with each level, exactly as for `=`.
	if strings.Count(got, `_msg:~`) != 2 {
		t.Errorf("want one line-text fallback per matched level, got %s", got)
	}
	// `!~` is the negation of the same expression.
	if neg := m.derivedLevelFilter("err.*|warn", true, true); neg != "NOT "+got {
		t.Fatalf("!~ must be NOT (=~): %s", neg)
	}
	// A regexp no canonical level matches matches no row — Loki never reports
	// "Information" — and its negation matches every row (CodeRabbit on PR 22:
	// a raw-field fallback still matched a stored "Information").
	if got := m.derivedLevelFilter("Information", false, true); got != logsqlNeverMatch {
		t.Fatalf("unmatched regexp must match nothing, got %s", got)
	}
	if got := m.derivedLevelFilter("Information", true, true); got != "*" {
		t.Fatalf("negated unmatched regexp must match everything, got %s", got)
	}
	if got := m.derivedLevelFilter("custom", false, false); got != logsqlNeverMatch {
		t.Fatalf("a literal Loki never reports must match nothing, got %s", got)
	}
}

// CodeRabbit on PR 22: the predicates must use the same canonical table as the
// `by (detected_level)` materialisation — fatal, critical and trace are
// distinct levels, not synonyms of error/debug.
func TestDerivedLevelFilter_UsesTheDetectedLevelTable(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level"}}
	// The field predicate is the first OR branch; the "present" guard after it
	// legitimately lists every recognised raw value.
	if got := m.derivedLevelFilter("debug", false, false); !strings.HasPrefix(got, `(level:~"(?i)^(debug|fine|verbose)$" OR`) {
		t.Fatalf("debug must not swallow trace: %s", got)
	}
	if got := m.derivedLevelFilter("error", false, false); !strings.HasPrefix(got, `(level:~"(?i)^(err|error|errors|emerg|panic|alert)$" OR`) {
		t.Fatalf("error must not swallow fatal/critical: %s", got)
	}
	if got := m.derivedLevelFilter("fatal", false, true); !strings.Contains(got, `(?i)^(fatal)$`) || !strings.Contains(got, buildFieldFilterStr("_msg", logsql.FieldOpRegexp, LokiTextLevelPattern("fatal"), false)) {
		t.Fatalf("fatal is a canonical level with its own text fallback: %s", got)
	}
}

// `detected_level != "info"` let a row with NO level field through (every
// `-field:~` negation held) and the derivation chain then labelled it `info`
// from its line text — 33 rows per bucket Loki excludes. The negation is now
// NOT (positive), positive including the line-text rule.
func TestDerivedLevelFilter_NegationExcludesTextDerivedRows(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level", "LogLevel"}}
	neg := m.derivedLevelFilter("info", true, false)
	if !strings.HasPrefix(neg, "NOT (") {
		t.Fatalf("negation must wrap the positive form: %s", neg)
	}
	if !strings.Contains(neg, buildFieldFilterStr("_msg", logsql.FieldOpRegexp, LokiTextLevelPattern("info"), false)) {
		t.Fatalf("negation lost the line-text rule: %s", neg)
	}
	if strings.Contains(neg, "-level:~") {
		t.Fatalf("per-field negation is back: %s", neg)
	}
}

// `unknown` is Loki's level for a row with no recognised level field and no
// keyword in the text — not a raw value "unknown".
func TestDerivedLevelFilter_Unknown(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level"}}
	got := m.derivedLevelFilter("unknown", false, false)
	if !strings.Contains(got, "NOT (level:~") || !strings.Contains(got, buildFieldFilterStr("_msg", logsql.FieldOpRegexp, lokiTextLevelRE.String(), true)) {
		t.Fatalf("unknown must be 'no recognised field AND no keyword in text': %s", got)
	}
}

// End to end through the label-filter translator: the emitted LogsQL carries
// the anchors exactly once and never the double form.
func TestTranslate_DetectedLevelRegexpAnchoredOnce(t *testing.T) {
	mapping := levelMapping(false)
	for _, q := range []string{
		`{namespace="ns"} | json | detected_level =~ "err.*|warn"`,
		`{namespace="ns", detected_level=~"err.*|warn"}`,
		`{namespace="ns"} | json | detected_level !~ "err.*|warn"`,
	} {
		got, err := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, mapping)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if strings.Contains(got, "^(?:^") {
			t.Fatalf("%s\n-> double anchor in %s", q, got)
		}
		if !strings.Contains(got, lokiDetectedLevelPattern("error")) || !strings.Contains(got, lokiDetectedLevelPattern("warn")) {
			t.Fatalf("%s\n-> canonical levels missing in %s", q, got)
		}
	}
	// The filter is valid LogsQL-side regexp syntax as well: every quoted regexp
	// compiles.
	got, _ := TranslateLogQLWithMapping(`{namespace="ns"} | json | detected_level != "info"`, nil, nil, logsql.Capabilities{}, mapping)
	for _, mm := range regexp.MustCompile(`:~"((?:[^"\\]|\\.)*)"`).FindAllStringSubmatch(got, -1) {
		if _, err := regexp.Compile(strings.ReplaceAll(mm[1], `\"`, `"`)); err != nil {
			t.Fatalf("regexp %q does not compile: %v", mm[1], err)
		}
	}
}

// Round 11, defect 6: the backtick form of a label_format template must not
// keep its backticks inside the LogsQL format pipe.
func TestTranslate_LabelFormatBacktickAlias(t *testing.T) {
	got, err := TranslateLogQLWithMapping("{a=\"b\"} | json | label_format lf=`{{ .level }}`", nil, nil, logsql.Capabilities{}, levelMapping(false))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `| format "<level>" as lf`) {
		t.Fatalf("want a clean format pipe, got %s", got)
	}
}

// Round 11, defect 8: a JSON key the collector lifts into _msg (vlagent
// msgField: message/Message/msg/log) is ABSENT after `| json` in VictoriaLogs,
// while Loki — which stores the whole wrapper — still sees it. A filter on the
// name reads the field when present and _msg when not.
func TestTranslate_MsgFieldAliasReadsMsgWhenAbsent(t *testing.T) {
	m := &MappingOptions{MsgFieldAliases: []string{"message", "msg"}}
	got, err := TranslateLogQLWithMapping(`{pod=~".*mirrormaker2-0"} | json | message=~".* ERROR .*"`, nil, nil, logsql.Capabilities{}, m)
	if err != nil {
		t.Fatal(err)
	}
	want := `(message:~"^(?:.* ERROR .*)$" OR (-message:* AND _msg:~"^(?:.* ERROR .*)$"))`
	if !strings.Contains(got, want) {
		t.Fatalf("got %s\nwant it to contain %s", got, want)
	}
	neg, _ := TranslateLogQLWithMapping(`{pod="x"} | json | message!="boot"`, nil, nil, logsql.Capabilities{}, m)
	if !strings.Contains(neg, `NOT (message:="boot" OR (-message:* AND _msg:="boot"))`) {
		t.Fatalf("negated alias filter must be NOT (positive): %s", neg)
	}
	// A name outside the list, and the list switched off, keep the plain filter.
	plain, _ := TranslateLogQLWithMapping(`{pod="x"} | json | other=~".* ERROR .*"`, nil, nil, logsql.Capabilities{}, m)
	off, _ := TranslateLogQLWithMapping(`{pod="x"} | json | message=~".* ERROR .*"`, nil, nil, logsql.Capabilities{}, &MappingOptions{})
	for _, q := range []string{plain, off} {
		if strings.Contains(q, "-message:*") || strings.Contains(q, "-other:*") {
			t.Fatalf("alias must not apply: %s", q)
		}
	}
}

// Round 11 (panel rewrite, omega): two label filters on the SAME field with
// different values collapsed to the second one on the pushdown path —
// `| Scopes=~"sql09" | Scopes=~"resumable"` answered 276 725 (the second filter
// alone). Loki ANDs them; only an include/exclude of the same value collapses.
func TestTranslate_TwoFiltersOnOneFieldStayAnded(t *testing.T) {
	m := &MappingOptions{}
	got, err := TranslateLogQLWithMapping(`{a="b"} | json | Scopes=~"sql09" | Scopes=~"resumable" | Category != "A" | Category != "B"`, nil, nil, logsql.Capabilities{}, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`Scopes:~"^(?:sql09)$"`, `Scopes:~"^(?:resumable)$"`, `-Category:="A"`, `-Category:="B"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("filter %s lost: %s", want, got)
		}
	}
	// The Drilldown click semantics survive: include then exclude of the same
	// value keeps the latest.
	got, _ = TranslateLogQLWithMapping(`{a="b"} | json | x="1" | x!="1"`, nil, nil, logsql.Capabilities{}, m)
	if strings.Count(got, `x:="1"`) != 1 || !strings.Contains(got, `-x:="1"`) {
		t.Fatalf("include then exclude of one value must keep the latest only: %s", got)
	}
}
