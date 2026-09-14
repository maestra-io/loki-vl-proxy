package translator

import (
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// Round 12, N2: a LogQL string literal is unquoted ONCE before the regexp is
// re-quoted for LogsQL. `"\\d{4}"` in the LogQL text is the regexp `\d{4}`;
// trimming the quotes instead kept the LogQL escapes and the LogsQL quoting
// doubled them (`\\\\d`, a literal backslash — 0 rows against Loki's 247817).
func TestTranslate_LabelFilterRegexpEscapesQuotedOnce(t *testing.T) {
	m := &MappingOptions{MsgFieldAliases: []string{"message"}}
	cases := map[string]string{
		// alias path (field OR _msg)
		`{pod="x"} | json | message=~"\\d{4}-\\d{2} \\S+ \\.x"`: `_msg:~"^(?:\\d{4}-\\d{2} \\S+ \\.x)$"`,
		// plain parsed field
		`{pod="x"} | json | other=~"\\d{4}\\s"`: `other:~"^(?:\\d{4}\\s)$"`,
		// backtick literal is verbatim
		"{pod=\"x\"} | json | other=~`\\d{4}`": `other:~"^(?:\\d{4})$"`,
		// stream matcher path
		`{pod=~"\\d+"}`: `pod:~"^(?:\\d+)$"`,
		// an escaped quote and an escaped backslash in an exact match
		`{pod="x"} | json | other="a\"b\\c"`: `other:="a\"b\\c"`,
	}
	for q, want := range cases {
		got, err := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, m)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		if !strings.Contains(got, want) {
			t.Errorf("%s\n got  %s\n want it to contain %s", q, got, want)
		}
		if strings.Contains(got, `\\\\`) {
			t.Errorf("%s: doubled escape in %s", q, got)
		}
	}
}

// Round 12 (b): `| (a="1" or b="2")` is a parenthesised label-filter stage.
func TestTranslate_ParenthesisedLabelFilterStage(t *testing.T) {
	got, err := TranslateLogQLWithMapping(`{a="b"} | json | (x="1" or y="2")`, nil, nil, logsql.Capabilities{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `| filter (x:="1" or y:="2")`) {
		t.Fatalf("got %s", got)
	}
	got, _ = TranslateLogQLWithMapping(`{a="b"} | json | (x="1" or y="2") and z!="3"`, nil, nil, logsql.Capabilities{}, nil)
	if !strings.Contains(got, `((x:="1" or y:="2") and -z:="3")`) {
		t.Fatalf("mixed: got %s", got)
	}
	// A quoted parenthesis is text, not grouping.
	got, _ = TranslateLogQLWithMapping(`{a="b"} | json | x="(1)"`, nil, nil, logsql.Capabilities{}, nil)
	if !strings.Contains(got, `x:="(1)"`) {
		t.Fatalf("quoted parens: got %s", got)
	}
}

// Round 12 (c): after a parser an unmapped underscore name is read under the
// Loki spelling (`| json` flattens nested keys with `_`) AND the VictoriaLogs
// one (unpack_json uses `.`); 53 dashboard filters name
// `ExceptionDetails_{Topic,ClusterBootstrapServers,StackTrace}`.
func TestTranslate_UnderscoreFieldAfterParserReadsDottedToo(t *testing.T) {
	m := &MappingOptions{}
	got, err := TranslateLogQLWithMapping(`{a="b"} | json | ExceptionDetails_StackTrace=~".*foo.*"`, nil, nil, logsql.Capabilities{}, m)
	if err != nil {
		t.Fatal(err)
	}
	want := `(ExceptionDetails_StackTrace:~"^(?:.*foo.*)$" OR "ExceptionDetails.StackTrace":~"^(?:.*foo.*)$")`
	if !strings.Contains(got, want) {
		t.Fatalf("got %s\nwant it to contain %s", got, want)
	}
	neg, _ := TranslateLogQLWithMapping(`{a="b"} | logfmt | ExceptionDetails_Topic!="t"`, nil, nil, logsql.Capabilities{}, m)
	if !strings.Contains(neg, `NOT (ExceptionDetails_Topic:="t" OR "ExceptionDetails.Topic":="t")`) {
		t.Fatalf("negated: %s", neg)
	}
	// The empty-value forms cover both spellings too — Grafana's
	// `sum by (X) (… | X!="" …)` is the common shape.
	empty, _ := TranslateLogQLWithMapping(`{a="b"} | json | ExceptionDetails_Topic!="" | ExceptionDetails_Trace=""`, nil, nil, logsql.Capabilities{}, m)
	for _, want := range []string{`(ExceptionDetails_Topic:!"" OR "ExceptionDetails.Topic":!"")`, `(ExceptionDetails_Trace:="" AND "ExceptionDetails.Trace":="")`} {
		if !strings.Contains(empty, want) {
			t.Fatalf("empty-value alias: got %s\nwant it to contain %s", empty, want)
		}
	}
	// Not before a parser, not for Loki's own `__error__`, not without the
	// fork mapping (nil restores upstream output exactly).
	for _, q := range []string{
		`{a="b"} | ExceptionDetails_StackTrace="x"`,
		`{a="b"} | json | __error__!="JSONParserErr"`,
	} {
		got, _ := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, m)
		if strings.Contains(got, `"ExceptionDetails.StackTrace"`) || strings.Contains(got, `"..error.."`) || strings.Contains(got, " OR ") {
			t.Fatalf("alias must not apply to %s: %s", q, got)
		}
	}
	off, _ := TranslateLogQLWithMapping(`{a="b"} | json | ExceptionDetails_StackTrace="x"`, nil, nil, logsql.Capabilities{}, nil)
	if strings.Contains(off, " OR ") {
		t.Fatalf("nil mapping must keep upstream output: %s", off)
	}
}
