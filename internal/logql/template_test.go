package logql

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func execTemplate(t *testing.T, src string, labels map[string]string, line string, ts time.Time) string {
	t.Helper()
	tmpl, err := ParseTemplate(src)
	if err != nil {
		t.Fatalf("ParseTemplate(%q): %v", src, err)
	}
	var buf strings.Builder
	out, err := tmpl.Exec(labels, line, ts, &buf)
	if err != nil {
		t.Fatalf("Exec(%q): %v", src, err)
	}
	return out
}

// TestTemplateFunctions covers one case per Loki template function, with the
// argument order the docs specify (piped value last).
func TestTemplateFunctions(t *testing.T) {
	labels := map[string]string{
		"status": "404",
		"method": "get",
		"path":   "/api/v1/users",
		"size":   "2048",
		"dur":    "1m30s",
		"msg":    "  padded  ",
		"num":    "3.7",
		"epoch":  "1700000000",
		"json":   `{"a":{"b":7}}`,
	}
	ts := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	line := `raw log line`

	cases := []struct{ name, tmpl, want string }{
		// built-in variables
		{"line_var", `{{ __line__ }}`, "raw log line"},
		{"timestamp_var", `{{ __timestamp__ | unixEpoch }}`, "1789041600"},
		{"label_access", `{{ .status }}`, "404"},
		{"missing_label_is_empty", `[{{ .nope }}]`, "[]"},

		// strings
		{"lower", `{{ lower "HELLO" }}`, "hello"},
		{"upper", `{{ upper .method }}`, "GET"},
		{"title", `{{ title "hello world" }}`, "Hello World"},
		{"trim", `{{ trim .msg }}`, "padded"},
		{"trimAll", `{{ trimAll "$" "$5.00$" }}`, "5.00"},
		{"trimPrefix", `{{ trimPrefix "-" "-hello" }}`, "hello"},
		{"trimSuffix", `{{ trimSuffix "-" "hello-" }}`, "hello"},
		{"trunc", `{{ trunc 5 "hello world" }}`, "hello"},
		{"trunc_negative", `{{ trunc -5 "hello world" }}`, "world"},
		{"substr", `{{ substr 0 5 "hello world" }}`, "hello"},
		{"replace", `{{ replace "hello" "world" "hello hello" }}`, "world world"},
		{"repeat", `{{ repeat 3 "ab" }}`, "ababab"},
		{"indent", `{{ indent 2 "a\nb" }}`, "  a\n  b"},
		{"nindent", `{{ nindent 2 "a" }}`, "\n  a"},
		{"alignLeft", `[{{ alignLeft 5 "hi" }}]`, "[hi   ]"},
		{"alignRight", `[{{ alignRight 5 "hi" }}]`, "[   hi]"},
		{"default_bare", `{{ default "-" "" }}`, "-"},
		{"default_piped", `{{ .nope | default "N/A" }}`, "N/A"},
		{"default_present", `{{ .status | default "N/A" }}`, "404"},
		{"contains", `{{ if contains "api" .path }}yes{{ end }}`, "yes"},
		{"hasPrefix", `{{ if hasPrefix "/api" .path }}yes{{ end }}`, "yes"},
		{"hasSuffix", `{{ if hasSuffix "users" .path }}yes{{ end }}`, "yes"},
		// Loki's `bytes` PARSES a humanised size into a byte count.
		{"bytes_plain", `{{ .size | bytes }}`, "2048"},
		{"bytes_decimal_unit", `{{ bytes "2kB" }}`, "2000"},
		{"bytes_binary_unit", `{{ bytes "1KiB" }}`, "1024"},
		{"bytes_mib", `{{ bytes "1.5MiB" }}`, "1572864"},
		{"bytes_bare_b", `{{ bytes "512B" }}`, "512"},
		{"bytes_unparseable", `{{ bytes "nope" }}`, "0"},

		// encoding
		{"b64enc", `{{ b64enc "abc" }}`, "YWJj"},
		{"b64dec", `{{ b64dec "YWJj" }}`, "abc"},
		{"urlencode", `{{ urlencode "a b&c" }}`, "a+b%26c"},
		{"urldecode", `{{ urldecode "a+b%26c" }}`, "a b&c"},
		{"fromJson", `{{ (fromJson .json).a.b }}`, "7"},
		{"toJson", `{{ toJson (fromJson .json) }}`, `{"a":{"b":7}}`},

		// regex
		{"regexReplaceAll", `{{ regexReplaceAll "/v1/" .path "/v2/" }}`, "/api/v2/users"},
		{"regexReplaceAll_group", `{{ regexReplaceAll "(a+)bc" "aaabc" "${1}!" }}`, "aaa!"},
		{"regexReplaceAllLiteral", `{{ regexReplaceAllLiteral "(a+)bc" "aaabc" "${1}" }}`, "${1}"},
		{"count", `{{ count "a|b" "abab" }}`, "4"},

		// time
		{"date", `{{ date "2006-01-02" __timestamp__ }}`, ts.Format("2006-01-02")},
		{"toDate", `{{ toDate "2006-01-02" "2021-11-02" | unixEpoch }}`, strconv.FormatInt(toDate("2006-01-02", "2021-11-02").Unix(), 10)},
		{"toDateInZone", `{{ toDateInZone "2006-01-02" "UTC" "2021-11-02" | unixEpoch }}`, "1635811200"},
		{"unixEpochMillis", `{{ unixEpochMillis __timestamp__ }}`, "1789041600000"},
		{"unixEpochNanos", `{{ unixEpochNanos __timestamp__ }}`, "1789041600000000000"},
		{"unixToTime", `{{ date "2006-01-02" (unixToTime .epoch) }}`, time.Unix(1700000000, 0).Format("2006-01-02")},
		{"duration_seconds", `{{ duration_seconds .dur }}`, "90"},
		{"duration_alias", `{{ .dur | duration }}`, "90"},

		// math
		{"int", `{{ "3" | int }}`, "3"},
		{"float64", `{{ "3.5" | float64 }}`, "3.5"},
		{"add", `{{ add 3 2 5 }}`, "10"},
		{"sub", `{{ sub 5 2 }}`, "3"},
		{"mul", `{{ mul 5 2 3 }}`, "30"},
		{"div", `{{ div 10 2 }}`, "5"},
		{"div_by_zero", `{{ div 10 0 }}`, "0"},
		{"mod", `{{ mod 10 3 }}`, "1"},
		{"addf", `{{ addf 3.5 2 5 }}`, "10.5"},
		{"subf", `{{ subf 5.5 2 1.5 }}`, "2"},
		{"mulf", `{{ mulf 5.5 2 2.5 }}`, "27.5"},
		{"divf", `{{ divf 10 2 4 }}`, "1.25"},
		{"max", `{{ max 1 2 3 }}`, "3"},
		{"min", `{{ min 1 2 3 }}`, "1"},
		{"maxf", `{{ maxf 1 2.5 3 }}`, "3"},
		{"minf", `{{ minf 1 2.5 3 }}`, "1"},
		{"ceil", `{{ ceil 123.001 }}`, "124"},
		{"floor", `{{ floor 123.9999 }}`, "123"},
		{"round", `{{ round 123.555555 3 }}`, "123.556"},

		// control flow + builtins
		{"if_else", `{{ if .nope }}a{{ else }}b{{ end }}`, "b"},
		{"or_fallback", `{{ or .nope __line__ }}`, "raw log line"},
		{"and_not", `{{ if and .status (not .nope) }}ok{{ end }}`, "ok"},
		{"eq_ne", `{{ if eq .status "404" }}{{ if ne .method "post" }}both{{ end }}{{ end }}`, "both"},
		{"printf", `{{ printf "%.1sxx" .status }}`, "4xx"},
		{"print", `{{ print .method "-" .status }}`, "get-404"},
		{"range", `{{ range $i, $v := (fromJson "[1,2,3]") }}{{ $v }}{{ end }}`, "123"},
		{"pipeline_chain", `{{ .path | replace "/" "_" | trunc 8 | upper }}`, "_API_V1_"},

		// deprecated CamelCase aliases keep Go strings argument order
		{"ToUpper_alias", `{{ ToUpper .method }}`, "GET"},
		{"Replace_alias", `{{ Replace "aaa" "a" "b" 2 }}`, "bba"},
		{"TrimPrefix_alias", `{{ TrimPrefix "-hello" "-" }}`, "hello"},
		{"Contains_alias", `{{ if Contains .path "api" }}yes{{ end }}`, "yes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := execTemplate(t, tc.tmpl, labels, line, ts); got != tc.want {
				t.Errorf("template %q\n got: %q\nwant: %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

func TestTemplateUnknownFunction(t *testing.T) {
	_, err := ParseTemplate(`{{ .foo | notAFunction }}`)
	if err == nil {
		t.Fatal("expected an error for an unknown template function")
	}
	var unknown *UnknownFuncError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected *UnknownFuncError, got %T: %v", err, err)
	}
	if unknown.Func != "notAFunction" {
		t.Errorf("error should name the function, got %q", unknown.Func)
	}
	// The message must never be able to carry the template text into results.
	if strings.Contains(err.Error(), "{{") {
		t.Errorf("error message leaks template text: %s", err)
	}
}

// TestTemplateQuotingForms proves both LogQL string literal forms reach the
// evaluator with the template intact — the backtick form is what Grafana emits
// for `| line_format ` + "`{{.message}}`" + `, and it used to be printed verbatim.
func TestTemplateQuotingForms(t *testing.T) {
	cases := []struct{ name, query, want string }{
		{"double_quoted_line_format", `{app="x"} | json | line_format "{{.message}}"`, "hello"},
		{"backtick_line_format", "{app=\"x\"} | json | line_format `{{.message}}`", "hello"},
		{"double_quoted_escapes", `{app="x"} | json | line_format "{{.message}} \"q\""`, `hello "q"`},
		{"backtick_with_quotes", "{app=\"x\"} | json | line_format `{{ printf \"%s!\" .message }}`", "hello!"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := runQueryPipeline(t, tc.query, `{"message":"hello"}`, map[string]string{"app": "x"})
			if e == nil {
				t.Fatal("entry was filtered out")
			}
			if e.Line != tc.want {
				t.Errorf("line = %q, want %q", e.Line, tc.want)
			}
		})
	}
}

// TestTemplateLabelFormatQuotingForms does the same for label_format, whose
// values used to be re-serialised through a token round-trip.
func TestTemplateLabelFormatQuotingForms(t *testing.T) {
	cases := []struct{ name, query, want string }{
		{"backtick", "{app=\"x\"} | json | label_format cls=`{{ printf \"%.1sxx\" .status }}`", "4xx"},
		{"double_quoted", `{app="x"} | json | label_format cls="{{ .status }}"`, "404"},
		{"conditional", "{app=\"x\"} | json | label_format cls=`{{ if .status }}has{{ else }}none{{ end }}`", "has"},
		{"bare_rename", `{app="x"} | json | label_format cls=status`, "404"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := runQueryPipeline(t, tc.query, `{"status":"404"}`, map[string]string{"app": "x"})
			if e == nil {
				t.Fatal("entry was filtered out")
			}
			if e.Labels["cls"] != tc.want {
				t.Errorf("cls = %q, want %q (labels=%v)", e.Labels["cls"], tc.want, e.Labels)
			}
		})
	}
}
