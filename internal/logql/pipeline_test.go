package logql

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// runQueryPipeline parses a LogQL log query, runs its pipeline over one entry
// and returns the result, or nil when the entry was filtered out.
func runQueryPipeline(t *testing.T, query, line string, streamLabels map[string]string) *Entry {
	t.Helper()
	expr, err := Parse(query)
	if err != nil {
		t.Fatalf("Parse(%q): %v", query, err)
	}
	lq, ok := expr.(*LogQuery)
	if !ok {
		t.Fatalf("expected a log query, got %T", expr)
	}
	pipeline, err := NewPipeline(lq.Pipeline)
	if err != nil {
		t.Fatalf("NewPipeline(%q): %v", query, err)
	}
	labels := make(map[string]string, len(streamLabels))
	for k, v := range streamLabels {
		labels[k] = v
	}
	e := &Entry{TS: time.Unix(1789041600, 0).UTC(), Line: line, Labels: labels}
	if !pipeline.Process(e) {
		return nil
	}
	return e
}

const esc = "\x1b"

// trowLine reproduces the shape of a trow-registry log line: a JSON envelope
// whose `message` field carries ANSI-coloured key=value pairs. Built through
// encoding/json so the ESC bytes are escaped exactly as the real producer does.
func trowLine(status, path string) string {
	msg := "response sent " +
		esc + "[3mstatus" + esc + "[0m" + esc + "[2m=" + esc + `[0m"` + status + `" ` +
		esc + "[3mpath" + esc + "[0m" + esc + "[2m=" + esc + `[0m"` + path + `"`
	b, err := json.Marshal(map[string]string{"message": msg})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestPipeline_TemplateThenRegexp is the T2/T8 shape: a `| regexp` that reads
// the line a `| line_format` produced. Before the pipeline was evaluated
// proxy-side the regexp ran against the raw JSON envelope (where the ESC bytes
// are `` escapes), matched nothing, and the trailing label filter passed
// every line through.
func TestPipeline_TemplateThenRegexp(t *testing.T) {
	query := `{ns="trow"} | json message="message" | line_format "{{ or .message __line__ }}" ` +
		`| drop __error__, __error_details__ ` +
		`| regexp "status.*?=\\x1b\\[0m\"(?P<status>\\d{3})\"" | status !~ "2.."`

	t.Run("non_2xx_survives", func(t *testing.T) {
		e := runQueryPipeline(t, query, trowLine("404", "/v2/a/blobs/x"), map[string]string{"ns": "trow"})
		if e == nil {
			t.Fatal("404 entry should survive `status !~ \"2..\"`")
		}
		if e.Labels["status"] != "404" {
			t.Errorf("status = %q, want 404", e.Labels["status"])
		}
	})

	t.Run("2xx_filtered", func(t *testing.T) {
		if e := runQueryPipeline(t, query, trowLine("200", "/v2/a/blobs/x"), map[string]string{"ns": "trow"}); e != nil {
			t.Fatalf("200 entry should be filtered out, got labels=%v", e.Labels)
		}
	})
}

// TestPipeline_LabelFormatConditional is the T6 shape: a conditional template
// producing the label a metric query groups by. The translator used to emit the
// template TEXT as the label value, collapsing every series into one.
func TestPipeline_LabelFormatConditional(t *testing.T) {
	query := `{ns="trow"} | json message="message" | line_format "{{ or .message __line__ }}" ` +
		"| regexp \"\\\\?ns=(?P<ns_upstream>[^\\\"&]+)\\\"\" " +
		"| label_format upstream=`{{ if .ns_upstream }}{{ .ns_upstream }}{{ else }}(no ns - trow-local){{ end }}`"

	cases := []struct{ path, want string }{
		{"/v2/a/manifests/v1?ns=docker.io", "docker.io"},
		{"/v2/a/manifests/v1?ns=515260921971.dkr.ecr.us-west-2.amazonaws.com", "515260921971.dkr.ecr.us-west-2.amazonaws.com"},
		{"/v2/a/manifests/v1", "(no ns - trow-local)"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			e := runQueryPipeline(t, query, trowLine("200", tc.path), map[string]string{"ns": "trow"})
			if e == nil {
				t.Fatal("entry was filtered out")
			}
			if e.Labels["upstream"] != tc.want {
				t.Errorf("upstream = %q, want %q", e.Labels["upstream"], tc.want)
			}
			if strings.Contains(e.Labels["upstream"], "{{") {
				t.Errorf("label value carries template text: %q", e.Labels["upstream"])
			}
		})
	}
}

func TestPipeline_Parsers(t *testing.T) {
	cases := []struct {
		name, query, line string
		want              map[string]string
	}{
		{
			"json_all_fields",
			`{a="b"} | json`,
			`{"method":"GET","status":200,"ok":true,"nested":{"x":"y"},"arr":[1,2]}`,
			map[string]string{"method": "GET", "status": "200", "ok": "true", "nested_x": "y", "arr_0": "1", "arr_1": "2"},
		},
		{
			"json_explicit_fields",
			`{a="b"} | json code="response.code", host="request.host"`,
			`{"response":{"code":503},"request":{"host":"api"},"other":"ignored"}`,
			map[string]string{"code": "503", "host": "api"},
		},
		{
			"json_index_path",
			`{a="b"} | json first="items[0].name"`,
			`{"items":[{"name":"one"},{"name":"two"}]}`,
			map[string]string{"first": "one"},
		},
		{
			"logfmt",
			`{a="b"} | logfmt`,
			`level=error msg="db pool exhausted" waiting=127`,
			map[string]string{"level": "error", "msg": "db pool exhausted", "waiting": "127"},
		},
		{
			"logfmt_explicit",
			`{a="b"} | logfmt lvl="level"`,
			`level=warn msg=hi`,
			map[string]string{"lvl": "warn"},
		},
		{
			"regexp_named_groups",
			`{a="b"} | regexp "(?P<verb>\\w+) (?P<route>/\\S+)"`,
			`GET /api/v1/users 200`,
			map[string]string{"verb": "GET", "route": "/api/v1/users"},
		},
		{
			"pattern",
			"{a=\"b\"} | pattern `<ip> - <_> [<ts>] \"<method> <path>\"`",
			`10.0.0.1 - admin [03/Apr/2026:10:30:00] "GET /x"`,
			map[string]string{"ip": "10.0.0.1", "ts": "03/Apr/2026:10:30:00", "method": "GET", "path": "/x"},
		},
		{
			"unpack",
			`{a="b"} | unpack`,
			`{"_entry":"real line","pod":"p1"}`,
			map[string]string{"pod": "p1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := runQueryPipeline(t, tc.query, tc.line, map[string]string{"a": "b"})
			if e == nil {
				t.Fatal("entry was filtered out")
			}
			for k, want := range tc.want {
				if e.Labels[k] != want {
					t.Errorf("label %s = %q, want %q (all=%v)", k, e.Labels[k], want, e.Labels)
				}
			}
		})
	}
}

func TestPipeline_UnpackReplacesLine(t *testing.T) {
	e := runQueryPipeline(t, `{a="b"} | unpack | line_format "{{ __line__ }}"`, `{"_entry":"real line","pod":"p1"}`, map[string]string{"a": "b"})
	if e == nil {
		t.Fatal("entry was filtered out")
	}
	if e.Line != "real line" {
		t.Errorf("line = %q, want %q", e.Line, "real line")
	}
}

func TestPipeline_Filters(t *testing.T) {
	line := `{"status":"404","level":"error","dur":"250ms","size":"2048"}`
	cases := []struct {
		name, query string
		survives    bool
	}{
		{"line_contains", `{a="b"} |= "404" | line_format "{{__line__}}"`, true},
		{"line_excludes", `{a="b"} != "404" | line_format "{{__line__}}"`, false},
		{"line_regex", `{a="b"} |~ "40[0-9]" | line_format "{{__line__}}"`, true},
		{"line_regex_negated", `{a="b"} !~ "40[0-9]" | line_format "{{__line__}}"`, false},
		{"label_eq", `{a="b"} | json | line_format "{{__line__}}" | status="404"`, true},
		{"label_neq", `{a="b"} | json | line_format "{{__line__}}" | status!="404"`, false},
		{"label_regex_anchored", `{a="b"} | json | line_format "{{__line__}}" | status=~"4.."`, true},
		{"label_regex_anchored_partial", `{a="b"} | json | line_format "{{__line__}}" | status=~"4"`, false},
		{"label_not_regex", `{a="b"} | json | line_format "{{__line__}}" | status!~"2.."`, true},
		{"numeric_gt", `{a="b"} | json | line_format "{{__line__}}" | status > 400`, true},
		{"numeric_lt", `{a="b"} | json | line_format "{{__line__}}" | status < 400`, false},
		{"duration_cmp", `{a="b"} | json | line_format "{{__line__}}" | dur > 100ms`, true},
		{"bytes_cmp", `{a="b"} | json | line_format "{{__line__}}" | size > 1KB`, true},
		{"and_combined", `{a="b"} | json | line_format "{{__line__}}" | status="404" and level="error"`, true},
		{"and_combined_false", `{a="b"} | json | line_format "{{__line__}}" | status="404" and level="info"`, false},
		{"or_combined", `{a="b"} | json | line_format "{{__line__}}" | status="500" or level="error"`, true},
		{"comma_is_and", `{a="b"} | json | line_format "{{__line__}}" | status="404", level="error"`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := runQueryPipeline(t, tc.query, line, map[string]string{"a": "b"})
			if got := e != nil; got != tc.survives {
				t.Errorf("survives = %v, want %v", got, tc.survives)
			}
		})
	}
}

func TestPipeline_DropKeepAndDecolorize(t *testing.T) {
	t.Run("drop", func(t *testing.T) {
		e := runQueryPipeline(t, `{a="b"} | json | line_format "{{__line__}}" | drop status, level`, `{"status":"404","level":"error","keep":"me"}`, map[string]string{"a": "b"})
		if e == nil {
			t.Fatal("filtered out")
		}
		if _, ok := e.Labels["status"]; ok {
			t.Error("status should have been dropped")
		}
		if e.Labels["keep"] != "me" {
			t.Error("keep should have survived")
		}
	})
	t.Run("keep", func(t *testing.T) {
		e := runQueryPipeline(t, `{a="b"} | json | line_format "{{__line__}}" | keep status`, `{"status":"404","level":"error"}`, map[string]string{"a": "b"})
		if e == nil {
			t.Fatal("filtered out")
		}
		if len(e.Labels) != 1 || e.Labels["status"] != "404" {
			t.Errorf("keep should leave only status, got %v", e.Labels)
		}
	})
	t.Run("decolorize", func(t *testing.T) {
		e := runQueryPipeline(t, `{a="b"} | decolorize | line_format "{{__line__}}"`, esc+"[32mgreen"+esc+"[0m", map[string]string{"a": "b"})
		if e == nil {
			t.Fatal("filtered out")
		}
		if e.Line != "green" {
			t.Errorf("line = %q, want %q", e.Line, "green")
		}
	})
	t.Run("json_error_label", func(t *testing.T) {
		e := runQueryPipeline(t, `{a="b"} | json | line_format "{{__line__}}"`, `not json`, map[string]string{"a": "b"})
		if e == nil {
			t.Fatal("filtered out")
		}
		if e.Labels["__error__"] != "JSONParserErr" {
			t.Errorf("__error__ = %q, want JSONParserErr", e.Labels["__error__"])
		}
	})
}

// TestHasTemplateStage guards the pushdown boundary: only a stage carrying an
// actual `{{` action forces proxy-side evaluation, so constant formats and bare
// renames keep going to VictoriaLogs.
func TestHasTemplateStage(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{`{a="b"} | line_format "{{.x}}"`, true},
		{"{a=\"b\"} | line_format `{{.x}}`", true},
		{`{a="b"} | line_format ""`, false},
		{`{a="b"} | line_format "constant text"`, false},
		{`{a="b"} | label_format new=old`, false},
		{`{a="b"} | label_format env="prod"`, false},
		{`{a="b"} | label_format cls="{{.status}}"`, true},
		{`{a="b"} | json | drop x`, false},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			expr, err := Parse(tc.query)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			lq, ok := expr.(*LogQuery)
			if !ok {
				t.Fatalf("expected log query, got %T", expr)
			}
			if got := HasTemplateStage(lq.Pipeline); got != tc.want {
				t.Errorf("HasTemplateStage = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPipeline_RejectsUnknownTemplateFunction(t *testing.T) {
	expr, err := Parse(`{a="b"} | line_format "{{ .x | bogusFunc }}"`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	lq := expr.(*LogQuery)
	if _, err := NewPipeline(lq.Pipeline); err == nil {
		t.Fatal("expected NewPipeline to reject an unknown template function")
	} else if !strings.Contains(err.Error(), "bogusFunc") {
		t.Errorf("error should name the function, got: %v", err)
	}
}

func TestPipeline_LabelFormatSwapsRatherThanAliases(t *testing.T) {
	e := runQueryPipeline(t, `{a="b"} | json | label_format x=y, y=x | line_format "{{.x}}/{{.y}}"`,
		`{"x":"1","y":"2"}`, map[string]string{"a": "b"})
	if e == nil {
		t.Fatal("filtered out")
	}
	if e.Line != "2/1" {
		t.Errorf("line = %q, want %q — assignments must read the pre-stage labels", e.Line, "2/1")
	}
}

// TestPipeline_ErrorLabelSemantics pins Loki's parse-failure model: a failed
// parser records `__error__` on the entry, `| __error__=""` therefore EXCLUDES
// those entries, `| __error__!=""` keeps only them, and `| drop __error__`
// filters nothing. VictoriaLogs has no such flag, which is why these queries
// must be evaluated proxy-side.
func TestPipeline_ErrorLabelSemantics(t *testing.T) {
	good := `{"level":"info","msg":"ok"}`
	bad := `this is not json`

	cases := []struct {
		name, query      string
		goodOK, badOK    bool
		wantDroppedLabel bool
	}{
		{"error_empty_excludes_failures", `{a="b"} | json | __error__="" | line_format "{{__line__}}"`, true, false, false},
		{"error_nonempty_keeps_only_failures", `{a="b"} | json | __error__!="" | line_format "{{__line__}}"`, false, true, false},
		{"error_named_kind", `{a="b"} | json | __error__="JSONParserErr" | line_format "{{__line__}}"`, false, true, false},
		{"drop_error_filters_nothing", `{a="b"} | json | drop __error__, __error_details__ | line_format "{{__line__}}"`, true, true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := runQueryPipeline(t, tc.query, good, map[string]string{"a": "b"})
			if (g != nil) != tc.goodOK {
				t.Errorf("well-formed line survives = %v, want %v", g != nil, tc.goodOK)
			}
			b := runQueryPipeline(t, tc.query, bad, map[string]string{"a": "b"})
			if (b != nil) != tc.badOK {
				t.Errorf("malformed line survives = %v, want %v", b != nil, tc.badOK)
			}
			if tc.wantDroppedLabel && b != nil {
				if _, ok := b.Labels["__error__"]; ok {
					t.Errorf("drop __error__ should remove the label, got %v", b.Labels)
				}
			}
		})
	}
}

// TestNeedsProxyEvaluation guards the routing predicate for both families.
func TestNeedsProxyEvaluation(t *testing.T) {
	cases := []struct {
		query string
		want  bool
	}{
		{`{a="b"} | json | __error__=""`, true},
		{`{a="b"} | json | __error__!=""`, true},
		{`{a="b"} | json | __error_details__=""`, true},
		{`{a="b"} | json | drop __error__, __error_details__`, false},
		{`{a="b"} | json | level="error"`, false},
		{`{a="b"} | line_format "{{.x}}"`, true},
		{`{a="b"} | json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			expr, err := Parse(tc.query)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			lq, ok := expr.(*LogQuery)
			if !ok {
				t.Fatalf("expected log query, got %T", expr)
			}
			if got := NeedsProxyEvaluation(lq.Pipeline); got != tc.want {
				t.Errorf("NeedsProxyEvaluation = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPipeline_MalformedTemplateIsNotAQueryError pins the split Loki makes: an
// unknown FUNCTION fails the query, a template SYNTAX error does not (Loki
// answers 200 for `| line_format "{{.method"`), it just flags the entry.
func TestPipeline_MalformedTemplateIsNotAQueryError(t *testing.T) {
	expr, err := Parse(`{a="b"} | line_format "{{.method"`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	lq := expr.(*LogQuery)
	pipeline, err := NewPipeline(lq.Pipeline)
	if err != nil {
		t.Fatalf("a malformed template must not fail the query: %v", err)
	}
	e := &Entry{TS: time.Unix(0, 0), Line: "original", Labels: map[string]string{"a": "b"}}
	if !pipeline.Process(e) {
		t.Fatal("entry should survive")
	}
	if e.Line != "original" {
		t.Errorf("line should be untouched, got %q", e.Line)
	}
	if e.Labels["__error__"] != "TemplateFormatErr" {
		t.Errorf("__error__ = %q, want TemplateFormatErr", e.Labels["__error__"])
	}
}

// TestPipeline_ConcurrentUse hammers the package-level compile caches from many
// goroutines. Before they were guarded, this reproduced
// `fatal error: concurrent map writes` — which kills the PROCESS, taking every
// other in-flight query with it. Run under -race.
func TestPipeline_ConcurrentUse(t *testing.T) {
	queries := []string{
		`{a="b"} |~ "40[0-9]" | json | line_format "{{.status}}" | status=~"4.."`,
		`{a="b"} |~ "50[0-9]" | json | line_format "{{ upper .level }}" | status!~"2.."`,
		"{a=\"b\"} | regexp \"(?P<code>\\\\d{3})\" | label_format cls=`{{ printf \"%.1sxx\" .code }}`",
		`{a="b"} | logfmt | line_format "{{.msg}}" | dur > 10ms`,
		"{a=\"b\"} | pattern `<verb> <path>` | line_format `{{.verb}}`",
		`{a="b"} | json | __error__="" | line_format "{{__line__}}"`,
	}
	lines := []string{
		`{"status":"404","level":"error","msg":"x","dur":"250ms"}`,
		`{"status":"200","level":"info","msg":"y","dur":"5ms"}`,
		`level=warn msg="hi there" dur=90ms`,
		`GET /api/v1/users`,
		`not json at all`,
	}

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				q := queries[(g+i)%len(queries)]
				expr, err := Parse(q)
				if err != nil {
					t.Errorf("Parse(%q): %v", q, err)
					return
				}
				lq, ok := expr.(*LogQuery)
				if !ok {
					t.Errorf("expected a log query for %q", q)
					return
				}
				// Each goroutine compiles its OWN Pipeline — that is the
				// supported usage — but they all share the compile caches.
				pipeline, err := NewPipeline(lq.Pipeline)
				if err != nil {
					t.Errorf("NewPipeline(%q): %v", q, err)
					return
				}
				for _, line := range lines {
					e := &Entry{TS: time.Unix(1789041600, 0), Line: line, Labels: map[string]string{"a": "b"}}
					pipeline.Process(e)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestCompileCacheIsBounded proves the 1024-entry cap still holds now that the
// length check moved under the write lock.
func TestCompileCacheIsBounded(t *testing.T) {
	var c compileCache[int]
	for i := 0; i < compileCacheMaxEntries+50; i++ {
		c.put(strconv.Itoa(i), i)
	}
	c.mu.RLock()
	size := len(c.m)
	c.mu.RUnlock()
	if size != compileCacheMaxEntries {
		t.Errorf("cache size = %d, want %d", size, compileCacheMaxEntries)
	}
	if _, ok := c.get("0"); !ok {
		t.Error("early entries should survive; the cap drops NEW writes")
	}
}
