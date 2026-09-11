package translator

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// mustUnquoteLiterals pulls every double-quoted span out of a LogsQL query and
// unquotes it the way VictoriaLogs does. A span that will not unquote is the
// HTTP 400 the backend returns.
func mustUnquoteLiterals(t *testing.T, query string) {
	t.Helper()
	for i := 0; i < len(query); i++ {
		if query[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(query) {
			if query[j] == '\\' {
				j += 2
				continue
			}
			if query[j] == '"' {
				break
			}
			j++
		}
		if j >= len(query) {
			t.Fatalf("unterminated literal in %q", query)
		}
		span := query[i : j+1]
		if _, err := strconv.Unquote(span); err != nil {
			t.Errorf("VictoriaLogs cannot unquote %s in %q: %v", span, query, err)
		}
		i = j
	}
}

// TestDerivedLevelFilterIsAcceptableLogsQL is CM16. The line-text heuristic that
// backs `detected_level = "error"` embeds a regexp with a `\[` character class
// into the generated LogsQL. With the regexp quoted at single-backslash depth,
// VictoriaLogs rejects the whole query — the omega symptom was HTTP 400 on
// `{namespace="status-router"} | json | detected_level = "error"`.
//
// The sibling `by (detected_level)` path quoted the same family of pattern
// correctly, which is why only one of the two broke.
func TestDerivedLevelFilterIsAcceptableLogsQL(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level", "severity"}}
	for _, level := range []string{"error", "warn", "info", "debug", "critical", "fatal", "trace"} {
		got := m.derivedLevelFilter(level, false, false)
		if got == "" {
			t.Fatalf("derivedLevelFilter(%q) produced nothing", level)
		}
		if !strings.Contains(got, "_msg:~") {
			t.Errorf("derivedLevelFilter(%q) lost the line-text fallback: %s", level, got)
		}
		mustUnquoteLiterals(t, got)
	}
}

// The normalise pipe chain feeds the `by (detected_level)` path. It was already
// correct; the test keeps the two paths from drifting apart again.
func TestLevelNormalizePipesAreAcceptableLogsQL(t *testing.T) {
	m := &MappingOptions{
		DerivedLevelFields: []string{"level", "severity", "lvl"},
		MaterializeLevel:   true,
		InferLevelFromText: true,
	}
	pipes := m.levelNormalizePipes()
	if len(pipes) == 0 {
		t.Fatal("no pipes")
	}
	mustUnquoteLiterals(t, strings.Join(pipes, " "))
}

// A whole-query check over the shapes that put a regexp into LogsQL, so a new
// call site that hand-rolls its own quoting is caught here rather than on omega.
func TestTranslatedQueriesCarryAcceptableLiterals(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"level"}}
	queries := []string{
		`{namespace="status-router"} | json | detected_level = "error"`,
		`{app="x"} |= "manifests."`,
		`{app="x"} |~ "a\\[b"`,
		`{app="x"} != "C:\\temp"`,
		`{app="x"} | json | path =~ "/v\\d+/"`,
		`{app="x"} |= ip("10.0.0.0/8")`,
		`{app="x"} | k8s . ` + "`cluster.`",
	}
	for _, q := range queries {
		got, err := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, m)
		if err != nil {
			continue // a query this fork declines is not this test's subject
		}
		mustUnquoteLiterals(t, got)
	}
}
