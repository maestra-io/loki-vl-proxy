package translator

import (
	"regexp"
	"strings"
	"testing"
)

// `level` is a STORED field; `detected_level` is the one Loki INFERS. Filling a
// stored level in from the message invented a series the store does not have:
// `sum by (level)` returned `{level="info"}` with 192 rows where Loki (and
// `stats by (level)` in VictoriaLogs) report an empty level on every row.
func TestLevelNormalizePipes_StoredLevelIsNotInferred(t *testing.T) {
	stored := &MappingOptions{
		DerivedLevelFields: []string{"level", "LogLevel"},
		MaterializeLevel:   true,
	}
	pipes := strings.Join(stored.levelNormalizePipes(), " ")
	if pipes == "" {
		t.Fatal("grouping by a stored level still needs its coalesce chain")
	}
	if strings.Contains(pipes, "extract_regexp") {
		t.Fatalf("`sum by (level)` must not read a level out of the message:\n%s", pipes)
	}

	inferred := &MappingOptions{
		DerivedLevelFields: []string{"level", "LogLevel"},
		MaterializeLevel:   true,
		InferLevelFromText: true,
	}
	if !strings.Contains(strings.Join(inferred.levelNormalizePipes(), " "), "extract_regexp") {
		t.Fatal("`sum by (detected_level)` still needs the line-text rule")
	}
}

// Loki's own canonical set for `detected_level`, measured on 3.7.1 over a
// 391-line corpus: it keeps `trace` distinct from `debug` and `critical`/`fatal`
// distinct from `error`, and labels what it cannot place `unknown` rather than
// leaving the label empty. The repo's synonym table folds all of those together,
// which is right for a STORED level and wrong for the derived one.
func TestLevelNormalizePipes_DetectedLevelUsesLokisCanonicalSet(t *testing.T) {
	m := &MappingOptions{
		DerivedLevelFields: []string{"level"},
		MaterializeLevel:   true,
		InferLevelFromText: true,
	}
	pipes := m.levelNormalizePipes()
	joined := strings.Join(pipes, " ")

	// The fallback covers a value Loki does not RECOGNISE as well as an empty one:
	// a derived field holding `custom` matches none of the replacements and is not
	// empty, so a guard on emptiness alone left `detected_level="custom"`.
	if !strings.Contains(joined, `| format if (-level:~"`+lokiDetectedLevelSetPattern()+`") "unknown" as level`) {
		t.Fatalf("no `unknown` fallback over the whole non-canonical set:\n%s", joined)
	}
	if strings.Contains(joined, `| format if (level:"") "unknown" as level`) {
		t.Fatalf("the fallback still only covers the EMPTY value:\n%s", joined)
	}
	// `trace` must be rewritten to itself BEFORE any stage whose alternation
	// contains it, or a later stage swallows it into `debug`.
	traceAt, debugAt := -1, -1
	for i, p := range pipes {
		if strings.Contains(p, `"trace")`) && traceAt < 0 {
			traceAt = i
		}
		if strings.Contains(p, `"debug")`) {
			debugAt = i
		}
	}
	if traceAt < 0 {
		t.Fatalf("no `trace` stage — it folds into `debug`:\n%s", joined)
	}
	if debugAt >= 0 && traceAt > debugAt {
		t.Fatalf("`trace` is normalised after `debug`, which swallows it:\n%s", joined)
	}
	for _, canonical := range []string{"critical", "fatal"} {
		if !strings.Contains(joined, `"`+canonical+`")`) {
			t.Errorf("no `%s` stage — it folds into `error`, which Loki does not do:\n%s", canonical, joined)
		}
	}
	// The `debug` alternation must no longer claim trace.
	for _, p := range pipes {
		if strings.Contains(p, `"debug")`) && strings.Contains(p, "trace") {
			t.Fatalf("the debug stage still swallows trace: %s", p)
		}
	}
}

// An unrecognised value must reach `unknown`, not survive as itself. Verified
// against VictoriaLogs on the 391-line corpus with `level="custom"` injected:
// the `custom` series disappears and the eight Loki buckets are unchanged.
func TestLokiDetectedLevelSetPattern_CoversExactlyLokisSet(t *testing.T) {
	re := regexp.MustCompile(lokiDetectedLevelSetPattern())
	for _, v := range []string{"trace", "debug", "info", "warn", "error", "critical", "fatal", "unknown", "ERROR"} {
		if !re.MatchString(v) {
			t.Errorf("%q is one of Loki's detected_level values", v)
		}
	}
	for _, v := range []string{"custom", "", "warning", "err", "notice", "information"} {
		if re.MatchString(v) {
			t.Errorf("%q is not a canonical detected_level — it must be rewritten before this guard", v)
		}
	}
}
