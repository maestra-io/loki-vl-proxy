package logsql_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// TestQuotePatternEscapesBackslashes pins the round-10 contract: a regexp
// embedded in a LogsQL string literal has every backslash DOUBLED, because
// VictoriaLogs unquotes the literal before compiling it. The old behaviour
// (backslash passed through verbatim) produced a query VictoriaLogs answers with
// HTTP 400 — `{namespace="status-router"} | json | detected_level = "error"` on
// us-omega, whose generated `_msg` filter carries `\[`.
//
// The round-trip assertion is the real contract, and it fails for every single
// input under the old escaping.
func TestQuotePatternEscapesBackslashes(t *testing.T) {
	patterns := []string{
		`\d+`,
		`\w+\s*`,
		`err\[`,
		`a\.b`,
		// The exact pattern that broke omega: LokiTextLevelPattern("error").
		`(?i)(?:^|[ \t\n="\[{(])(?:error|err)(?:$|[ \t\n="\[\]{}(),:!])`,
		`say "hi"`,
		`no-escapes-at-all`,
	}
	for _, pat := range patterns {
		quoted := logsql.QuotePattern(pat)
		// 1. It is a well-formed quoted literal that unquotes back to the pattern —
		//    this is exactly what VictoriaLogs does before handing it to RE2.
		got, err := strconv.Unquote(quoted)
		if err != nil {
			t.Errorf("QuotePattern(%q) = %s: not a valid quoted literal: %v", pat, quoted, err)
			continue
		}
		if got != pat {
			t.Errorf("QuotePattern(%q) round-trips to %q", pat, got)
		}
		// 2. What comes back still compiles as the regexp the caller asked for.
		if _, err := regexp.Compile(got); err != nil {
			t.Errorf("QuotePattern(%q) round-trips to an uncompilable regexp: %v", pat, err)
		}
		// 3. No LONE backslash survives into the literal body.
		body := quoted[1 : len(quoted)-1]
		for i := 0; i < len(body); i++ {
			if body[i] != '\\' {
				continue
			}
			if i+1 >= len(body) || !strings.ContainsRune(`\"nrtvfab0xuU'`, rune(body[i+1])) {
				t.Errorf("QuotePattern(%q) = %s: lone backslash at %d", pat, quoted, i)
			}
			i++ // skip the escaped char
		}
	}
}
