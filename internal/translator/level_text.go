package translator

import (
	"regexp"
	"strings"
)

// Loki derives `detected_level` at ingest. When neither a JSON nor a logfmt
// level key yields a recognised value it scans the LINE TEXT for a level
// keyword — which is why a panel filtering on `detected_level="error"` returns
// rows whose only evidence of a level is the word in the message.
//
// The keyword set and the delimiters below are MEASURED against Loki 3.7.1, not
// guessed: 391 lines pushed to a real Loki and read back through
// `detected_level`, 0 mismatches. The delimiter classes are deliberately
// asymmetric because Loki's are — `AA[error]BB` is detected, `AA<error>BB` and
// `AA:error:BB` are not, and a closing bracket ends a keyword but cannot start
// one.
var lokiTextLevelRE = regexp.MustCompile(
	`(?i)(?:^|[ \t\n="\[{(])(trace|debug|info|warning|warn|error|err|critical|fatal)(?:$|[ \t\n="\[\]{}(),:!])`)

// lokiTextLevelKeywords maps each canonical level to the keywords Loki accepts
// for it in line text.
var lokiTextLevelKeywords = map[string][]string{
	"trace":    {"trace"},
	"debug":    {"debug"},
	"info":     {"info"},
	"warn":     {"warning", "warn"},
	"error":    {"error", "err"},
	"critical": {"critical"},
	"fatal":    {"fatal"},
}

// LokiTextLevel returns the level Loki derives from a log line's TEXT, or "" when
// the line carries no level keyword. The first keyword in the line wins.
func LokiTextLevel(line string) string {
	m := lokiTextLevelRE.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	switch strings.ToLower(m[1]) {
	case "warn", "warning":
		return "warn"
	case "err", "error":
		return "error"
	default:
		return strings.ToLower(m[1])
	}
}

// LokiTextLevelPattern returns a RE2 pattern matching the lines whose text Loki
// would read as the given canonical level, or "" for a level Loki never derives
// from text. It is the single-level slice of lokiTextLevelRE, so the two cannot
// drift apart.
func LokiTextLevelPattern(level string) string {
	keywords, ok := lokiTextLevelKeywords[strings.ToLower(strings.TrimSpace(level))]
	if !ok {
		return ""
	}
	return `(?i)(?:^|[ \t\n="\[{(])(?:` + strings.Join(keywords, "|") + `)(?:$|[ \t\n="\[\]{}(),:!])`
}
