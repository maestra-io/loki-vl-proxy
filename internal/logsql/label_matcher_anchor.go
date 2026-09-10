package logsql

import "regexp"

// AnchorLabelMatcherRegex wraps a Loki LABEL-matcher regexp so it must match the
// WHOLE label value.
//
// This is Loki semantics, not an option: `{namespace=~"nch"}` matches only the
// exact value `nch`, never `anch` or `nch-b`. VictoriaLogs' `field:~"re"` is an
// UNANCHORED match, so passing the pattern through verbatim silently widens
// every `=~` matcher — and a widened matcher inflates counts rather than
// erroring, so nothing surfaces it.
//
// The non-capturing group is load-bearing: `^a|b$` parses as `(^a)|(b$)`, so an
// alternation must be grouped before it is anchored.
//
// Leading inline flags are hoisted out front — `(?i)abc` becomes
// `(?i)^(?:abc)$` — so the flags keep applying to the whole pattern and the
// result stays readable in logs.
//
// Line filters (`|~`) must NOT go through this: Loki's `|~` is a substring
// regexp over the log line, which is what VL already does.
func AnchorLabelMatcherRegex(pattern string) string {
	if pattern == "" {
		return pattern
	}
	flags := ""
	rest := pattern
	for {
		m := leadingRegexFlagsRE.FindStringSubmatch(rest)
		if m == nil {
			break
		}
		flags += m[0]
		rest = rest[len(m[0]):]
	}
	if rest == "" {
		// Pattern was nothing but flags; anchoring an empty body would match
		// only the empty string, so leave it alone.
		return pattern
	}
	return flags + "^(?:" + rest + ")$"
}

// leadingRegexFlagsRE matches a leading inline-flag group such as `(?i)` or
// `(?is)`. It deliberately does not match `(?i:...)`, which is a scoped group
// carrying its own body and must stay inside the anchors.
var leadingRegexFlagsRE = regexp.MustCompile(`^\(\?[imsU]+\)`)
