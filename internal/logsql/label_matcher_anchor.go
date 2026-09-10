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
// Leading inline flags are SCOPED to the body — `(?i)abc` becomes
// `^(?:(?i:abc))$` — never hoisted in front of the anchors: a hoisted `(?m)`
// makes ^ and $ match at line boundaries, which would let a multi-line value
// satisfy a matcher for one of its lines.
//
// An empty pattern is anchored like any other: Loki's `=~""` matches only the
// empty value, so it becomes `^(?:)$` rather than an unanchored match-all.
//
// Line filters (`|~`) must NOT go through this: Loki's `|~` is a substring
// regexp over the log line, which is what VL already does.
func AnchorLabelMatcherRegex(pattern string) string {
	flags, body := splitLeadingRegexFlags(pattern)

	// Scope each leading flag group to the body instead of hoisting it in front
	// of the anchors. `(?m)` hoisted out would make ^ and $ match at LINE
	// boundaries, so `(?m)foo` would accept the value "foo\nbar" — the anchors
	// stop meaning "the whole value", which is the one thing they are for.
	// Nesting preserves the groups' original order and is always valid:
	// `(?i)(?s)foo` -> `^(?:(?i:(?s:foo)))$`.
	inner := body
	for i := len(flags) - 1; i >= 0; i-- {
		inner = "(?" + flags[i] + ":" + inner + ")"
	}
	return "^(?:" + inner + ")$"
}

// splitLeadingRegexFlags peels the leading inline-flag groups off a pattern,
// returning their flag strings in order plus the remaining body. `(?i)(?s)foo`
// yields (["i", "s"], "foo"). A scoped group like `(?i:…)` carries its own body
// and is left in place.
func splitLeadingRegexFlags(pattern string) ([]string, string) {
	var flags []string
	rest := pattern
	for {
		m := leadingRegexFlagsRE.FindStringSubmatch(rest)
		if m == nil {
			return flags, rest
		}
		flags = append(flags, m[1])
		rest = rest[len(m[0]):]
	}
}

// leadingRegexFlagsRE matches a leading inline-flag group such as `(?i)`,
// `(?is)`, `(?-s)` or `(?i-s)`, capturing the flag string. It deliberately does
// not match `(?i:...)`, which is a scoped group carrying its own body.
var leadingRegexFlagsRE = regexp.MustCompile(`^\(\?([imsU]+(?:-[imsU]+)?|-[imsU]+)\)`)
