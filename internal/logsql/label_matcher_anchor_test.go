package logsql

import (
	"regexp"
	"testing"
)

// TestAnchorLabelMatcherRegex locks the Loki label-matcher contract: a label
// regex must match the WHOLE label value. VictoriaLogs' `field:~"re"` is an
// unanchored match, so an un-anchored pattern silently widens every `=~`
// matcher — and a widened matcher inflates counts instead of erroring.
func TestAnchorLabelMatcherRegex(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			// The reported case: `nch` must not match `anch` or `nch-b`.
			name: "plain literal",
			in:   "nch",
			want: "^(?:nch)$",
		},
		{
			// The group is load-bearing: "^a|b$" parses as "(^a)|(b$)", which
			// would match any value merely CONTAINING a or ending in b.
			name: "alternation is grouped, not split by the anchors",
			in:   "a|b",
			want: "^(?:a|b)$",
		},
		{
			name: "multi-branch alternation",
			in:   "prod|staging|dev",
			want: "^(?:prod|staging|dev)$",
		},
		{
			name: "match-all",
			in:   ".*",
			want: "^(?:.*)$",
		},
		{
			name: "prefix wildcard",
			in:   "api-.*",
			want: "^(?:api-.*)$",
		},
		{
			// Leading inline flags are hoisted so they still apply to the whole
			// pattern and the emitted LogsQL stays readable.
			name: "case-insensitive flag is hoisted out front",
			in:   "(?i)prod",
			want: "(?i)^(?:prod)$",
		},
		{
			name: "multiple flags hoisted",
			in:   "(?is)prod",
			want: "(?is)^(?:prod)$",
		},
		{
			// A scoped group carries its own body and must stay inside.
			name: "scoped flag group is not hoisted",
			in:   "(?i:prod)",
			want: "^(?:(?i:prod))$",
		},
		{
			name: "already anchored by the author is anchored again, harmlessly",
			in:   "^prod$",
			want: "^(?:^prod$)$",
		},
		{
			name: "character class",
			in:   "kafka-[23]",
			want: "^(?:kafka-[23])$",
		},
		{
			name: "empty pattern is left alone",
			in:   "",
			want: "",
		},
		{
			name: "flags with no body are left alone",
			in:   "(?i)",
			want: "(?i)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AnchorLabelMatcherRegex(tc.in)
			if got != tc.want {
				t.Errorf("AnchorLabelMatcherRegex(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got != "" {
				if _, err := regexp.Compile(got); err != nil {
					t.Errorf("AnchorLabelMatcherRegex(%q) = %q, which does not compile: %v", tc.in, got, err)
				}
			}
		})
	}
}

// TestAnchorLabelMatcherRegexMatchesLokiSemantics is the behavioural half: the
// anchored pattern must accept exactly the values Loki's fully-anchored matcher
// accepts. Table-driven over (pattern, value, shouldMatch) so a future
// "optimisation" of the wrapper cannot quietly change the matched set.
func TestAnchorLabelMatcherRegexMatchesLokiSemantics(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		// The exact reported defect.
		{"nch", "nch", true},
		{"nch", "anch", false},
		{"nch", "nch-b", false},
		{"anch", "anch", true},
		{"anch", "anch-b", false},

		// Alternation must not leak into a prefix/suffix match.
		{"a|b", "a", true},
		{"a|b", "b", true},
		{"a|b", "ab", false},
		{"a|b", "xa", false},
		{"a|b", "bx", false},
		{"prod|staging", "prod", true},
		{"prod|staging", "production", false},

		// Wildcards.
		{".*", "", true},
		{".*", "anything", true},
		{"api-.*", "api-gw", true},
		{"api-.*", "my-api-gw", false},

		// Flags survive the hoist.
		{"(?i)prod", "PROD", true},
		{"(?i)prod", "prod", true},
		{"(?i)prod", "production", false},

		// Character class.
		{"kafka-[23]", "kafka-2", true},
		{"kafka-[23]", "kafka-4", false},
		{"kafka-[23]", "my-kafka-2", false},
	}

	for _, tc := range tests {
		anchored := AnchorLabelMatcherRegex(tc.pattern)
		re, err := regexp.Compile(anchored)
		if err != nil {
			t.Fatalf("pattern %q -> %q does not compile: %v", tc.pattern, anchored, err)
		}
		if got := re.MatchString(tc.value); got != tc.want {
			t.Errorf("pattern %q (anchored %q) against %q = %v, want %v",
				tc.pattern, anchored, tc.value, got, tc.want)
		}
	}
}
