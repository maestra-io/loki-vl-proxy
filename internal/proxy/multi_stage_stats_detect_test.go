package proxy

import "testing"

// TestIsMultiStageStatsQuery locks the stage COUNT against text that merely
// looks like a stage. The detector routes queries away from the stats-compat
// layer, so a false positive silently changes which engine answers a query.
func TestIsMultiStageStatsQuery(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "single stats stage",
			in:   `ns:="a" | unpack_json | stats count()`,
			want: false,
		},
		{
			name: "two stats stages",
			in:   `ns:="a" | unpack_json | stats by (x) max(D) as __lvp_inner | stats sum(__lvp_inner)`,
			want: true,
		},
		{
			// A line filter carrying the literal text is DATA, not a stage.
			// `{...} |= "| stats "` translates to `~"| stats "`.
			name: "quoted stage text in a line filter is not a stage",
			in:   `ns:="a" ~"| stats " | unpack_json | stats count()`,
			want: false,
		},
		{
			name: "quoted stage text alongside a real second stage",
			in:   `ns:="a" ~"| stats " | stats by (x) max(D) as __lvp_inner | stats sum(__lvp_inner)`,
			want: true,
		},
		{
			name: "backtick-quoted stage text is not a stage",
			in:   "ns:=\"a\" ~`| stats ` | unpack_json | stats count()",
			want: false,
		},
		{
			name: "escaped quote inside the filter does not end the span",
			in:   `ns:="a" ~"say \" | stats " | stats count()`,
			want: false,
		},
		{
			// Rate pipelines are two-stage by construction and keep their own
			// manual handling; | math identifies them.
			name: "math rate pipeline is exempt",
			in:   `ns:="a" | stats by (_stream) count() as __lvp_inner | math __lvp_inner/600 as __lvp_rate | stats by (_stream) sum(__lvp_rate)`,
			want: false,
		},
		{
			name: "quoted math text does not exempt a real two-stage query",
			in:   `ns:="a" ~"| math " | stats by (x) max(D) as __lvp_inner | stats sum(__lvp_inner)`,
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMultiStageStatsQuery(tc.in); got != tc.want {
				t.Errorf("isMultiStageStatsQuery(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
