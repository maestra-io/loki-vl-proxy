package proxy

import (
	"testing"

	fj "github.com/valyala/fastjson"
)

// TestAddGroupByParsedLabelsFJUsesLokiNames locks the fix for the duplicated
// grouping label on the manual (parser-stage) metric path.
//
// groupBy carries VL field names, origGroupBy the Loki label names the client
// asked for. buildMetricSeriesEntry renames VL->Loki (e.g. VL "level" becomes
// Loki "detected_level" for `sum by (detected_level)`), and this function then
// injects the by(...) fields that only exist after a parser stage. It used to
// inject them under the VL name, re-adding the label the rename had just
// removed — so `sum by (detected_level) (...)` came back carrying BOTH
// detected_level AND level, one grouping dimension more than Loki returns.
func TestAddGroupByParsedLabelsFJUsesLokiNames(t *testing.T) {
	entry := `{"level":"error","method":"GET","status":"500","blank":""}`

	tests := []struct {
		name     string
		existing map[string]string
		groupBy  []string
		orig     []string
		want     map[string]string
	}{
		{
			// The reported case: the VL name must not come back alongside the
			// Loki name the caller asked for.
			name:     "vl name renamed to loki name",
			existing: map[string]string{"detected_level": "error"},
			groupBy:  []string{"level"},
			orig:     []string{"detected_level"},
			want:     map[string]string{"detected_level": "error"},
		},
		{
			name:     "field absent from labels is injected under loki name",
			existing: map[string]string{},
			groupBy:  []string{"level"},
			orig:     []string{"detected_level"},
			want:     map[string]string{"detected_level": "error"},
		},
		{
			// Identical names: nothing to rename, value comes from the entry.
			name:     "identical names inject as-is",
			existing: map[string]string{},
			groupBy:  []string{"method"},
			orig:     []string{"method"},
			want:     map[string]string{"method": "GET"},
		},
		{
			name:     "multiple fields keep positional alignment",
			existing: map[string]string{},
			groupBy:  []string{"level", "method"},
			orig:     []string{"detected_level", "method"},
			want:     map[string]string{"detected_level": "error", "method": "GET"},
		},
		{
			// Misaligned lengths must not mis-map: fall back to the VL names
			// rather than pairing the wrong label with the wrong field.
			name:     "misaligned origGroupBy falls back to vl names",
			existing: map[string]string{},
			groupBy:  []string{"level", "method"},
			orig:     []string{"detected_level"},
			want:     map[string]string{"level": "error", "method": "GET"},
		},
		{
			name:     "nil origGroupBy falls back to vl names",
			existing: map[string]string{},
			groupBy:  []string{"method"},
			orig:     nil,
			want:     map[string]string{"method": "GET"},
		},
		{
			name:     "empty field value is not injected",
			existing: map[string]string{},
			groupBy:  []string{"blank"},
			orig:     []string{"blank"},
			want:     map[string]string{},
		},
		{
			name:     "missing field is not injected",
			existing: map[string]string{},
			groupBy:  []string{"nonexistent"},
			orig:     []string{"nonexistent"},
			want:     map[string]string{},
		},
		{
			name:     "vl internal fields are skipped",
			existing: map[string]string{},
			groupBy:  []string{"_stream_id"},
			orig:     []string{"_stream_id"},
			want:     map[string]string{},
		},
		{
			// An existing Loki-named value wins: the stream label already
			// resolved it, the per-entry parse must not overwrite it.
			name:     "existing loki value is preserved",
			existing: map[string]string{"detected_level": "warn"},
			groupBy:  []string{"level"},
			orig:     []string{"detected_level"},
			want:     map[string]string{"detected_level": "warn"},
		},
	}

	var p fj.Parser
	v, err := p.Parse(entry)
	if err != nil {
		t.Fatalf("parse test entry: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			labels := make(map[string]string, len(tc.existing))
			for k, val := range tc.existing {
				labels[k] = val
			}

			addGroupByParsedLabelsFJ(labels, v, tc.groupBy, tc.orig)

			if len(labels) != len(tc.want) {
				t.Fatalf("labels = %v, want %v", labels, tc.want)
			}
			for k, want := range tc.want {
				if got := labels[k]; got != want {
					t.Errorf("labels[%q] = %q, want %q (full: %v)", k, got, want, labels)
				}
			}
		})
	}
}
