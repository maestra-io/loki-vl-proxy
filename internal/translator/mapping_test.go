package translator

import (
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// appChain is the omicron shape: `app` falls back from the plain pod label to
// the Kubernetes recommended label, whose name carries both dots and a slash.
var appChain = []string{
	"kubernetes.pod_labels.app",
	"kubernetes.pod_labels.app.kubernetes.io/name",
}

func chainMapping() *MappingOptions {
	return &MappingOptions{
		Expand: func(label string) []string {
			switch label {
			case "app":
				return appChain
			case "product":
				return []string{"kubernetes.pod_labels.product", "kubernetes.namespace_labels.product"}
			}
			return nil
		},
	}
}

func TestQuoteVLField(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"bare", "app", "app"},
		{"underscore", "pod_name", "pod_name"},
		{"digits", "field2", "field2"},
		{"leading digit", "2field", `"2field"`},
		{"dotted", "kubernetes.pod_labels.app", `"kubernetes.pod_labels.app"`},
		{"slashed", "kubernetes.pod_labels.app.kubernetes.io/name", `"kubernetes.pod_labels.app.kubernetes.io/name"`},
		{"already quoted", `"a.b"`, `"a.b"`},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := quoteVLField(tt.in); got != tt.want {
				t.Fatalf("quoteVLField(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFallbackChainSelectors(t *testing.T) {
	tests := []struct {
		name, logql, want string
	}{
		{
			name:  "exact match is a disjunction over the chain",
			logql: `{app="loki-vl-proxy"}`,
			want:  `("kubernetes.pod_labels.app":="loki-vl-proxy" OR "kubernetes.pod_labels.app.kubernetes.io/name":="loki-vl-proxy")`,
		},
		{
			name:  "regexp match is a disjunction over the chain",
			logql: `{app=~"trow.*"}`,
			want:  `("kubernetes.pod_labels.app":~"trow.*" OR "kubernetes.pod_labels.app.kubernetes.io/name":~"trow.*")`,
		},
		{
			name:  "negated exact match is a conjunction of negations",
			logql: `{app!="noisy"}`,
			want:  `(-"kubernetes.pod_labels.app":="noisy" -"kubernetes.pod_labels.app.kubernetes.io/name":="noisy")`,
		},
		{
			name:  "negated regexp match is a conjunction of negations",
			logql: `{app!~"noisy.*"}`,
			want:  `(-"kubernetes.pod_labels.app":~"noisy.*" -"kubernetes.pod_labels.app.kubernetes.io/name":~"noisy.*")`,
		},
		{
			name:  "empty value means none of the chained fields is set",
			logql: `{app=""}`,
			want:  `(-"kubernetes.pod_labels.app":* -"kubernetes.pod_labels.app.kubernetes.io/name":*)`,
		},
		{
			name:  "non-empty means at least one chained field is set",
			logql: `{app!=""}`,
			want:  `("kubernetes.pod_labels.app":!"" OR "kubernetes.pod_labels.app.kubernetes.io/name":!"")`,
		},
		{
			name:  "chain composes with an unmapped matcher",
			logql: `{namespace="trow-system", app="trow"}`,
			want:  `namespace:="trow-system" ("kubernetes.pod_labels.app":="trow" OR "kubernetes.pod_labels.app.kubernetes.io/name":="trow")`,
		},
		{
			name:  "chain in a pipeline label filter",
			logql: `{namespace="ns"} | app="trow"`,
			want:  `namespace:="ns" ("kubernetes.pod_labels.app":="trow" OR "kubernetes.pod_labels.app.kubernetes.io/name":="trow")`,
		},
		{
			name:  "second chain is independent",
			logql: `{product="cdp"}`,
			want:  `("kubernetes.pod_labels.product":="cdp" OR "kubernetes.namespace_labels.product":="cdp")`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslateLogQLWithMapping(tt.logql, nil, nil, logsql.Capabilities{}, chainMapping())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestFallbackChainNeverUsesNativeStreamSelector(t *testing.T) {
	// `app` is declared a stream field, but it is backed by a chain — a native
	// {app="x"} stream selector would match neither VL field.
	streamFields := map[string]bool{"app": true, "namespace": true}
	got, err := TranslateLogQLWithMapping(`{namespace="ns", app="trow"}`, nil, streamFields, logsql.Capabilities{}, chainMapping())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "{app=") {
		t.Fatalf("chain label leaked into a native stream selector: %s", got)
	}
	if !strings.Contains(got, `"kubernetes.pod_labels.app":="trow"`) {
		t.Fatalf("chain not expanded: %s", got)
	}
}

func TestSingleFieldMappingIsUnchanged(t *testing.T) {
	// A mapping with exactly one field must keep the upstream translation path.
	mapping := &MappingOptions{Expand: func(string) []string { return nil }}
	got, err := TranslateLogQLWithMapping(`{namespace="ns"}`, nil, nil, logsql.Capabilities{}, mapping)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := TranslateLogQL(`{namespace="ns"}`)
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNilMappingMatchesUpstream(t *testing.T) {
	for _, q := range []string{
		`{namespace="ns"}`,
		`{namespace="ns"} |= "boom" | json | level="error"`,
		`sum by (pod) (rate({namespace="ns"}[5m]))`,
		`{detected_level="error"}`,
	} {
		want, wantErr := TranslateLogQLWithCapabilities(q, nil, nil, logsql.Capabilities{})
		got, gotErr := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, nil)
		if got != want || (gotErr == nil) != (wantErr == nil) {
			t.Fatalf("%s: got (%s,%v), want (%s,%v)", q, got, gotErr, want, wantErr)
		}
	}
}

func computedMapping() *MappingOptions {
	return &MappingOptions{
		Computed: []ComputedLabel{{LokiLabel: "job", Join: []string{"namespace", "app"}, Sep: "/"}},
	}
}

func TestComputedLabelSelectors(t *testing.T) {
	tests := []struct {
		name, logql, want, wantErr string
	}{
		{
			name:  "exact match splits on the separator",
			logql: `{job="trow-system/trow"}`,
			want:  `(namespace:="trow-system" app:="trow")`,
		},
		{
			name:  "negated match is the disjunction of negations",
			logql: `{job!="trow-system/trow"}`,
			want:  `(-namespace:="trow-system" OR -app:="trow")`,
		},
		{
			name:  "last component absorbs extra separators",
			logql: `{job="ns/team/app"}`,
			want:  `(namespace:="ns" app:="team/app")`,
		},
		{
			name:    "regexp match is rejected with a usable message",
			logql:   `{job=~"trow-system/.*"}`,
			wantErr: `computed label "job" supports only = and !=`,
		},
		{
			// Emitting only namespace:="trow-system" would match EVERY app in the
			// namespace, while Loki matches nothing for this selector.
			name:    "too few components is rejected, never widened",
			logql:   `{job="trow-system"}`,
			wantErr: `computed label "job" expects 2 components separated by "/"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslateLogQLWithMapping(tt.logql, nil, nil, logsql.Capabilities{}, computedMapping())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got (%s, %v), want error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

func TestComputedLabelOverChains(t *testing.T) {
	mapping := chainMapping()
	mapping.Computed = computedMapping().Computed
	got, err := TranslateLogQLWithMapping(`{job="trow-system/trow"}`, nil, nil, logsql.Capabilities{}, mapping)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `(namespace:="trow-system" ("kubernetes.pod_labels.app":="trow" OR "kubernetes.pod_labels.app.kubernetes.io/name":="trow"))`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func levelMapping(materialize bool) *MappingOptions {
	return &MappingOptions{
		DerivedLevelFields: []string{"level", "loglevel"},
		MaterializeLevel:   materialize,
	}
}

func TestLevelValuePattern(t *testing.T) {
	tests := []struct{ in, want string }{
		{"info", `(?i)^(info|information|informational|notice)$`},
		{"warn", `(?i)^(warn|warning|warnings)$`},
		{"error", `(?i)^(err|error|errors|fatal|critical|crit|emerg|panic|alert)$`},
		{"debug", `(?i)^(debug|trace|fine|verbose)$`},
		{"custom", `(?i)^(custom)$`},
		{"a.b", `(?i)^(a\.b)$`},
	}
	for _, tt := range tests {
		if got := levelValuePattern(tt.in); got != tt.want {
			t.Fatalf("levelValuePattern(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDerivedLevelSelectors(t *testing.T) {
	tests := []struct {
		name, logql string
		wantParts   []string
	}{
		{
			name:      "level matcher unpacks json then logfmt and filters both raw fields",
			logql:     `{namespace="ns", level="error"}`,
			wantParts: []string{`namespace:="ns"`, "| unpack_json", "| unpack_logfmt", `| filter (level:~"(?i)^(err|error|errors|fatal|critical|crit|emerg|panic|alert)$" OR loglevel:~"(?i)^(err|`},
		},
		{
			name:      "information maps onto info",
			logql:     `{level="info"}`,
			wantParts: []string{`loglevel:~"(?i)^(info|information|informational|notice)$"`},
		},
		{
			name:      "detected_level is the same label",
			logql:     `{detected_level="warn"}`,
			wantParts: []string{`loglevel:~"(?i)^(warn|warning|warnings)$"`},
		},
		{
			name:      "negated level is a conjunction",
			logql:     `{namespace="ns", level!="error"}`,
			wantParts: []string{`| filter (-level:~"(?i)^(err|`, ` -loglevel:~"(?i)^(err|`},
		},
		{
			name:      "pipeline level filter gets its own unpack chain",
			logql:     `{namespace="ns"} | level="error"`,
			wantParts: []string{"| unpack_json", "| unpack_logfmt", "| filter (level:~"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TranslateLogQLWithMapping(tt.logql, nil, nil, logsql.Capabilities{}, levelMapping(false))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, part := range tt.wantParts {
				if !strings.Contains(got, part) {
					t.Fatalf("got %s\nmissing %q", got, part)
				}
			}
		})
	}
}

func TestDerivedLevelMaterialization(t *testing.T) {
	got, err := TranslateLogQLWithMapping(`{namespace="ns"}`, nil, nil, logsql.Capabilities{}, levelMapping(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, part := range []string{
		"| unpack_json",
		"| unpack_logfmt",
		"| coalesce(level, loglevel) as level",
		"| replace_regexp (level, `(?i)^(err|error|errors|fatal|critical|crit|emerg|panic|alert)$`, \"error\")",
		"| replace_regexp (level, `(?i)^(info|information|informational|notice)$`, \"info\")",
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("got %s\nmissing %q", got, part)
		}
	}
	// A query that already unpacks must not be unpacked twice — but it must still
	// get the coalesce/normalise chain, or `sum by (level)` over a parser query
	// silently groups on the raw stored field.
	for _, q := range []string{
		`{namespace="ns"} | json`,
		`sum by (level) (count_over_time({namespace="ns"} | json [5m]))`,
	} {
		got2, err := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, levelMapping(true))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", q, err)
		}
		if strings.Count(got2, "unpack_json") != 1 {
			t.Fatalf("%s: expected a single unpack_json, got %s", q, got2)
		}
		if !strings.Contains(got2, "| coalesce(level, loglevel) as level") {
			t.Fatalf("%s: missing the coalesce pipe: %s", q, got2)
		}
		if !strings.Contains(got2, "| replace_regexp (level,") {
			t.Fatalf("%s: missing the normalisation pipes: %s", q, got2)
		}
	}
}

func TestSplitComputedValue(t *testing.T) {
	spec := ComputedLabel{LokiLabel: "job", Join: []string{"namespace", "app"}}
	tests := []struct {
		in   string
		want []string
	}{
		{"ns/app", []string{"ns", "app"}},
		{"ns/team/app", []string{"ns", "team/app"}},
		{"ns", []string{"ns"}},
	}
	for _, tt := range tests {
		got := splitComputedValue(tt.in, spec)
		if len(got) != len(tt.want) {
			t.Fatalf("splitComputedValue(%q) = %v, want %v", tt.in, got, tt.want)
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Fatalf("splitComputedValue(%q) = %v, want %v", tt.in, got, tt.want)
			}
		}
	}
}
