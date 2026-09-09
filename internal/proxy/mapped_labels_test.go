package proxy

import (
	"reflect"
	"testing"
)

var omicronMappings = []FieldMapping{
	{VLField: "kubernetes.pod_namespace", LokiLabel: "namespace"},
	{VLFields: []string{"kubernetes.pod_labels.app", "kubernetes.pod_labels.app.kubernetes.io/name"}, LokiLabel: "app"},
	{VLFields: []string{"kubernetes.pod_labels.product", "kubernetes.namespace_labels.product"}, LokiLabel: "product"},
}

func TestFieldMappingFields(t *testing.T) {
	tests := []struct {
		name string
		in   FieldMapping
		want []string
	}{
		{"single field", FieldMapping{VLField: "a", LokiLabel: "l"}, []string{"a"}},
		{"chain wins over single", FieldMapping{VLField: "a", VLFields: []string{"b", "c"}, LokiLabel: "l"}, []string{"b", "c"}},
		{"blanks dropped", FieldMapping{VLFields: []string{" b ", "", "c"}, LokiLabel: "l"}, []string{"b", "c"}},
		{"duplicates collapsed", FieldMapping{VLFields: []string{"b", "b"}, LokiLabel: "l"}, []string{"b"}},
		{"empty", FieldMapping{LokiLabel: "l"}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.in.Fields(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Fields() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLabelTranslatorFallbackChains(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, omicronMappings)

	if got := lt.ToVLFields("app"); !reflect.DeepEqual(got, []string{"kubernetes.pod_labels.app", "kubernetes.pod_labels.app.kubernetes.io/name"}) {
		t.Fatalf("ToVLFields(app) = %v", got)
	}
	if got := lt.ToVLFields("namespace"); !reflect.DeepEqual(got, []string{"kubernetes.pod_namespace"}) {
		t.Fatalf("ToVLFields(namespace) = %v", got)
	}
	if got := lt.ToVLFields("nope"); got != nil {
		t.Fatalf("ToVLFields(nope) = %v, want nil", got)
	}
	// Single-field call sites keep resolving to the primary field.
	if got := lt.ToVL("app"); got != "kubernetes.pod_labels.app" {
		t.Fatalf("ToVL(app) = %q", got)
	}
	// Every chained field maps forward to the same Loki label.
	if got := lt.ToLoki("kubernetes.pod_labels.app.kubernetes.io/name"); got != "app" {
		t.Fatalf("ToLoki(fallback field) = %q", got)
	}
	if !lt.HasFallbackChains() {
		t.Fatal("HasFallbackChains() = false")
	}
	if got := lt.MappedVLFields(); len(got) != 5 {
		t.Fatalf("MappedVLFields() = %v, want 5 entries", got)
	}
}

func TestResolveLabelCandidatesUnionsTheChain(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, omicronMappings)
	available := []string{
		"kubernetes.pod_namespace",
		"kubernetes.pod_labels.app",
		"kubernetes.pod_labels.app.kubernetes.io/name",
	}
	got := lt.ResolveLabelCandidates("app", available)
	want := []string{"kubernetes.pod_labels.app", "kubernetes.pod_labels.app.kubernetes.io/name"}
	if !reflect.DeepEqual(got.candidates, want) {
		t.Fatalf("candidates = %v, want %v", got.candidates, want)
	}
	// Only the second chain member is present in the inventory.
	got = lt.ResolveLabelCandidates("app", []string{"kubernetes.pod_labels.app.kubernetes.io/name"})
	if !reflect.DeepEqual(got.candidates, []string{"kubernetes.pod_labels.app.kubernetes.io/name"}) {
		t.Fatalf("candidates = %v", got.candidates)
	}
	// No inventory at all still yields the whole chain so label_values can union.
	got = lt.ResolveLabelCandidates("app", nil)
	if !reflect.DeepEqual(got.candidates, want) {
		t.Fatalf("candidates without inventory = %v, want %v", got.candidates, want)
	}
}

func TestApplyLabelPromotions(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, omicronMappings)
	proms := buildLabelPromotions(lt, []ComputedLabel{{LokiLabel: "job", Join: []string{"namespace", "app"}, Sep: "/"}})

	tests := []struct {
		name   string
		labels map[string]string
		fields map[string]string
		want   map[string]string
	}{
		{
			name:   "primary field wins",
			labels: map[string]string{"namespace": "trow-system"},
			fields: map[string]string{
				"kubernetes.pod_labels.app":                    "trow",
				"kubernetes.pod_labels.app.kubernetes.io/name": "trow-chart",
			},
			want: map[string]string{"namespace": "trow-system", "app": "trow", "job": "trow-system/trow"},
		},
		{
			name:   "falls back to the second field",
			labels: map[string]string{"namespace": "ns"},
			fields: map[string]string{"kubernetes.pod_labels.app.kubernetes.io/name": "grafana"},
			want:   map[string]string{"namespace": "ns", "app": "grafana", "job": "ns/grafana"},
		},
		{
			name:   "empty primary is skipped",
			labels: map[string]string{"namespace": "ns"},
			fields: map[string]string{
				"kubernetes.pod_labels.app":                    "   ",
				"kubernetes.pod_labels.app.kubernetes.io/name": "grafana",
			},
			want: map[string]string{"namespace": "ns", "app": "grafana", "job": "ns/grafana"},
		},
		{
			name:   "product falls back to the namespace label",
			labels: map[string]string{},
			fields: map[string]string{"kubernetes.namespace_labels.product": "cdp"},
			want:   map[string]string{"product": "cdp"},
		},
		{
			name:   "computed label needs every part",
			labels: map[string]string{},
			fields: map[string]string{"kubernetes.pod_labels.app": "trow"},
			want:   map[string]string{"app": "trow"},
		},
		{
			name:   "existing label is never overwritten",
			labels: map[string]string{"app": "explicit"},
			fields: map[string]string{"kubernetes.pod_labels.app": "trow"},
			want:   map[string]string{"app": "explicit"},
		},
		{
			name:   "nothing to promote",
			labels: map[string]string{"namespace": "ns"},
			fields: map[string]string{},
			want:   map[string]string{"namespace": "ns"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			labels := map[string]string{}
			for k, v := range tt.labels {
				labels[k] = v
			}
			applyLabelPromotions(proms, labels, func(f string) string { return tt.fields[f] })
			if !reflect.DeepEqual(labels, tt.want) {
				t.Fatalf("labels = %v, want %v", labels, tt.want)
			}
		})
	}
}

func TestNormalizeLevelValue(t *testing.T) {
	tests := []struct{ in, want string }{
		{"information", "info"}, {"Information", "info"}, {"INFO", "info"},
		{"warning", "warn"}, {"Warning", "warn"}, {"warn", "warn"},
		{"error", "error"}, {"Error", "error"}, {"fatal", "error"}, {"crit", "error"},
		{"debug", "debug"}, {"trace", "trace"},
		{"", ""}, {"Weird", "weird"},
	}
	for _, tt := range tests {
		if got := normalizeLevelValue(tt.in); got != tt.want {
			t.Fatalf("normalizeLevelValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestLevelFromSubstring(t *testing.T) {
	tests := []struct{ in, want string }{
		{"nothing here", ""},
		{"a DEBUG line", "debug"},
		{"a warning happened", "warn"},
		{"an Error occurred", "error"},
		{"debug beats warn when both appear", "debug"},
	}
	for _, tt := range tests {
		if got := levelFromSubstring(tt.in); got != tt.want {
			t.Fatalf("levelFromSubstring(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestApplyDerivedLevel(t *testing.T) {
	off := &Proxy{}
	on := &Proxy{derivedLevelFields: []string{"level", "loglevel"}}
	tests := []struct {
		name   string
		p      *Proxy
		labels map[string]string
		msg    string
		want   map[string]string
	}{
		{
			name: "disabled leaves labels untouched",
			p:    off, labels: map[string]string{}, msg: `{"loglevel":"warning"}`,
			want: map[string]string{},
		},
		{
			name: "loglevel key from the message body",
			p:    on, labels: map[string]string{}, msg: `{"loglevel":"information","message":"hi"}`,
			want: map[string]string{"level": "info", "detected_level": "info"},
		},
		{
			name: "warning normalises to warn",
			p:    on, labels: map[string]string{}, msg: `{"loglevel":"warning"}`,
			want: map[string]string{"level": "warn", "detected_level": "warn"},
		},
		{
			name: "existing raw level is normalised",
			p:    on, labels: map[string]string{"level": "Error"}, msg: "",
			want: map[string]string{"level": "error", "detected_level": "error"},
		},
		{
			name: "substring fallback for unstructured lines",
			p:    on, labels: map[string]string{}, msg: "connection reset, will warn upstream",
			want: map[string]string{"level": "warn", "detected_level": "warn"},
		},
		{
			name: "no level anywhere",
			p:    on, labels: map[string]string{"namespace": "ns"}, msg: "all good",
			want: map[string]string{"namespace": "ns"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.p.applyDerivedLevel(tt.labels, tt.msg)
			if !reflect.DeepEqual(tt.labels, tt.want) {
				t.Fatalf("labels = %v, want %v", tt.labels, tt.want)
			}
		})
	}
}

func TestLineFieldSkip(t *testing.T) {
	upstream := &Proxy{}
	msgLine := &Proxy{lineFieldMsg: true}
	tests := []struct {
		name      string
		p         *Proxy
		msg       string
		querySkip bool
		want      bool
	}{
		{"upstream default reconstructs", upstream, "hello", false, false},
		{"upstream honours the parser flag", upstream, "hello", true, true},
		{"msg line returns the message", msgLine, `{"message":"hi"}`, false, true},
		{"msg line falls back when _msg is missing", msgLine, "missing _msg field; see https://docs.victoriametrics.com/victorialogs/keyconcepts/#message-field", false, false},
		{"msg line falls back on an empty message", msgLine, "   ", false, false},
		{"parser flag still wins", msgLine, "hello", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.lineFieldSkip(tt.msg, tt.querySkip); got != tt.want {
				t.Fatalf("lineFieldSkip = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNamedCaptureFields(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  []string
	}{
		{"no parser", `{app="x"} |= "boom"`, nil},
		{"regexp named group", `{app="x"} | regexp "sent (?P<status>[0-9]{3})"`, []string{"status"}},
		{"go style group", `{app="x"} | regexp "(?<status>[0-9]{3})"`, []string{"status"}},
		{"pattern placeholders", `{app="x"} | pattern "<ip> - <method>"`, []string{"ip", "method"}},
		{"unnamed groups ignored", `{app="x"} | regexp "([0-9]{3})"`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := namedCaptureFields(tt.query)
			if len(got) != len(tt.want) {
				t.Fatalf("namedCaptureFields = %v, want %v", got, tt.want)
			}
			for _, w := range tt.want {
				if _, ok := got[w]; !ok {
					t.Fatalf("namedCaptureFields = %v, missing %q", got, w)
				}
			}
		})
	}
}

func TestBuildMappingOptions(t *testing.T) {
	lt := NewLabelTranslator(LabelStyleUnderscores, omicronMappings)
	plain := &Proxy{labelTranslator: NewLabelTranslator(LabelStylePassthrough, nil)}
	if got := plain.buildMappingOptions(`{app="x"}`); got != nil {
		t.Fatalf("unconfigured proxy must not build mapping options, got %+v", got)
	}
	p := &Proxy{
		labelTranslator:     lt,
		computedLabels:      []ComputedLabel{{LokiLabel: "job", Join: []string{"namespace", "app"}}},
		derivedLevelFields:  []string{"level", "loglevel"},
		derivedLevelGroupBy: true,
	}
	opts := p.buildMappingOptions(`sum by (level) (count_over_time({app="x"}[5m]))`)
	if opts == nil || !opts.MaterializeLevel {
		t.Fatalf("expected MaterializeLevel for a level-referencing query, got %+v", opts)
	}
	if got := opts.Expand("app"); len(got) != 2 {
		t.Fatalf("Expand(app) = %v", got)
	}
	if got := opts.Expand("namespace"); got != nil {
		t.Fatalf("single-field mapping must not expand, got %v", got)
	}
	if opts2 := p.buildMappingOptions(`{app="x"}`); opts2.MaterializeLevel {
		t.Fatal("query without a level reference must not materialise level")
	}
}
