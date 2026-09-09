package main

import (
	"strings"
	"testing"
)

func TestParseFieldMappingsChain(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantLabels []string
		wantFields [][]string
		wantErr    bool
	}{
		{name: "empty", raw: ""},
		{
			name:       "single field form",
			raw:        `[{"vl_field":"service.name","loki_label":"service_name"}]`,
			wantLabels: []string{"service_name"},
			wantFields: [][]string{{"service.name"}},
		},
		{
			name:       "fallback chain form",
			raw:        `[{"vl_fields":["kubernetes.pod_labels.app","kubernetes.pod_labels.app.kubernetes.io/name"],"loki_label":"app"}]`,
			wantLabels: []string{"app"},
			wantFields: [][]string{{"kubernetes.pod_labels.app", "kubernetes.pod_labels.app.kubernetes.io/name"}},
		},
		{
			name:       "both forms in one config",
			raw:        `[{"vl_field":"kubernetes.pod_namespace","loki_label":"namespace"},{"vl_fields":["a","b"],"loki_label":"app"}]`,
			wantLabels: []string{"namespace", "app"},
			wantFields: [][]string{{"kubernetes.pod_namespace"}, {"a", "b"}},
		},
		{name: "malformed json", raw: `[{`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFieldMappingsJSON(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tt.wantLabels) {
				t.Fatalf("got %d mappings, want %d", len(got), len(tt.wantLabels))
			}
			for i := range got {
				if got[i].LokiLabel != tt.wantLabels[i] {
					t.Fatalf("mapping %d label = %q, want %q", i, got[i].LokiLabel, tt.wantLabels[i])
				}
				fields := got[i].Fields()
				if strings.Join(fields, ",") != strings.Join(tt.wantFields[i], ",") {
					t.Fatalf("mapping %d fields = %v, want %v", i, fields, tt.wantFields[i])
				}
			}
		})
	}
}

func TestParseComputedLabelsJSON(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantLen int
		wantSep string
		wantErr string
	}{
		{name: "empty", raw: ""},
		{
			name:    "job from namespace and app",
			raw:     `[{"loki_label":"job","join":["namespace","app"],"sep":"/"}]`,
			wantLen: 1, wantSep: "/",
		},
		{
			name:    "separator defaults to slash",
			raw:     `[{"loki_label":"job","join":["namespace","app"]}]`,
			wantLen: 1, wantSep: "/",
		},
		{
			name:    "one join label is rejected",
			raw:     `[{"loki_label":"job","join":["namespace"]}]`,
			wantErr: "at least two join labels",
		},
		{
			name:    "missing label is rejected",
			raw:     `[{"join":["namespace","app"]}]`,
			wantErr: "at least two join labels",
		},
		{name: "malformed json", raw: `[{`, wantErr: "unexpected end of JSON input"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseComputedLabelsJSON(tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("got (%v, %v), want error containing %q", got, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Fatalf("got %d specs, want %d", len(got), tt.wantLen)
			}
			if tt.wantLen > 0 && got[0].Separator() != tt.wantSep {
				t.Fatalf("separator = %q, want %q", got[0].Separator(), tt.wantSep)
			}
		})
	}
}

func TestValidateLineField(t *testing.T) {
	tests := []struct {
		in      string
		wantErr bool
	}{
		{"", false},
		{"_msg", false},
		{" _msg ", false},
		{"message", true},
		{"kubernetes.pod_name", true},
	}
	for _, tt := range tests {
		err := validateLineField(tt.in)
		if (err != nil) != tt.wantErr {
			t.Fatalf("validateLineField(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
	}
}
