package translator

import (
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// `| json alias="field"` names an extracted JSON BODY field. VL has no alias:
// `| unpack_json` extracts under the field's own name, so every downstream
// reference has to be rewritten to that name — in templates as well as filters,
// and without running it through the stream-label mapper.
//
// Measured on us-omega 17.09.2026 over the same window: Loki answered `reco`
// for all 27 lines of
//
//	{namespace="vault-secrets-operator"} |= "Vault request failed"
//	  | json vss_ns="namespace" | line_format "{{.vss_ns}}"
//
// while the proxy answered 27 EMPTY bodies, and adding `| vss_ns=~".+"` dropped
// the proxy to 0 lines because the filter had been mapped onto the stream field
// kubernetes.pod_namespace.
func TestJSONAliasReachesTemplatesAndFilters(t *testing.T) {
	labelFn := func(label string) string {
		if label == "namespace" {
			return "kubernetes.pod_namespace"
		}
		return label
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "template reference resolves to the extracted field",
			in:   `{namespace="vso"} | json vss_ns="namespace" | line_format "{{.vss_ns}}"`,
			want: `"kubernetes.pod_namespace":="vso" | unpack_json | format "<namespace>"`,
		},
		{
			name: "filter on the alias stays on the extracted field",
			in:   `{namespace="vso"} | json vss_ns="namespace" | vss_ns=~".+" | line_format "{{.vss_ns}}"`,
			want: `"kubernetes.pod_namespace":="vso" | unpack_json | filter namespace:~"^(?:.+)$" | format "<namespace>"`,
		},
		{
			name: "a longer field name is not eaten by a shorter alias",
			in:   `{namespace="vso"} | json a="ns" | line_format "{{.a}} {{.abc}}"`,
			want: `"kubernetes.pod_namespace":="vso" | unpack_json | format "<ns> <abc>"`,
		},
		{
			name: "a later stream-label filter is still mapped",
			in:   `{namespace="vso"} | json a="ns" | a=~".+" | namespace="vso"`,
			want: `"kubernetes.pod_namespace":="vso" | unpack_json | filter ns:~"^(?:.+)$" | filter "kubernetes.pod_namespace":="vso"`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TranslateLogQLWithCapabilities(tc.in, labelFn, map[string]bool{}, logsql.Capabilities{})
			if err != nil {
				t.Fatalf("translate %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("translate %q\n got: %s\nwant: %s", tc.in, got, tc.want)
			}
		})
	}
}
