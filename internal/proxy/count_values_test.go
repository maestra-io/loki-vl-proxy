package proxy

import (
	"encoding/json"
	"testing"
)

// TestParseCountValuesPostAgg locks the parsing of count_values("label", inner)
// as an instant/range post-aggregation. Before the fix the translator rejected
// the whole expression with 400 "count_values is not translatable to LogsQL",
// because no handler intercepted it ahead of translation.
func TestParseCountValuesPostAgg(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantOK    bool
		wantLabel string
		wantInner string
	}{
		{
			name:      "double quoted label",
			in:        `count_values("c", sum by (app) (count_over_time({namespace="x"}[5m])))`,
			wantOK:    true,
			wantLabel: "c",
			wantInner: `sum by (app) (count_over_time({namespace="x"}[5m]))`,
		},
		{
			name:      "single quoted label",
			in:        `count_values('level', count_over_time({namespace="x"}[5m]))`,
			wantOK:    true,
			wantLabel: "level",
			wantInner: `count_over_time({namespace="x"}[5m])`,
		},
		{
			name:      "underscored label name",
			in:        `count_values("_my_bucket9", count_over_time({namespace="x"}[5m]))`,
			wantOK:    true,
			wantLabel: "_my_bucket9",
			wantInner: `count_over_time({namespace="x"}[5m])`,
		},
		{
			// The inner expression contains a top-level comma inside parens
			// (quantile_over_time's two-arg form); the split must not happen there.
			name:      "inner expression with its own comma",
			in:        `count_values("v", quantile_over_time(0.95, {namespace="x"} | unwrap d [5m]))`,
			wantOK:    true,
			wantLabel: "v",
			wantInner: `quantile_over_time(0.95, {namespace="x"} | unwrap d [5m])`,
		},
		{
			name:   "unquoted label rejected",
			in:     `count_values(c, count_over_time({namespace="x"}[5m]))`,
			wantOK: false,
		},
		{
			name:   "illegal label name rejected",
			in:     `count_values("not-a-label", count_over_time({namespace="x"}[5m]))`,
			wantOK: false,
		},
		{
			name:   "missing inner expression rejected",
			in:     `count_values("c", )`,
			wantOK: false,
		},
		{
			name:   "missing comma rejected",
			in:     `count_values("c")`,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseInstantMetricPostAggQuery(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseInstantMetricPostAggQuery(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.name != "count_values" {
				t.Errorf("name = %q, want count_values", got.name)
			}
			if got.label != tc.wantLabel {
				t.Errorf("label = %q, want %q", got.label, tc.wantLabel)
			}
			if got.inner != tc.wantInner {
				t.Errorf("inner = %q, want %q", got.inner, tc.wantInner)
			}
		})
	}
}

// TestApplyInstantCountValuesAgg checks the vector output shape: one series per
// distinct SAMPLE VALUE of the inner query, labelled with the requested name,
// whose value is how many input series carried it.
func TestApplyInstantCountValuesAgg(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		label string
		want  map[string]string // label value -> count
	}{
		{
			name:  "distinct values each count once",
			label: "c",
			body: `{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"app":"a"},"value":[1,"9"]},
				{"metric":{"app":"b"},"value":[1,"6"]}]}}`,
			want: map[string]string{"9": "1", "6": "1"},
		},
		{
			// The discriminating case: two input series share a value, so the
			// output bucket for that value must be 2 — this is what separates
			// count_values from "group by a field".
			name:  "shared value counts twice",
			label: "n",
			body: `{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"app":"a"},"value":[1,"6"]},
				{"metric":{"app":"b"},"value":[1,"6"]},
				{"metric":{"app":"c"},"value":[1,"4"]}]}}`,
			want: map[string]string{"6": "2", "4": "1"},
		},
		{
			name:  "input labels are dropped",
			label: "bucket",
			body: `{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"app":"a","pod":"p1","namespace":"ns"},"value":[1,"1"]}]}}`,
			want: map[string]string{"1": "1"},
		},
		{
			name:  "fractional values keep their shortest form",
			label: "r",
			body: `{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"app":"a"},"value":[1,"0.5"]},
				{"metric":{"app":"b"},"value":[1,"0.50"]}]}}`,
			want: map[string]string{"0.5": "2"},
		},
		{
			name:  "empty input yields empty result",
			label: "c",
			body:  `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			want:  map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := applyInstantCountValuesAgg([]byte(tc.body), tc.label)

			var resp struct {
				Status string `json:"status"`
				Data   struct {
					ResultType string `json:"resultType"`
					Result     []struct {
						Metric map[string]string `json:"metric"`
						Value  []interface{}     `json:"value"`
					} `json:"result"`
				} `json:"data"`
			}
			if err := json.Unmarshal(out, &resp); err != nil {
				t.Fatalf("unmarshal output: %v\n%s", err, out)
			}
			if resp.Status != "success" || resp.Data.ResultType != "vector" {
				t.Fatalf("status/resultType = %q/%q", resp.Status, resp.Data.ResultType)
			}
			if len(resp.Data.Result) != len(tc.want) {
				t.Fatalf("got %d series, want %d\n%s", len(resp.Data.Result), len(tc.want), out)
			}
			for _, s := range resp.Data.Result {
				if len(s.Metric) != 1 {
					t.Errorf("series metric = %v, want exactly one label", s.Metric)
					continue
				}
				val, ok := s.Metric[tc.label]
				if !ok {
					t.Errorf("series metric = %v, want label %q", s.Metric, tc.label)
					continue
				}
				wantCount, ok := tc.want[val]
				if !ok {
					t.Errorf("unexpected bucket %q", val)
					continue
				}
				if got := s.Value[1]; got != wantCount {
					t.Errorf("bucket %q = %v, want %v", val, got, wantCount)
				}
			}
		})
	}
}

// TestApplyMatrixCountValuesAgg checks the matrix output shape: buckets are
// recomputed independently per timestamp, so a series only carries samples at
// the timestamps where its value actually occurred.
func TestApplyMatrixCountValuesAgg(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"matrix","result":[
		{"metric":{"app":"a"},"values":[[10,"5"],[20,"7"]]},
		{"metric":{"app":"b"},"values":[[10,"5"],[20,"9"]]}]}}`

	out := applyMatrixCountValuesAgg([]byte(body), "c")

	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Values [][]interface{}   `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if resp.Data.ResultType != "matrix" {
		t.Fatalf("resultType = %q, want matrix", resp.Data.ResultType)
	}

	// Expected: value 5 occurred in both series at ts=10 -> {c="5"} = 2 @10 only.
	//           value 7 in one series at ts=20            -> {c="7"} = 1 @20 only.
	//           value 9 in one series at ts=20            -> {c="9"} = 1 @20 only.
	want := map[string][][2]string{
		"5": {{"10", "2"}},
		"7": {{"20", "1"}},
		"9": {{"20", "1"}},
	}
	if len(resp.Data.Result) != len(want) {
		t.Fatalf("got %d series, want %d\n%s", len(resp.Data.Result), len(want), out)
	}
	for _, s := range resp.Data.Result {
		bucket := s.Metric["c"]
		exp, ok := want[bucket]
		if !ok {
			t.Errorf("unexpected bucket %q", bucket)
			continue
		}
		if len(s.Values) != len(exp) {
			t.Errorf("bucket %q has %d samples, want %d", bucket, len(s.Values), len(exp))
			continue
		}
		for i, pair := range s.Values {
			gotTS := jsonNumberString(pair[0])
			gotVal, _ := pair[1].(string)
			if gotTS != exp[i][0] || gotVal != exp[i][1] {
				t.Errorf("bucket %q sample %d = (%s,%s), want (%s,%s)",
					bucket, i, gotTS, gotVal, exp[i][0], exp[i][1])
			}
		}
	}
}

// jsonNumberString renders a decoded JSON number as an integer string so
// timestamps can be compared without float formatting noise.
func jsonNumberString(v interface{}) string {
	f, err := parseFloat(v)
	if err != nil {
		return ""
	}
	return formatCountValuesLabel(f)
}
