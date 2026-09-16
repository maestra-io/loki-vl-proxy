package translator

import (
	"strings"
	"testing"

	"github.com/ReliablyObserve/Loki-VL-proxy/internal/logsql"
)

// Round 13, class I: a derived-level filter injects `unpack_json from _msg |
// unpack_logfmt from _msg`, and VictoriaLogs' unpack pipes OVERWRITE a stored
// field the message text happens to name. The collector already split the
// wrapper into fields (Category, Exception, …) and _msg is free text, so the
// four pushhub Kafka errors lost their `Category` and the line filter fanned
// out over it — `{app="pushhub"} | level=~"error|critical|fatal" |~ "(?i)kafka"`
// — answered {} against Loki's 4. Both pipes keep the original fields; the
// same filter placed after the line filter (4/4) never had the problem.
func TestRound13_DerivedLevelUnpackKeepsStoredFields(t *testing.T) {
	m := &MappingOptions{DerivedLevelFields: []string{"LogLevel", "level"}, LineFilterFields: []string{"_msg", "Category"}}
	for _, q := range []string{
		`{app="pushhub"} | level=~"error|critical|fatal" |~ "(?i)kafka"`,
		`{app="pushhub", level="error"} |~ "(?i)kafka"`,
	} {
		got, err := TranslateLogQLWithMapping(q, nil, nil, logsql.Capabilities{}, m)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for _, want := range []string{
			"| unpack_json from _msg keep_original_fields | unpack_logfmt from _msg keep_original_fields | filter ",
			`Category:~"(?i)kafka"`,
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s\n got  %s\n want it to contain %s", q, got, want)
			}
		}
		if strings.Contains(got, "unpack_logfmt from _msg |") || strings.Contains(got, "| unpack_logfmt |") {
			t.Errorf("%s: an unpack pipe without keep_original_fields: %s", q, got)
		}
	}
}
