package proxy

import (
	"testing"
)

func TestProbeTmpl(t *testing.T) {
	q := "{app=\"web\"} | line_format `{{printf \"%s\" .app}}`"
	t.Logf("extract=%q", extractLineFormatTemplate(q))
}
