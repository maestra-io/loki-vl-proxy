package proxy

import (
	"context"
	"io"
	"strings"
	"testing"
)

// A wide manual scan streams rows line by line and retains only the samples it
// accepts, so the read must follow -ordered-json-metric-max-bytes (1 GiB by
// default) rather than the 64 MiB ceiling on the response the proxy builds.
// Bit on omicron 2026-09-16: `quantile_over_time(0.95, {namespace=~"traefik-.*"}
// | json | unwrap Duration [5m])` walked past 64 MiB of rows that carry no
// Duration field, retained nothing, and answered 502 where Loki answered an
// empty 200.
func TestRawRowsReadFollowsTheConfigurableCap(t *testing.T) {
	rows := strings.NewReader(strings.Repeat("x", int(maxBufferedBackendBodyBytes)+4096))
	limited := &io.LimitedReader{R: rows, N: defaultOrderedJSONMetricMaxBytes + 1}
	if _, err := io.Copy(io.Discard, io.LimitReader(limited, maxBufferedBackendBodyBytes+2048)); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := checkManualMetricRead(context.Background(), limited, defaultOrderedJSONMetricMaxBytes); err != nil {
		t.Fatalf("a read past 64 MiB must be allowed under the 1 GiB cap: %v", err)
	}

	small := &io.LimitedReader{R: strings.NewReader("yyyy"), N: 2}
	if _, err := io.Copy(io.Discard, small); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := checkManualMetricRead(context.Background(), small, 2); err == nil {
		t.Fatal("a read that exhausts its own cap must still be refused")
	}
}
