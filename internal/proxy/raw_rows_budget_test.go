package proxy

import (
	"context"
	"io"
	"math"
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

// Every reader of -ordered-json-metric-max-bytes adds one byte for the overflow
// probe, so the accessor must never hand back math.MaxInt64: `cap + 1` would
// wrap negative, exhaust the io.LimitedReader on contact and refuse the scan
// before it read a row.
func TestOrderedJSONMetricMaxBytesLeavesRoomForTheOverflowProbe(t *testing.T) {
	p := &Proxy{orderedJSONMaxBytes: math.MaxInt64}
	got := p.orderedJSONMetricMaxBytes()
	if got != math.MaxInt64-1 {
		t.Fatalf("cap = %d, want %d", got, int64(math.MaxInt64-1))
	}
	if got+1 <= 0 {
		t.Fatalf("cap+1 = %d must stay positive", got+1)
	}
	if p := (&Proxy{orderedJSONMaxBytes: 4096}).orderedJSONMetricMaxBytes(); p != 4096 {
		t.Fatalf("a configured cap must pass through: %d", p)
	}
	if p := (&Proxy{}).orderedJSONMetricMaxBytes(); p != defaultOrderedJSONMetricMaxBytes {
		t.Fatalf("unset cap must fall back to the default: %d", p)
	}
}
