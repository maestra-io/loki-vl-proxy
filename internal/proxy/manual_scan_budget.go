package proxy

import (
	"fmt"
	"sync/atomic"
)

// The manual range-metric path RETAINS one sample per accepted row until the
// whole scan is folded, so its memory is O(rows) — 16 bytes per sample before
// slice growth, parser buffers and the per-series label maps. A per-request row
// cap alone therefore bounds nothing that matters: the requests are concurrent,
// `MaxConcurrent` counts requests rather than bytes, and the proxy runs with a
// 256Mi limit in production (already 152Mi under comparison load).
//
// The budget below is what actually bounds it: a GLOBAL pool of sample slots
// every concurrent scan draws from, so the path's total retained samples — and
// with them its heap — cannot exceed one number no matter how many requests
// arrive. Running out is refused explicitly and logged, never silently trimmed:
// a short aggregate is indistinguishable from a real drop in traffic.
const (
	// defaultManualScanSampleBudget is ~32 MiB of retained samples across ALL
	// in-flight manual scans (16 bytes per rangeMetricSample), which leaves room
	// for the rest of a 256Mi pod.
	defaultManualScanSampleBudget = 2_000_000

	// manualScanReservationChunk is how many slots a scan takes at a time, so the
	// hot loop touches the shared counter once per chunk instead of once per row.
	manualScanReservationChunk = 4096

	// defaultManualScanSeriesLimit caps DISTINCT series in one scan. Samples are
	// not the only thing that grows: every new series adds a label map and a
	// translated copy of it, which a high-cardinality group-by multiplies.
	defaultManualScanSeriesLimit = 10_000
)

// manualScanBudget hands out sample slots to concurrent manual scans.
type manualScanBudget struct{ remaining atomic.Int64 }

func newManualScanBudget(total int64) *manualScanBudget {
	if total <= 0 {
		total = defaultManualScanSampleBudget
	}
	b := &manualScanBudget{}
	b.remaining.Store(total)
	return b
}

// reserve takes n slots, or reports how many were actually available.
func (b *manualScanBudget) reserve(n int64) bool {
	for {
		left := b.remaining.Load()
		if left < n {
			return false
		}
		if b.remaining.CompareAndSwap(left, left-n) {
			return true
		}
	}
}

func (b *manualScanBudget) release(n int64) {
	if n > 0 {
		b.remaining.Add(n)
	}
}

// manualScanReservation is one scan's draw on the shared budget.
type manualScanReservation struct {
	budget *manualScanBudget
	held   int64
	used   int64
}

func (p *Proxy) newManualScanReservation() *manualScanReservation {
	return &manualScanReservation{budget: p.manualScanBudget}
}

// account records one more retained sample, reserving another chunk when the
// current one runs out. It reports false when the shared budget is exhausted.
func (r *manualScanReservation) account() bool {
	if r == nil || r.budget == nil {
		return true
	}
	r.used++
	if r.used <= r.held {
		return true
	}
	if !r.budget.reserve(manualScanReservationChunk) {
		r.used--
		return false
	}
	r.held += manualScanReservationChunk
	return true
}

// release returns the whole reservation. Safe to call twice.
func (r *manualScanReservation) release() {
	if r == nil || r.budget == nil {
		return
	}
	r.budget.release(r.held)
	r.held, r.used = 0, 0
}

// manualScanBudgetError reports that the shared retained-sample budget is gone.
type manualScanBudgetError struct{ budget int64 }

func (e *manualScanBudgetError) Error() string {
	return fmt.Sprintf(
		"query needs more raw log samples than this instance will hold in memory at once "+
			"(shared budget %d samples across concurrent queries); the result would be silently incomplete. "+
			"Narrow the time range or the stream selector, or group by a label the backend can see so the "+
			"aggregation runs there", e.budget)
}

// manualScanSeriesError reports that one scan produced more distinct series than
// the path will hold.
type manualScanSeriesError struct{ limit int }

func (e *manualScanSeriesError) Error() string {
	return fmt.Sprintf(
		"query produces more than %d distinct series in the proxy-side fold; the result would be silently "+
			"incomplete. Narrow the grouping, or group by a label the backend can see so the aggregation "+
			"runs there", e.limit)
}
