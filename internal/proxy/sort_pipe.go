package proxy

import "strconv"

// sortByTimePipe returns the `| sort by (_time …)` stage that every raw-row read
// path appends, with VictoriaLogs' BOUNDED sort.
//
// `sort` is a blocking pipe: without a `limit` VictoriaLogs has to hold every
// matching row in memory before it can emit the first one, so the HTTP `limit`
// argument — which trims the RESULT — cannot cap the scan. On the logs path that
// is the whole namespace buffered to answer a 1000-line panel, which is how both
// us-omega replicas came to sit at 255.5 MiB of a 256 MiB limit on 11.09.2026.
// `sort by (_time desc) limit N` makes VictoriaLogs keep a top-N heap instead,
// and it is the form its own documentation prescribes.
//
// n <= 0 emits the unbounded form: a caller that genuinely folds the whole match
// client-side (collectRangeMetricSamples) must not have its input truncated.
func sortByTimePipe(forward bool, n int) string {
	s := " | sort by (_time desc)"
	if forward {
		s = " | sort by (_time)"
	}
	if n > 0 {
		s += " limit " + strconv.Itoa(n)
	}
	return s
}
