package proxy

import (
	"net/http"
	"net/url"
	"strconv"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
)

// alignRangeRequestToStepGrid rewrites a metric range request's start/end onto
// Loki's own evaluation grid: multiples of `step`, both bounds truncated DOWN.
//
// Loki's queryrange step-align middleware does exactly that, and it is visible
// from the outside — on 3.7.1 with step=137s and a start that is not a multiple
// of 137, every returned timestamp satisfies `ts % 137 == 0` and the first point
// lands 17 seconds BEFORE the requested start. Starting the grid at `start`
// instead shifted the whole series (+27s at step=137, +39s at step=97) while a
// step that happens to divide the start looked perfectly fine.
//
// LOG queries are left alone: they have no evaluation grid, and moving their
// bounds would change which lines they return.
func alignRangeRequestToStepGrid(r *http.Request, logqlQuery string) {
	if r == nil {
		return
	}
	step, ok := parsePositiveStepDuration(r.FormValue("step"))
	if !ok || step <= 0 {
		return
	}
	if !isMetricRangeExpr(logqlQuery) {
		return
	}
	stepNs := step.Nanoseconds()

	aligned := func(raw string) (string, bool) {
		ns, ok := parseLokiTimeToUnixNano(raw)
		if !ok {
			return "", false
		}
		rem := ns % stepNs
		if rem < 0 {
			rem += stepNs
		}
		if rem == 0 {
			return "", false
		}
		return strconv.FormatInt(ns-rem, 10), true
	}

	setForm := func(key, value string) {
		if r.Form == nil {
			r.Form = url.Values{}
		}
		r.Form.Set(key, value)
		if r.PostForm != nil && r.PostForm.Get(key) != "" {
			r.PostForm.Set(key, value)
		}
		if r.URL != nil {
			q := r.URL.Query()
			if q.Get(key) != "" {
				q.Set(key, value)
				r.URL.RawQuery = q.Encode()
			}
		}
	}

	if v, ok := aligned(r.FormValue("start")); ok {
		setForm("start", v)
	}
	if v, ok := aligned(r.FormValue("end")); ok {
		setForm("end", v)
	}
}

// isMetricRangeExpr reports whether a LogQL query produces a matrix — the only
// shape Loki evaluates on a step grid.
func isMetricRangeExpr(logqlQuery string) bool {
	parsed, err := logqlpkg.Parse(logqlQuery)
	if err != nil {
		return false
	}
	switch parsed.(type) {
	case *logqlpkg.RangeAggregation, *logqlpkg.VectorAggregation, *logqlpkg.BinOpExpr,
		*logqlpkg.OpaqueMetricExpr, *logqlpkg.LiteralExpr:
		return true
	}
	return false
}
