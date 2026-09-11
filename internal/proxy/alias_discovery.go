package proxy

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	logqlpkg "github.com/ReliablyObserve/Loki-VL-proxy/internal/logql"
)

// aliasDiscoveryWindow is the lookback the on-demand field inventory asks for.
// It is only ever used to learn NAMES, so the narrowest window that still holds
// every live pod label is the right one; fetchAllFieldNamesCached caps it again.
const aliasDiscoveryWindow = time.Hour

// ensureQueryLabelAliases resolves, before translation, every Loki label in this
// query that only the backend's field inventory can map to a VL field.
//
// Without it, whether `{strimzi_io_cluster="kf-x"}` translates correctly depends
// on whether THIS replica happened to serve a metadata request that missed its
// cache — the only place alias learning used to happen. That made the answer
// replica-local and time-dependent: on 11.09.2026 one us-omega replica returned
// 0 rows with HTTP 200 at 13:19 and 14:19 while the other returned 5000 for the
// same query at 14:10, and `by (strimzi_io_cluster)` grouped everything under an
// EMPTY value because VictoriaLogs groups an absent field that way. The
// translation cache then froze whichever answer the replica reached first.
//
// Every replica now consults the inventory for the labels it is about to
// translate. The fetch is the cached, coalesced field_names call (~0.25s cold,
// 30s TTL), so a warm replica pays nothing.
//
// Returns false when a lookup was needed but the backend could not answer — the
// caller must then NOT cache the translation, or one failed metadata call pins a
// wrong query for the life of the process.
func (p *Proxy) ensureQueryLabelAliases(ctx context.Context, logql string) bool {
	if p == nil || p.labelTranslator == nil {
		return true
	}
	var needed []string
	for _, label := range queryLabelNames(logql) {
		if p.labelTranslator.NeedsAliasDiscovery(label) {
			needed = append(needed, label)
		}
	}
	if len(needed) == 0 {
		return true
	}
	now := time.Now()
	params := url.Values{}
	params.Set("query", "*")
	params.Set("start", formatVLTimestamp(now.Add(-aliasDiscoveryWindow).UTC().Format(time.RFC3339Nano)))
	params.Set("end", formatVLTimestamp(now.UTC().Format(time.RFC3339Nano)))
	// fetchAllFieldNamesCached feeds LearnFieldAliases on every return path.
	if _, err := p.fetchAllFieldNamesCached(ctx, params); err != nil {
		p.log.Debug("label alias discovery failed", "error", err)
		return false
	}
	// A label the inventory did not account for is NOT resolved — the window
	// above is an hour wide, and a pod label that only existed in the query's own
	// (older) range is absent from it. Caching that translation would pin a query
	// against a field VictoriaLogs does not have for the cache's whole TTL, which
	// is the defect this function exists to close. The lookup itself stays cheap
	// on the retry: fetchAllFieldNamesCached holds its answer for 30s.
	for _, label := range needed {
		if p.labelTranslator.NeedsAliasDiscovery(label) {
			p.log.Debug("label alias unresolved after discovery", "label", label)
			return false
		}
	}
	return true
}

// queryLabelNames returns the Loki label names a query SELECTS ON or GROUPS BY —
// the two positions where an unresolved name silently becomes a filter or a
// grouping key on a VL field that does not exist.
func queryLabelNames(logql string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(name string) {
		name = strings.TrimSpace(name)
		if name == "" {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if lq, err := logqlpkg.ParseLogQuery(logql); err == nil && lq != nil {
		if lq.Selector != nil {
			for _, m := range lq.Selector.Matchers {
				add(m.Name)
			}
		}
		// `| strimzi_io_cluster="x"` names a label just as the selector does, and
		// the translator resolves it the same way.
		for _, stage := range lq.Pipeline {
			if lf, ok := stage.(*logqlpkg.LabelFilterStage); ok {
				for _, name := range labelFilterStageNames(lf.Raw) {
					add(name)
				}
			}
		}
	}
	for _, label := range logqlGroupingLabels(logql) {
		add(label)
	}
	return out
}

// labelFilterStageIdentRE matches the LABEL position of a `| label <op> value`
// filter, including each operand of an `and`/`or` chain.
var labelFilterStageIdentRE = regexp.MustCompile(`(?:^|[\s(,]|\band\b|\bor\b)\s*([A-Za-z_][A-Za-z0-9_.]*)\s*(?:=~|!~|!=|>=|<=|==|=|>|<)`)

// labelFilterStageNames returns the label names a label-filter stage tests.
func labelFilterStageNames(raw string) []string {
	var out []string
	for _, m := range labelFilterStageIdentRE.FindAllStringSubmatch(raw, -1) {
		switch m[1] {
		case "and", "or", "unwrap":
			continue
		}
		out = append(out, m[1])
	}
	return out
}
