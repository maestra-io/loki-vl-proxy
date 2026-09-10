package logql

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pipeline evaluates a LogQL log pipeline entry-by-entry inside the proxy.
//
// It exists for the stages VictoriaLogs cannot express — `| line_format` and
// `| label_format` carry arbitrary Go templates. Once one of those is present,
// pushing the *rest* of the pipeline down would still be wrong, because every
// later stage reads the line/labels the template produced. So when a query
// contains a template stage the proxy sends VL only the stream selector plus
// the leading line filters (cheap and index-backed) and runs the whole pipeline
// here, with Loki's semantics.
//
// A Pipeline is not safe for concurrent use — see Template.
type Pipeline struct {
	stages []Stage
	tmpls  map[any]*Template
	buf    strings.Builder

	// UnwrapLabel is the label named by a trailing `| unwrap x` stage, if any.
	UnwrapLabel string
	// UnwrapConv is the converter of `| unwrap bytes(x)` / `duration(x)`.
	UnwrapConv string
}

// Entry is one log record flowing through the pipeline.
type Entry struct {
	TS     time.Time
	Line   string
	Labels map[string]string
}

const (
	errorLabel        = "__error__"
	errorDetailsLabel = "__error_details__"
)

// NeedsProxyEvaluation reports whether the pipeline must be evaluated by the
// proxy rather than pushed down to VictoriaLogs.
//
// Two families qualify, and both need the SAME machinery — a Loki-faithful
// per-entry evaluator — so they share one trigger:
//
//   - a Go template in line_format / label_format (HasTemplateStage);
//   - a filter on `__error__` / `__error_details__` (HasErrorLabelFilter),
//     because those labels only exist in Loki's model: a parser records its
//     failure on the entry, and `| json | __error__=""` therefore EXCLUDES the
//     lines that failed to parse. VictoriaLogs has no such flag — its
//     unpack_json simply adds no fields — so a pushed-down query counts the
//     malformed lines that Loki drops.
func NeedsProxyEvaluation(stages []Stage) bool {
	return HasTemplateStage(stages) || HasErrorLabelFilter(stages)
}

// HasErrorLabelFilter reports whether the pipeline FILTERS on the parser-error
// labels. `| drop __error__` is not a filter — it removes the label and keeps
// every line, which is Loki's behaviour too.
func HasErrorLabelFilter(stages []Stage) bool {
	for _, s := range stages {
		lf, ok := s.(*LabelFilterStage)
		if !ok {
			continue
		}
		if strings.Contains(lf.Raw, errorLabel) || strings.Contains(lf.Raw, errorDetailsLabel) {
			return true
		}
	}
	return false
}

// HasTemplateStage reports whether the pipeline contains a line_format or
// label_format stage carrying an actual Go template — the trigger for
// proxy-side evaluation.
//
// A format stage with no `{{` action (`| line_format ""`, `| label_format
// env="prod"`) is a constant, and a bare rename (`| label_format new=old`) is a
// field copy: both translate to LogsQL faithfully, so they stay pushed down.
func HasTemplateStage(stages []Stage) bool {
	for _, s := range stages {
		switch st := s.(type) {
		case *LineFormatStage:
			if strings.Contains(st.Template, "{{") {
				return true
			}
		case *LabelFormatStage:
			if len(st.Assignments) == 0 {
				// Unparsed expression: assume it needs evaluation only when the
				// raw text carries an action.
				if strings.Contains(st.Raw, "{{") {
					return true
				}
				continue
			}
			for _, a := range st.Assignments {
				if strings.Contains(a.Tmpl, "{{") {
					return true
				}
			}
		}
	}
	return false
}

// NewPipeline compiles the stages for repeated evaluation. Templates are
// compiled once here so an unknown function fails the query with a 400 instead
// of leaking the template text into the results.
func NewPipeline(stages []Stage) (*Pipeline, error) {
	p := &Pipeline{stages: stages, tmpls: make(map[any]*Template)}
	for _, s := range stages {
		switch st := s.(type) {
		case *LineFormatStage:
			t, err := compileStageTemplate(st.Template)
			if err != nil {
				return nil, err
			}
			if t != nil {
				p.tmpls[s] = t
			}
		case *LabelFormatStage:
			if len(st.Assignments) == 0 && strings.TrimSpace(st.Raw) != "" {
				return nil, fmt.Errorf("unsupported label_format expression: %s", strings.TrimSpace(st.Raw))
			}
			for i := range st.Assignments {
				a := &st.Assignments[i]
				if a.Tmpl == "" {
					continue
				}
				t, err := compileStageTemplate(a.Tmpl)
				if err != nil {
					return nil, err
				}
				if t != nil {
					p.tmpls[assignKey{s, i}] = t
				}
			}
		case *LabelFilterStage:
			if _, err := parseLabelFilter(st.Raw); err != nil {
				return nil, err
			}
		case *ParserStage:
			if st.Type == ParserRegexp || st.Type == ParserPattern {
				if _, err := compileExtractor(st); err != nil {
					return nil, err
				}
			}
		case *UnwrapStage:
			p.UnwrapLabel, p.UnwrapConv = st.Label, st.Converter
		}
	}
	return p, nil
}

// compileStageTemplate compiles a format stage's template, distinguishing the
// two failure modes Loki treats differently:
//
//   - an unimplemented FUNCTION is fatal: the proxy would otherwise have to
//     invent a value, and silently emitting the template text is exactly the
//     bug this package exists to fix. It becomes a 400 naming the function.
//   - a SYNTAX error is not: Loki answers 200 for `| line_format "{{.method"`,
//     so a nil template is returned and the stage becomes a no-op that records
//     `__error__=TemplateFormatErr`, as Loki does.
func compileStageTemplate(src string) (*Template, error) {
	t, err := ParseTemplate(src)
	if err == nil {
		return t, nil
	}
	var unknown *UnknownFuncError
	if errors.As(err, &unknown) {
		return nil, err
	}
	return nil, nil //nolint:nilnil // a malformed template is a runtime no-op, not a query error
}

// assignKey identifies one assignment of a label_format stage in tmpls.
type assignKey struct {
	stage Stage
	idx   int
}

// Process runs every stage against e, mutating it in place. It reports whether
// the entry survives the pipeline's filters.
func (p *Pipeline) Process(e *Entry) bool {
	for _, s := range p.stages {
		if !p.apply(s, e) {
			return false
		}
	}
	return true
}

func (p *Pipeline) apply(s Stage, e *Entry) bool { //nolint:gocyclo // one branch per LogQL stage kind
	switch st := s.(type) {
	case *LineFilterStage:
		return matchLineFilter(st, e.Line)

	case *ParserStage:
		p.applyParser(st, e)

	case *LabelFilterStage:
		f, err := parseLabelFilter(st.Raw)
		if err != nil {
			return true // validated in NewPipeline; be permissive at runtime
		}
		return f.eval(e.Labels)

	case *DropStage:
		applyDropKeep(e.Labels, st.Labels, st.Matchers, true)

	case *KeepStage:
		applyDropKeep(e.Labels, st.Labels, st.Matchers, false)

	case *DecolorizeStage:
		e.Line = ansiRE.ReplaceAllString(e.Line, "")

	case *LineFormatStage:
		t := p.tmpls[s]
		if t == nil {
			// Malformed template — Loki keeps the line and flags the entry.
			setError(e.Labels, "TemplateFormatErr", "invalid template: "+st.Template)
			return true
		}
		out, err := t.Exec(e.Labels, e.Line, e.TS, &p.buf)
		if err != nil {
			setError(e.Labels, "TemplateFormatErr", err.Error())
			return true
		}
		e.Line = out

	case *LabelFormatStage:
		p.applyLabelFormat(st, e)

	case *StreamSelector, *UnwrapStage:
		// Selector matchers are enforced by the backend; unwrap is read by the
		// metric layer, not by the log pipeline.
	}
	return true
}

func (p *Pipeline) applyLabelFormat(st *LabelFormatStage, e *Entry) {
	// Loki evaluates every assignment against the labels as they were BEFORE
	// the stage, so `label_format a=b, b=a` swaps rather than aliases.
	out := make(map[string]string, len(st.Assignments))
	for i := range st.Assignments {
		a := &st.Assignments[i]
		if a.Src != "" {
			out[a.Dst] = e.Labels[a.Src]
			continue
		}
		t := p.tmpls[assignKey{st, i}]
		if t == nil {
			setError(e.Labels, "TemplateFormatErr", "invalid template: "+a.Tmpl)
			continue
		}
		v, err := t.Exec(e.Labels, e.Line, e.TS, &p.buf)
		if err != nil {
			setError(e.Labels, "TemplateFormatErr", err.Error())
			continue
		}
		out[a.Dst] = v
	}
	for k, v := range out {
		e.Labels[k] = v
	}
}

// ─── parsers ────────────────────────────────────────────────────────────────

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func (p *Pipeline) applyParser(st *ParserStage, e *Entry) {
	switch st.Type {
	case ParserJSON:
		parseJSONInto(e, st.Params)
	case ParserLogfmt:
		parseLogfmtInto(e, st.Params)
	case ParserUnpack:
		parseUnpackInto(e)
	case ParserRegexp, ParserPattern:
		re, err := compileExtractor(st)
		if err != nil || re == nil {
			return
		}
		m := re.FindStringSubmatch(e.Line)
		if m == nil {
			return
		}
		for i, name := range re.SubexpNames() {
			if name == "" || i >= len(m) {
				continue
			}
			e.Labels[name] = m[i]
		}
	}
}

func setError(labels map[string]string, kind, details string) {
	labels[errorLabel] = kind
	labels[errorDetailsLabel] = details
}

func parseJSONInto(e *Entry, params []LabelExtraction) {
	var v interface{}
	if err := json.Unmarshal([]byte(e.Line), &v); err != nil {
		setError(e.Labels, "JSONParserErr", err.Error())
		return
	}
	if len(params) == 0 {
		flattenJSON("", v, e.Labels)
		return
	}
	for _, prm := range params {
		path := prm.Expr
		if path == "" {
			path = prm.Name
		}
		if got, ok := lookupJSONPath(v, path); ok {
			e.Labels[sanitizeLabel(prm.Name)] = got
		}
	}
}

// flattenJSON mirrors Loki's json parser: nested objects join with "_",
// arrays index with "_N", scalars render as their JSON text.
func flattenJSON(prefix string, v interface{}, out map[string]string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, sub := range t {
			out2 := sanitizeLabel(k)
			if prefix != "" {
				out2 = prefix + "_" + out2
			}
			flattenJSON(out2, sub, out)
		}
	case []interface{}:
		for i, sub := range t {
			flattenJSON(prefix+"_"+strconv.Itoa(i), sub, out)
		}
	default:
		if prefix == "" {
			return
		}
		out[prefix] = scalarString(v)
	}
}

func scalarString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// lookupJSONPath resolves Loki's json label expressions: `a.b`, `a["b"]`, `a[0]`.
func lookupJSONPath(v interface{}, path string) (string, bool) {
	cur := v
	for _, seg := range splitJSONPath(path) {
		switch node := cur.(type) {
		case map[string]interface{}:
			next, ok := node[seg]
			if !ok {
				return "", false
			}
			cur = next
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return "", false
			}
			cur = node[idx]
		default:
			return "", false
		}
	}
	switch t := cur.(type) {
	case map[string]interface{}, []interface{}:
		b, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(b), true
	default:
		return scalarString(cur), true
	}
}

func splitJSONPath(path string) []string {
	var segs []string
	var cur strings.Builder
	i := 0
	for i < len(path) {
		switch path[i] {
		case '.':
			if cur.Len() > 0 {
				segs = append(segs, cur.String())
				cur.Reset()
			}
			i++
		case '[':
			if cur.Len() > 0 {
				segs = append(segs, cur.String())
				cur.Reset()
			}
			end := strings.IndexByte(path[i:], ']')
			if end < 0 {
				i = len(path)
				continue
			}
			seg := strings.Trim(path[i+1:i+end], `"'`)
			segs = append(segs, seg)
			i += end + 1
		default:
			cur.WriteByte(path[i])
			i++
		}
	}
	if cur.Len() > 0 {
		segs = append(segs, cur.String())
	}
	return segs
}

func parseLogfmtInto(e *Entry, params []LabelExtraction) {
	fields := parseLogfmt(e.Line)
	if len(params) == 0 {
		for k, v := range fields {
			e.Labels[sanitizeLabel(k)] = v
		}
		return
	}
	for _, prm := range params {
		src := prm.Expr
		if src == "" {
			src = prm.Name
		}
		if v, ok := fields[src]; ok {
			e.Labels[sanitizeLabel(prm.Name)] = v
		}
	}
}

// parseLogfmt splits `k=v k2="v 2"` into a map.
func parseLogfmt(line string) map[string]string {
	out := make(map[string]string, 8)
	i, n := 0, len(line)
	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		if i == start {
			i++
			continue
		}
		key := line[start:i]
		if i >= n || line[i] != '=' {
			out[key] = ""
			continue
		}
		i++ // consume '='
		if i < n && line[i] == '"' {
			j := i + 1
			var b strings.Builder
			for j < n && line[j] != '"' {
				if line[j] == '\\' && j+1 < n {
					j++
					b.WriteByte(unescapeByte(line[j]))
				} else {
					b.WriteByte(line[j])
				}
				j++
			}
			out[key] = b.String()
			i = j + 1
			continue
		}
		vs := i
		for i < n && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		out[key] = line[vs:i]
	}
	return out
}

func unescapeByte(c byte) byte {
	switch c {
	case 'n':
		return '\n'
	case 't':
		return '\t'
	case 'r':
		return '\r'
	default:
		return c
	}
}

// parseUnpackInto implements `| unpack`: a JSON object whose `_entry` field
// replaces the line while its other fields become labels.
func parseUnpackInto(e *Entry) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(e.Line), &obj); err != nil {
		setError(e.Labels, "JSONParserErr", err.Error())
		return
	}
	for k, v := range obj {
		if k == "_entry" {
			if s, ok := v.(string); ok {
				e.Line = s
			}
			continue
		}
		if s, ok := v.(string); ok {
			e.Labels[sanitizeLabel(k)] = s
		}
	}
}

// compileCache memoises compiled regexps and label filters across requests.
//
// These caches are package-level and every in-flight HTTP request writes to
// them from its own goroutine, so a plain map is a `fatal error: concurrent map
// writes` waiting to happen — one that kills the PROCESS, not the request.
// Reads take the read lock; the 1024-entry bound is checked under the write lock
// so two racing writers cannot both pass it.
type compileCache[T any] struct {
	mu sync.RWMutex
	m  map[string]T
}

// compileCacheMaxEntries bounds each cache. Queries are operator-authored and
// few; the bound exists so a pathological client cannot grow them without end.
const compileCacheMaxEntries = 1024

func (c *compileCache[T]) get(key string) (T, bool) {
	c.mu.RLock()
	v, ok := c.m[key]
	c.mu.RUnlock()
	return v, ok
}

func (c *compileCache[T]) put(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]T, 16)
	}
	if len(c.m) >= compileCacheMaxEntries {
		return
	}
	c.m[key] = v
}

var extractorCache compileCache[*regexp.Regexp]

// compileExtractor turns a regexp or pattern stage into a named-group regexp.
func compileExtractor(st *ParserStage) (*regexp.Regexp, error) {
	key := strconv.Itoa(int(st.Type)) + "\x00" + st.Param
	if re, ok := extractorCache.get(key); ok {
		return re, nil
	}
	src := st.Param
	if st.Type == ParserPattern {
		src = patternToRegexp(st.Param)
	}
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("invalid %s expression %q: %w", st.String(), st.Param, err)
	}
	extractorCache.put(key, re)
	return re, nil
}

var patternCaptureRE = regexp.MustCompile(`<([a-zA-Z_][a-zA-Z0-9_]*|_)>`)

// patternToRegexp converts Loki's `| pattern "<ip> - <_> [<ts>]"` to a regexp.
func patternToRegexp(pat string) string {
	var b strings.Builder
	last := 0
	for _, loc := range patternCaptureRE.FindAllStringSubmatchIndex(pat, -1) {
		b.WriteString(regexp.QuoteMeta(pat[last:loc[0]]))
		name := pat[loc[2]:loc[3]]
		if name == "_" {
			b.WriteString(`(?:.*?)`)
		} else {
			b.WriteString(`(?P<` + name + `>.*?)`)
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(pat[last:]))
	return "^" + b.String() + "$"
}

// sanitizeLabel maps a field name to a Prometheus-legal label name, as Loki does.
func sanitizeLabel(s string) string {
	ok := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9' && i > 0) {
			continue
		}
		ok = false
		break
	}
	if ok && s != "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			b.WriteByte(c)
		case c >= '0' && c <= '9' && b.Len() > 0:
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ─── filters ────────────────────────────────────────────────────────────────

var lineFilterCache compileCache[*regexp.Regexp]

func matchLineFilter(st *LineFilterStage, line string) bool {
	switch st.Op {
	case LineFilterContains:
		return strings.Contains(line, st.Value)
	case LineFilterExcludes:
		return !strings.Contains(line, st.Value)
	case LineFilterMatchRe, LineFilterExcludeRe:
		re, ok := lineFilterCache.get(st.Value)
		if !ok {
			var err error
			re, err = regexp.Compile(st.Value)
			if err != nil {
				return true
			}
			lineFilterCache.put(st.Value, re)
		}
		if st.Op == LineFilterMatchRe {
			return re.MatchString(line)
		}
		return !re.MatchString(line)
	default:
		// |> and !> are pattern line filters — treat as a match so the backend's
		// own filtering stands rather than dropping everything.
		return true
	}
}

func applyDropKeep(labels map[string]string, names []string, matchers []DropMatcher, drop bool) {
	hit := make(map[string]bool, len(names)+len(matchers))
	for _, n := range names {
		hit[n] = true
	}
	for _, m := range matchers {
		if matchDropMatcher(m, labels[m.Name]) {
			hit[m.Name] = true
		}
	}
	if drop {
		for n := range hit {
			delete(labels, n)
		}
		return
	}
	for k := range labels {
		if !hit[k] {
			delete(labels, k)
		}
	}
}

func matchDropMatcher(m DropMatcher, val string) bool {
	switch m.Op {
	case "=":
		return val == m.Value
	case "!=":
		return val != m.Value
	case "=~":
		return matchAnchored(m.Value, val)
	case "!~":
		return !matchAnchored(m.Value, val)
	default:
		return false
	}
}

var anchoredCache compileCache[*regexp.Regexp]

// matchAnchored applies LogQL label-matcher regex semantics: fully anchored.
func matchAnchored(pattern, val string) bool {
	re, ok := anchoredCache.get(pattern)
	if !ok {
		var err error
		re, err = regexp.Compile("^(?:" + pattern + ")$")
		if err != nil {
			return false
		}
		anchoredCache.put(pattern, re)
	}
	return re.MatchString(val)
}

// ─── label filter expressions ───────────────────────────────────────────────

type labelFilter interface {
	eval(labels map[string]string) bool
}

type labelFilterBinary struct {
	or          bool
	left, right labelFilter
}

func (f *labelFilterBinary) eval(l map[string]string) bool {
	if f.or {
		return f.left.eval(l) || f.right.eval(l)
	}
	return f.left.eval(l) && f.right.eval(l)
}

type labelFilterPred struct {
	name    string
	op      string
	str     string
	num     float64
	numeric bool
}

func (f *labelFilterPred) eval(l map[string]string) bool {
	val, present := l[f.name]
	if f.numeric {
		got, err := parseNumericLabel(val)
		if err != nil || !present {
			return false
		}
		switch f.op {
		case ">":
			return got > f.num
		case ">=":
			return got >= f.num
		case "<":
			return got < f.num
		case "<=":
			return got <= f.num
		case "==", "=":
			return got == f.num
		case "!=":
			return got != f.num
		}
		return false
	}
	switch f.op {
	case "=", "==":
		return val == f.str
	case "!=":
		return val != f.str
	case "=~":
		return matchAnchored(f.str, val)
	case "!~":
		return !matchAnchored(f.str, val)
	}
	return false
}

var labelFilterCache compileCache[labelFilter]

func parseLabelFilter(raw string) (labelFilter, error) {
	if f, ok := labelFilterCache.get(raw); ok {
		return f, nil
	}
	lp := &lfParser{src: raw}
	f, err := lp.parseExpr()
	if err != nil {
		return nil, err
	}
	lp.skipSpace()
	if lp.pos < len(lp.src) {
		return nil, fmt.Errorf("unsupported label filter expression: %s", strings.TrimSpace(raw))
	}
	labelFilterCache.put(raw, f)
	return f, nil
}

type lfParser struct {
	src string
	pos int
}

func (p *lfParser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t') {
		p.pos++
	}
}

func (p *lfParser) parseExpr() (labelFilter, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for {
		p.skipSpace()
		var or bool
		switch {
		case p.pos < len(p.src) && p.src[p.pos] == ',':
			p.pos++
		case p.hasWord("and"):
			p.pos += 3
		case p.hasWord("or"):
			p.pos += 2
			or = true
		default:
			return left, nil
		}
		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		left = &labelFilterBinary{or: or, left: left, right: right}
	}
}

func (p *lfParser) hasWord(w string) bool {
	if !strings.HasPrefix(p.src[p.pos:], w) {
		return false
	}
	end := p.pos + len(w)
	return end >= len(p.src) || p.src[end] == ' ' || p.src[end] == '\t' || p.src[end] == '('
}

func (p *lfParser) parseTerm() (labelFilter, error) {
	p.skipSpace()
	if p.pos < len(p.src) && p.src[p.pos] == '(' {
		p.pos++
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return nil, fmt.Errorf("unbalanced parenthesis in label filter %q", p.src)
		}
		p.pos++
		return inner, nil
	}
	return p.parsePredicate()
}

var lfOps = []string{">=", "<=", "==", "!=", "=~", "!~", ">", "<", "="}

func (p *lfParser) parsePredicate() (labelFilter, error) {
	p.skipSpace()
	start := p.pos
	for p.pos < len(p.src) && (isIdentByte(p.src[p.pos]) || p.src[p.pos] == '.') {
		p.pos++
	}
	name := p.src[start:p.pos]
	if name == "" {
		return nil, fmt.Errorf("expected label name in label filter %q", p.src)
	}
	p.skipSpace()
	op := ""
	for _, cand := range lfOps {
		if strings.HasPrefix(p.src[p.pos:], cand) {
			op = cand
			break
		}
	}
	if op == "" {
		return nil, fmt.Errorf("expected comparison operator after %q in label filter %q", name, p.src)
	}
	p.pos += len(op)
	p.skipSpace()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("missing value after %q in label filter %q", op, p.src)
	}

	if q := p.src[p.pos]; q == '"' || q == '`' {
		val, err := p.readQuoted(q)
		if err != nil {
			return nil, err
		}
		return &labelFilterPred{name: name, op: op, str: val}, nil
	}

	vStart := p.pos
	for p.pos < len(p.src) && p.src[p.pos] != ' ' && p.src[p.pos] != ',' && p.src[p.pos] != ')' {
		p.pos++
	}
	lit := p.src[vStart:p.pos]
	num, err := parseNumericLabel(lit)
	if err != nil {
		return nil, fmt.Errorf("unsupported literal %q in label filter %q", lit, p.src)
	}
	return &labelFilterPred{name: name, op: op, num: num, numeric: true}, nil
}

func (p *lfParser) readQuoted(q byte) (string, error) {
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == q {
			p.pos++
			return b.String(), nil
		}
		if q == '"' && c == '\\' && p.pos+1 < len(p.src) {
			p.pos++
			b.WriteByte(unescapeByte(p.src[p.pos]))
			p.pos++
			continue
		}
		b.WriteByte(c)
		p.pos++
	}
	return "", fmt.Errorf("unterminated string in label filter %q", p.src)
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

var byteUnitFactors = []struct {
	suffix string
	factor float64
}{
	{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
	{"kB", 1e3}, {"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12},
	{"B", 1},
}

// parseNumericLabel accepts plain numbers, Go durations and byte sizes — the
// three literal forms a LogQL label filter may compare against.
func parseNumericLabel(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty numeric value")
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	for _, u := range byteUnitFactors {
		if strings.HasSuffix(s, u.suffix) {
			if f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), 64); err == nil {
				return f * u.factor, nil
			}
		}
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d.Seconds(), nil
	}
	return 0, fmt.Errorf("not a number, duration or byte size: %q", s)
}
