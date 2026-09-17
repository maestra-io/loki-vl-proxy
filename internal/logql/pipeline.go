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

	// LineFilterFields names the labels a LINE filter reads besides the line
	// itself — the proxy's -line-filter-fields, which the pushed-down LogsQL
	// already honours. Without the same list here, a row VictoriaLogs matched in
	// `Scopes` is dropped by the re-run of the filter on `_msg` alone. Names are
	// VictoriaLogs spellings; a trailing `*` is a prefix wildcard.
	LineFilterFields []string

	// DerivedLevelFields names the labels the proxy derives a level from
	// (-derived-level-fields). Loki's logfmt/pattern/regexp read the line
	// only, so a level the collector split out of a JSON line is not among
	// their output: those parsers drop these labels before merging what they
	// extracted from the line, and `| logfmt | level="error"` then reads the
	// parsed field, as Loki does. Empty keeps the labels.
	DerivedLevelFields []string

	// base is the label set the entry arrived with — its stream labels and
	// structured metadata. LogQL gives those priority over anything a parser
	// extracts: a `| json` that finds a `namespace` in the body does NOT
	// overwrite the stream's `namespace`, it adds `namespace_extracted`.
	// Reused across entries; Process resets it (a Pipeline is single-goroutine,
	// like buf).
	base   map[string]struct{}
	parsed map[string]string

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
	// SplitJSON reports that the collector already parsed the line's JSON into
	// the fields the entry carries as labels, leaving only the message text in
	// Line. Loki holds the whole JSON line, so its `| json` succeeds there; a
	// `| json` on the bare text must not record JSONParserErr (round 13, J).
	SplitJSON bool
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
			if len(st.Formats) == 0 {
				// Unparsed expression: assume it needs evaluation only when the
				// raw text carries an action.
				if strings.Contains(st.Raw, "{{") {
					return true
				}
				continue
			}
			if !labelFormatPushable(st) {
				return true
			}
		}
	}
	return false
}

// pureFieldRefRE is a template whose only action is one field reference:
// `{{ .level }}`, `{{.service.name}}`.
var pureFieldRefRE = regexp.MustCompile(`^\s*\{\{\s*\.([\w.]+)\s*\}\}\s*$`)

// labelFormatPushable reports whether every templated assignment of the stage
// is a pure field reference, which translates to LogsQL `| format "<field>"
// as dst` exactly. The reference must not name a label another assignment of
// the SAME stage writes: Loki evaluates all assignments against the pre-stage
// labels, the translator emits sequential pipes, so `a={{.b}}, b={{.a}}` would
// swap wrongly pushed down. Round 11: `sum by (lf) (... | label_format
// lf=`{{ .level }}`)` was routed through the proxy-side raw-row read for a
// stage VictoriaLogs evaluates natively.
func labelFormatPushable(st *LabelFormatStage) bool {
	dsts := make(map[string]struct{}, len(st.Formats))
	for _, a := range st.Formats {
		dsts[a.Name] = struct{}{}
	}
	for _, a := range st.Formats {
		if a.Rename || !strings.Contains(a.Value, "{{") {
			continue
		}
		m := pureFieldRefRE.FindStringSubmatch(a.Value)
		if m == nil {
			return false
		}
		if _, clash := dsts[m[1]]; clash {
			return false
		}
	}
	return true
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
			if len(st.Formats) == 0 && strings.TrimSpace(st.Raw) != "" {
				return nil, fmt.Errorf("unsupported label_format expression: %s", strings.TrimSpace(st.Raw))
			}
			for i := range st.Formats {
				a := &st.Formats[i]
				if a.Rename {
					continue
				}
				t, err := compileStageTemplate(a.Value)
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
			switch st.Type {
			case ParserRegexp:
				if _, err := compileExtractor(st); err != nil {
					return nil, err
				}
			case ParserPattern:
				if _, err := compilePattern(st.Param); err != nil {
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
	//   - a BUDGET overflow is fatal too: evaluating it per line is the denial
	//     of service the budget exists to refuse, so it becomes a 400.
	var budget *TemplateBudgetError
	if errors.As(err, &budget) {
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
	if p.base == nil {
		p.base = make(map[string]struct{}, len(e.Labels))
	}
	clear(p.base)
	for k := range e.Labels {
		p.base[k] = struct{}{}
	}
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
		return matchLineFilter(st, e.Line, p.lineFilterTexts(e))

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
		// The line is no longer the collector's source text: a later `| json`
		// parses what the template produced and fails on it like Loki does.
		e.SplitJSON = false

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
	out := make(map[string]string, len(st.Formats))
	for i := range st.Formats {
		a := &st.Formats[i]
		if a.Rename {
			out[a.Name] = e.Labels[a.Value]
			continue
		}
		t := p.tmpls[assignKey{st, i}]
		if t == nil {
			setError(e.Labels, "TemplateFormatErr", "invalid template: "+a.Value)
			continue
		}
		v, err := t.Exec(e.Labels, e.Line, e.TS, &p.buf)
		if err != nil {
			setError(e.Labels, "TemplateFormatErr", err.Error())
			continue
		}
		out[a.Name] = v
	}
	for k, v := range out {
		e.Labels[k] = v
	}
}

// ─── parsers ────────────────────────────────────────────────────────────────

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func (p *Pipeline) applyParser(st *ParserStage, e *Entry) {
	if p.parsed == nil {
		p.parsed = make(map[string]string, 16)
	}
	clear(p.parsed)
	if st.Type != ParserJSON && st.Type != ParserUnpack {
		for _, f := range p.DerivedLevelFields {
			delete(e.Labels, f)
			delete(p.base, f)
		}
	}
	switch st.Type {
	case ParserJSON:
		parseJSONInto(e, st.Fields, p.parsed)
	case ParserLogfmt:
		parseLogfmtInto(e, st.Fields, p.parsed)
	case ParserUnpack:
		parseUnpackInto(e, p.parsed)
	case ParserPattern:
		m, err := compilePattern(st.Param)
		if err != nil {
			return
		}
		m.match(e.Line, p.parsed)
	case ParserRegexp:
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
			p.parsed[name] = m[i]
		}
	}
	p.mergeParsed(e)
}

// mergeParsed copies the stage's extracted labels onto the entry, renaming any
// that collide with a label the entry already carried — Loki's `_extracted`
// rule, without which a body field silently replaces the stream label it shares
// a name with (a `sum by (namespace)` then fans out over the body's values).
func (p *Pipeline) mergeParsed(e *Entry) {
	for k, v := range p.parsed {
		if _, collides := p.base[k]; collides {
			k += "_extracted"
		}
		e.Labels[k] = v
	}
}

func setError(labels map[string]string, kind, details string) {
	labels[errorLabel] = kind
	labels[errorDetailsLabel] = details
}

func parseJSONInto(e *Entry, params []ExtractionField, out map[string]string) {
	var v interface{}
	if err := json.Unmarshal([]byte(e.Line), &v); err != nil {
		if !e.SplitJSON {
			setError(e.Labels, "JSONParserErr", err.Error())
		}
		return
	}
	if len(params) == 0 {
		flattenJSON("", v, out)
		return
	}
	for _, prm := range params {
		path := prm.Expression
		if path == "" {
			path = prm.Name
		}
		if got, ok := lookupJSONPath(v, path); ok {
			out[sanitizeLabel(prm.Name)] = got
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

func parseLogfmtInto(e *Entry, params []ExtractionField, out map[string]string) {
	fields := parseLogfmt(e.Line)
	if len(params) == 0 {
		for k, v := range fields {
			out[sanitizeLabel(k)] = v
		}
		return
	}
	for _, prm := range params {
		src := prm.Expression
		if src == "" {
			src = prm.Name
		}
		if v, ok := fields[src]; ok {
			out[sanitizeLabel(prm.Name)] = v
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
func parseUnpackInto(e *Entry, out map[string]string) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(e.Line), &obj); err != nil {
		setError(e.Labels, "JSONParserErr", err.Error())
		return
	}
	for k, v := range obj {
		if k == "_entry" {
			if s, ok := v.(string); ok {
				e.Line = s
				e.SplitJSON = false
			}
			continue
		}
		if s, ok := v.(string); ok {
			out[sanitizeLabel(k)] = s
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

// compileExtractor turns a regexp stage into a named-group regexp (a pattern
// stage goes through compilePattern: Loki's pattern is not a regexp).
func compileExtractor(st *ParserStage) (*regexp.Regexp, error) {
	key := strconv.Itoa(int(st.Type)) + "\x00" + st.Param
	if re, ok := extractorCache.get(key); ok {
		return re, nil
	}
	src := st.Param
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("invalid %s expression %q: %w", st.String(), st.Param, err)
	}
	extractorCache.put(key, re)
	return re, nil
}

var patternCaptureRE = regexp.MustCompile(`<([a-zA-Z_][a-zA-Z0-9_]*|_)>`)

// patternPart is one element of a compiled `| pattern`: a literal, or a
// capture (name "" for `<_>`).
type patternPart struct {
	literal string
	capture string
	isCap   bool
}

// patternMatcher reproduces Loki's pattern parser (pkg/logql/log/pattern),
// which is NOT a regexp: it walks the expression left to right, each capture
// runs up to the FIRST occurrence of the literal that follows it, and a
// mismatch stops the walk KEEPING the captures filled so far — a capture whose
// following literal is absent takes the rest of the line. Round 12, class E:
// `Launch Task 'X' #81799` against `<task>;<_>;<project>;<_>` is
// `task="Launch Task 'X' #81799"` and no `project` in Loki (15 series), while
// the regexp conversion `^(?P<task>.*?);…$` matched nothing (2 series).
type patternMatcher struct {
	parts []patternPart
}

var patternCache compileCache[*patternMatcher]

// compilePattern parses a Loki pattern expression. Loki rejects an expression
// with no NAMED capture, one with two adjacent captures, and a duplicate name.
func compilePattern(pat string) (*patternMatcher, error) {
	if m, ok := patternCache.get(pat); ok {
		return m, nil
	}
	var parts []patternPart
	last := 0
	named := 0
	seen := map[string]struct{}{}
	for _, loc := range patternCaptureRE.FindAllStringSubmatchIndex(pat, -1) {
		if lit := pat[last:loc[0]]; lit != "" {
			parts = append(parts, patternPart{literal: lit})
		} else if len(parts) > 0 && parts[len(parts)-1].isCap {
			return nil, fmt.Errorf("invalid pattern %q: consecutive captures are not allowed", pat)
		}
		name := pat[loc[2]:loc[3]]
		if name == "_" {
			name = ""
		} else {
			if _, dup := seen[name]; dup {
				return nil, fmt.Errorf("invalid pattern %q: duplicate capture name (%s)", pat, name)
			}
			seen[name] = struct{}{}
			named++
		}
		parts = append(parts, patternPart{capture: name, isCap: true})
		last = loc[1]
	}
	if lit := pat[last:]; lit != "" {
		parts = append(parts, patternPart{literal: lit})
	}
	if named == 0 {
		return nil, fmt.Errorf("invalid pattern %q: at least one capture is required", pat)
	}
	m := &patternMatcher{parts: parts}
	patternCache.put(pat, m)
	return m, nil
}

// match fills out with the captures Loki's matcher would produce for in.
func (m *patternMatcher) match(in string, out map[string]string) {
	parts := m.parts
	if len(parts) > 0 && !parts[0].isCap {
		if !strings.HasPrefix(in, parts[0].literal) {
			return
		}
		in = in[len(parts[0].literal):]
		parts = parts[1:]
	}
	for len(parts) > 0 {
		capt := parts[0]
		if len(parts) == 1 {
			if capt.capture != "" {
				out[capt.capture] = in
			}
			return
		}
		lit := parts[1].literal
		i := strings.Index(in, lit)
		if i < 0 {
			if capt.capture != "" {
				out[capt.capture] = in
			}
			return
		}
		if capt.capture != "" {
			out[capt.capture] = in[:i]
		}
		in = in[i+len(lit):]
		parts = parts[2:]
	}
}

// SanitizeLabel maps a field name to a Prometheus-legal label name, as Loki does.
func SanitizeLabel(s string) string { return sanitizeLabel(s) }

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

// lineFilterTexts returns the label values a line filter reads in addition to
// the line: every label named by LineFilterFields, under the VictoriaLogs
// spelling or its sanitised Loki spelling (`State.Foo` arrives as `State_Foo`).
func (p *Pipeline) lineFilterTexts(e *Entry) []string {
	if len(p.LineFilterFields) == 0 {
		return nil
	}
	var out []string
	for _, f := range p.LineFilterFields {
		if f == "_msg" {
			continue
		}
		if prefix, ok := strings.CutSuffix(f, "*"); ok {
			sanitised := sanitizeLabel(prefix)
			for k, v := range e.Labels {
				if strings.HasPrefix(k, prefix) || strings.HasPrefix(k, sanitised) {
					out = append(out, v)
				}
			}
			continue
		}
		if v, ok := e.Labels[f]; ok {
			out = append(out, v)
		} else if v, ok := e.Labels[sanitizeLabel(f)]; ok {
			out = append(out, v)
		}
	}
	return out
}

// matchLineFilter evaluates a line filter against the line and, when the
// proxy is configured to read other fields too (extra), against each of them:
// a positive filter matches when ANY text matches, a negative one when NONE do.
func matchLineFilter(st *LineFilterStage, line string, extra []string) bool {
	texts := append([]string{line}, extra...)
	// An OR-list shares one operator: a positive filter keeps a line matching ANY
	// alternative, a negative one drops a line matching any of them.
	anyContains := func() bool {
		for _, v := range st.Values() {
			for _, text := range texts {
				if strings.Contains(text, v) {
					return true
				}
			}
		}
		return false
	}
	anyMatchesRe := func() bool {
		for _, v := range st.Values() {
			re, ok := lineFilterCache.get(v)
			if !ok {
				var err error
				re, err = regexp.Compile(v)
				if err != nil {
					return true
				}
				lineFilterCache.put(v, re)
			}
			for _, text := range texts {
				if re.MatchString(text) {
					return true
				}
			}
		}
		return false
	}
	switch st.Op {
	case LineFilterContains:
		return anyContains()
	case LineFilterExcludes:
		return !anyContains()
	case LineFilterMatchRe:
		return anyMatchesRe()
	case LineFilterExcludeRe:
		return !anyMatchesRe()
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
