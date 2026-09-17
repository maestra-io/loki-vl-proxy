package logql

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
	"unicode"
)

// Template is a compiled LogQL Go template as used by `| line_format` and
// `| label_format`. It mirrors Loki's function map (see
// https://grafana.com/docs/loki/latest/query/template_functions/).
//
// A Template is NOT safe for concurrent use: `__line__` and `__timestamp__` are
// niladic template functions in Loki, so they must read per-entry state that
// Exec mutates. Compile one Template per query and evaluate entries serially,
// or call Clone for a second goroutine.
type Template struct {
	src  string
	tmpl *template.Template

	// per-entry state read by the __line__ / __timestamp__ functions.
	line string
	ts   time.Time
}

// UnknownFuncError reports a template that references a function this proxy
// does not implement. It is surfaced to the client as a 400 naming the function
// rather than emitting the raw template text into the results.
type UnknownFuncError struct {
	Func string
	Err  error
}

func (e *UnknownFuncError) Error() string {
	return fmt.Sprintf("unsupported template function %q in line_format/label_format", e.Func)
}

func (e *UnknownFuncError) Unwrap() error { return e.Err }

// TemplateBudgetError reports a template the proxy refuses to evaluate because
// it would blow the per-line formatting budget. Unlike a plain syntax error
// (which Loki answers 200 + __error__ for) this is fatal: the client gets a 400
// naming the limit, as it does on every other budget in this proxy.
type TemplateBudgetError struct{ Msg string }

func (e *TemplateBudgetError) Error() string { return e.Msg }

var unknownFuncRE = regexp.MustCompile(`function "([^"]+)" not defined`)

// ParseTemplate compiles a LogQL template.
func ParseTemplate(src string) (*Template, error) {
	t := &Template{src: src}
	tmpl, err := template.New("logql").Option("missingkey=zero").Funcs(t.funcMap()).Parse(src)
	if err != nil {
		if m := unknownFuncRE.FindStringSubmatch(err.Error()); m != nil {
			return nil, &UnknownFuncError{Func: m[1], Err: err}
		}
		return nil, fmt.Errorf("invalid template %q: %w", src, err)
	}
	// A constant printf width is rejected at compile time so the client gets a
	// 400 naming the limit rather than a per-line __error__ it cannot act on.
	if err := checkConstantPrintfBudget(tmpl); err != nil {
		return nil, err
	}
	t.tmpl = tmpl
	return t, nil
}

// MaxTemplateOutputBytes bounds one template's formatted output. A LogQL
// template runs once per log line, so an unbounded printf width is a memory
// amplifier the client controls with a handful of query bytes.
const MaxTemplateOutputBytes = 64 << 10

// CheckPrintfFormatBudget rejects a printf format whose numeric width or
// precision would blow the per-line output budget, before fmt allocates for it.
func CheckPrintfFormatBudget(format string, max int) error {
	number := 0
	inDirective := false
	for _, c := range format {
		if !inDirective {
			if c == '%' {
				inDirective = true
			}
			continue
		}
		if c == '%' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			inDirective = false
			number = 0
			continue
		}
		if c >= '0' && c <= '9' {
			number = number*10 + int(c-'0')
			if number > max {
				return &TemplateBudgetError{Msg: "line_format printf width limit exceeded"}
			}
		} else {
			number = 0
		}
	}
	return nil
}

// boundedPrintf is Loki's `printf` with the width budget applied, so a
// template built from a runtime value cannot escape it either.
func boundedPrintf(format string, args ...any) (string, error) {
	if len(format) > MaxTemplateOutputBytes {
		return "", &TemplateBudgetError{Msg: "line_format printf limit exceeded"}
	}
	if err := CheckPrintfFormatBudget(format, MaxTemplateOutputBytes); err != nil {
		return "", err
	}
	out := fmt.Sprintf(format, args...)
	if len(out) > MaxTemplateOutputBytes {
		return "", &TemplateBudgetError{Msg: "line_format printf output limit exceeded"}
	}
	return out, nil
}

// checkConstantPrintfBudget walks the compiled tree and applies the width
// budget to every `printf` whose format is a string constant.
func checkConstantPrintfBudget(tmpl *template.Template) error {
	if tmpl.Tree == nil {
		return nil
	}
	var walkList func(*parse.ListNode) error
	walkPipe := func(pipe *parse.PipeNode) error {
		if pipe == nil {
			return nil
		}
		for _, cmd := range pipe.Cmds {
			if len(cmd.Args) < 2 {
				continue
			}
			ident, ok := cmd.Args[0].(*parse.IdentifierNode)
			if !ok || ident.Ident != "printf" {
				continue
			}
			str, ok := cmd.Args[1].(*parse.StringNode)
			if !ok {
				continue
			}
			if len(str.Text) > MaxTemplateOutputBytes {
				return &TemplateBudgetError{Msg: "line_format printf limit exceeded"}
			}
			if err := CheckPrintfFormatBudget(str.Text, MaxTemplateOutputBytes); err != nil {
				return err
			}
		}
		return nil
	}
	walkList = func(list *parse.ListNode) error {
		if list == nil {
			return nil
		}
		for _, node := range list.Nodes {
			var branch *parse.BranchNode
			switch n := node.(type) {
			case *parse.ActionNode:
				if err := walkPipe(n.Pipe); err != nil {
					return err
				}
			case *parse.IfNode:
				branch = &n.BranchNode
			case *parse.RangeNode:
				branch = &n.BranchNode
			case *parse.WithNode:
				branch = &n.BranchNode
			}
			if branch != nil {
				if err := walkPipe(branch.Pipe); err != nil {
					return err
				}
				if err := walkList(branch.List); err != nil {
					return err
				}
				if err := walkList(branch.ElseList); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walkList(tmpl.Tree.Root)
}

// Clone returns an independent copy that can be evaluated on another goroutine.
func (t *Template) Clone() (*Template, error) { return ParseTemplate(t.src) }

// Source returns the original template text.
func (t *Template) Source() string { return t.src }

// Exec evaluates the template for one entry. labels supplies `.field` lookups,
// line backs `__line__` and ts backs `__timestamp__`.
func (t *Template) Exec(labels map[string]string, line string, ts time.Time, buf *strings.Builder) (string, error) {
	t.line, t.ts = line, ts
	buf.Reset()
	if err := t.tmpl.Execute(buf, labels); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ─── function map ───────────────────────────────────────────────────────────

func (t *Template) funcMap() template.FuncMap {
	fm := template.FuncMap{
		"__line__":      func() string { return t.line },
		"__timestamp__": func() time.Time { return t.ts },
		"printf":        boundedPrintf,
	}
	for k, v := range lokiFuncs {
		fm[k] = v
	}
	return fm
}

// lokiFuncs is the entry-independent part of Loki's template function map.
// Argument order follows the docs: the piped value is the LAST argument.
var lokiFuncs = template.FuncMap{
	// ── strings ──
	"lower":      strings.ToLower,
	"upper":      strings.ToUpper,
	"title":      titleCase,
	"trim":       strings.TrimSpace,
	"trimAll":    func(cut, s string) string { return strings.Trim(s, cut) },
	"trimPrefix": func(prefix, s string) string { return strings.TrimPrefix(s, prefix) },
	"trimSuffix": func(suffix, s string) string { return strings.TrimSuffix(s, suffix) },
	"trunc":      truncate,
	"substr":     substring,
	"replace":    func(old, new, s string) string { return strings.ReplaceAll(s, old, new) }, //nolint:predeclared // sprig/Loki parameter names
	"repeat":     func(n int, s string) string { return strings.Repeat(s, maxInt(n, 0)) },
	"indent":     func(spaces int, s string) string { return indent(spaces, s) },
	"nindent":    func(spaces int, s string) string { return "\n" + indent(spaces, s) },
	"alignLeft":  alignLeft,
	"alignRight": alignRight,
	"default":    defaultVal,
	"contains":   func(substr, s string) bool { return strings.Contains(s, substr) },
	"hasPrefix":  func(prefix, s string) bool { return strings.HasPrefix(s, prefix) },
	"hasSuffix":  func(suffix, s string) bool { return strings.HasSuffix(s, suffix) },
	"bytes":      humanBytes,

	// ── encoding ──
	"b64enc":    func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
	"b64dec":    b64dec,
	"urlencode": url.QueryEscape,
	"urldecode": urlDecode,
	"fromJson":  fromJSON,
	"toJson":    toJSON,

	// ── regex ──
	"regexReplaceAll":        regexReplaceAll,
	"regexReplaceAllLiteral": regexReplaceAllLiteral,
	"count":                  regexCount,

	// ── time ──
	"now":              time.Now,
	"date":             dateFormat,
	"toDate":           toDate,
	"toDateInZone":     toDateInZone,
	"unixEpoch":        func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) },
	"unixEpochMillis":  func(t time.Time) string { return strconv.FormatInt(t.UnixMilli(), 10) },
	"unixEpochNanos":   func(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) },
	"unixToTime":       unixToTime,
	"duration":         durationSecondsFn,
	"duration_seconds": durationSecondsFn,

	// ── math ──
	"int":     toInt,
	"float64": toFloat,
	"add":     func(v ...interface{}) int64 { return foldInt(0, v, func(a, b int64) int64 { return a + b }) },
	"sub":     func(a, b interface{}) int64 { return toInt64(a) - toInt64(b) },
	"mul": func(a interface{}, v ...interface{}) int64 {
		return foldInt(toInt64(a), v, func(x, y int64) int64 { return x * y })
	},
	"div":  func(a, b interface{}) int64 { return divInt(toInt64(a), toInt64(b)) },
	"mod":  func(a, b interface{}) int64 { return modInt(toInt64(a), toInt64(b)) },
	"addf": func(v ...interface{}) float64 { return foldFloat(0, v, func(a, b float64) float64 { return a + b }) },
	"subf": func(a interface{}, v ...interface{}) float64 {
		return foldFloat(toFloat(a), v, func(x, y float64) float64 { return x - y })
	},
	"mulf": func(a interface{}, v ...interface{}) float64 {
		return foldFloat(toFloat(a), v, func(x, y float64) float64 { return x * y })
	},
	"divf":  func(a interface{}, v ...interface{}) float64 { return foldFloat(toFloat(a), v, divFloat) },
	"max":   func(a interface{}, v ...interface{}) int64 { return foldInt(toInt64(a), v, maxInt64) },
	"min":   func(a interface{}, v ...interface{}) int64 { return foldInt(toInt64(a), v, minInt64) },
	"maxf":  func(a interface{}, v ...interface{}) float64 { return foldFloat(toFloat(a), v, math.Max) },
	"minf":  func(a interface{}, v ...interface{}) float64 { return foldFloat(toFloat(a), v, math.Min) },
	"ceil":  func(a interface{}) float64 { return math.Ceil(toFloat(a)) },
	"floor": func(a interface{}) float64 { return math.Floor(toFloat(a)) },
	"round": roundTo,

	// ── deprecated CamelCase aliases (Go `strings` argument order) ──
	"ToLower":    strings.ToLower,
	"ToUpper":    strings.ToUpper,
	"Title":      titleCase,
	"Replace":    strings.Replace,
	"Trim":       strings.Trim,
	"TrimAll":    func(s, cut string) string { return strings.Trim(s, cut) },
	"TrimLeft":   strings.TrimLeft,
	"TrimRight":  strings.TrimRight,
	"TrimPrefix": strings.TrimPrefix,
	"TrimSuffix": strings.TrimSuffix,
	"TrimSpace":  strings.TrimSpace,
	"Substr":     func(s string, start, end int) string { return substring(start, end, s) },
	"HasPrefix":  strings.HasPrefix,
	"HasSuffix":  strings.HasSuffix,
	"Contains":   strings.Contains,
}

// TemplateFuncNames reports every function name the evaluator implements.
// Used by the docs test to keep documentation and implementation in step.
func TemplateFuncNames() []string {
	names := make([]string, 0, len(lokiFuncs)+2)
	names = append(names, "__line__", "__timestamp__")
	for k := range lokiFuncs {
		names = append(names, k)
	}
	return names
}

// ─── helpers ────────────────────────────────────────────────────────────────

func titleCase(s string) string {
	prevIsLetter := false
	return strings.Map(func(r rune) rune {
		if !prevIsLetter && unicode.IsLetter(r) {
			prevIsLetter = true
			return unicode.ToTitle(r)
		}
		prevIsLetter = unicode.IsLetter(r)
		return r
	}, s)
}

// truncate cuts s to n runes. A negative n keeps the LAST -n runes (sprig).
func truncate(n int, s string) string {
	r := []rune(s)
	switch {
	case n < 0:
		if -n >= len(r) {
			return s
		}
		return string(r[len(r)+n:])
	case n >= len(r):
		return s
	default:
		return string(r[:n])
	}
}

// substring returns s[start:end] in runes; a negative bound means "omitted".
func substring(start, end int, s string) string {
	r := []rune(s)
	if start < 0 {
		start = 0
	}
	if end < 0 || end > len(r) {
		end = len(r)
	}
	if start > len(r) || start >= end {
		return ""
	}
	return string(r[start:end])
}

func indent(spaces int, s string) string {
	pad := strings.Repeat(" ", maxInt(spaces, 0))
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

func alignLeft(count int, src string) string {
	r := []rune(src)
	if len(r) >= count {
		return string(r[:maxInt(count, 0)])
	}
	return src + strings.Repeat(" ", count-len(r))
}

func alignRight(count int, src string) string {
	r := []rune(src)
	if len(r) >= count {
		return string(r[len(r)-maxInt(count, 0):])
	}
	return strings.Repeat(" ", count-len(r)) + src
}

// defaultVal returns def when the piped value is empty. Loki's signature is
// default(d, src); used bare ({{ default "-" .x }}) or piped ({{ .x | default "-" }}).
func defaultVal(def string, src ...interface{}) string {
	if len(src) == 0 {
		return def
	}
	s := stringify(src[len(src)-1])
	if s == "" {
		return def
	}
	return s
}

func b64dec(s string) string {
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(out)
}

func urlDecode(s string) string {
	out, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return out
}

func fromJSON(s string) interface{} {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

func toJSON(v interface{}) string {
	out, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(out)
}

func regexReplaceAll(re, src, repl string) string {
	r, err := regexp.Compile(re)
	if err != nil {
		return src
	}
	return r.ReplaceAllString(src, repl)
}

func regexReplaceAllLiteral(re, src, repl string) string {
	r, err := regexp.Compile(re)
	if err != nil {
		return src
	}
	return r.ReplaceAllLiteralString(src, repl)
}

func regexCount(re, src string) int {
	r, err := regexp.Compile(re)
	if err != nil {
		return 0
	}
	return len(r.FindAllStringIndex(src, -1))
}

func dateFormat(layout string, v interface{}) string {
	switch t := v.(type) {
	case time.Time:
		return t.Format(layout)
	case *time.Time:
		if t == nil {
			return ""
		}
		return t.Format(layout)
	default:
		return ""
	}
}

func toDate(layout, s string) time.Time {
	t, _ := time.Parse(layout, s) //nolint:errcheck // Loki returns the zero time on failure
	return t
}

func toDateInZone(layout, zone, s string) time.Time {
	loc, err := time.LoadLocation(zone)
	if err != nil {
		loc = time.UTC
	}
	t, _ := time.ParseInLocation(layout, s, loc) //nolint:errcheck // zero time on failure
	return t
}

func unixToTime(epoch string) time.Time {
	n, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil {
		return time.Time{}
	}
	// Loki picks the unit from the digit count: s / ms / µs / ns.
	switch len(epoch) {
	case 13:
		return time.UnixMilli(n)
	case 16:
		return time.UnixMicro(n)
	case 19:
		return time.Unix(0, n)
	default:
		return time.Unix(n, 0)
	}
}

func durationSecondsFn(s string) float64 {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d.Seconds()
}

// byteSizeUnits maps a humanised size suffix to its multiplier. Longest suffix
// wins, so "KiB" is matched before "B".
var byteSizeUnits = []struct {
	suffix string
	factor float64
}{
	{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"TiB", 1 << 40},
	{"PiB", 1 << 50}, {"EiB", 1 << 60},
	{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"TB", 1e12}, {"PB", 1e15}, {"EB", 1e18},
	{"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}, {"P", 1e15}, {"E", 1e18},
	{"B", 1},
}

// humanBytes implements Loki's `bytes`: it PARSES a humanised size and returns
// the byte count ("2kB" → 2000, "1KiB" → 1024, "2048" → 2048). It does not
// render a number as a humanised string — that is the opposite direction, and
// getting it backwards silently corrupted every `{{ .size | bytes }}`.
func humanBytes(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "0"
	}
	for _, u := range byteSizeUnits {
		if len(trimmed) <= len(u.suffix) {
			continue
		}
		if !strings.EqualFold(trimmed[len(trimmed)-len(u.suffix):], u.suffix) {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(trimmed[:len(trimmed)-len(u.suffix)]), 64)
		if err != nil {
			continue
		}
		return strconv.FormatFloat(n*u.factor, 'f', -1, 64)
	}
	n, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return "0"
	}
	return strconv.FormatFloat(n, 'f', -1, 64)
}

func stringify(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

func toInt(v interface{}) int { return int(toInt64(v)) }

func toInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int:
		return int64(t)
	case int64:
		return t
	case float64:
		return int64(t)
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return n
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(t), 64); err == nil {
			return int64(f)
		}
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	default:
		return 0
	}
}

func toFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0
		}
		return f
	default:
		return 0
	}
}

func foldInt(acc int64, vals []interface{}, op func(a, b int64) int64) int64 {
	for _, v := range vals {
		acc = op(acc, toInt64(v))
	}
	return acc
}

func foldFloat(acc float64, vals []interface{}, op func(a, b float64) float64) float64 {
	for _, v := range vals {
		acc = op(acc, toFloat(v))
	}
	return acc
}

func divInt(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func modInt(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return a % b
}

func divFloat(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func roundTo(v interface{}, precision int, _ ...float64) float64 {
	shift := math.Pow(10, float64(precision))
	return math.Round(toFloat(v)*shift) / shift
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
