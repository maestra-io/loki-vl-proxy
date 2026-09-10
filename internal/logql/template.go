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
	t.tmpl = tmpl
	return t, nil
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

var byteUnits = []string{"B", "kB", "MB", "GB", "TB", "PB", "EB"}

func humanBytes(s string) string {
	v := toFloat(s)
	i := 0
	for v >= 1000 && i < len(byteUnits)-1 {
		v /= 1000
		i++
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + byteUnits[i]
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
