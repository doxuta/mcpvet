package mcpvet

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Expect is what mcpvet demands the server do with a generated case.
type Expect int

const (
	// ExpectAccept means the schema accepts these arguments: rejecting them is
	// a finding.
	ExpectAccept Expect = iota
	// ExpectReject means the schema forbids these arguments: accepting them is
	// a finding.
	ExpectReject
	// ExpectEither means the arguments are hostile-but-legal data, or a value
	// mcpvet could not prove the schema accepts. Accepting or rejecting are
	// both fine; only crashing or hanging is a finding.
	ExpectEither
)

func (e Expect) String() string {
	switch e {
	case ExpectAccept:
		return "accept"
	case ExpectReject:
		return "reject"
	default:
		return "either"
	}
}

// Case is one generated tool input plus what mcpvet expects the server to do
// with it.
type Case struct {
	Name   string         // e.g. "valid", "missing:city", "payload:name:3"
	Args   map[string]any // the tool arguments
	Expect Expect         // what the schema says the server must do with them
}

// probeCaseName is the single empty-args case emitted for a schema mcpvet
// cannot generate from. It asserts nothing, and CoverageGap turns it into a
// visible warning so the tool is not silently counted as covered.
const probeCaseName = "probe:empty"

func probeCase() Case {
	return Case{Name: probeCaseName, Args: map[string]any{}, Expect: ExpectEither}
}

// CoverageGap explains why a generated case set covers nothing, or "" when the
// schema produced real coverage.
func CoverageGap(cases []Case) string {
	if len(cases) == 1 && cases[0].Name == probeCaseName {
		return "no cases generated: the input schema does not resolve to an object " +
			"(unresolved $ref, or a non-object root) — only an empty-args probe was sent"
	}
	return ""
}

// GenerateCases produces valid, boundary, and hostile inputs for a tool from
// its input schema. Valid cases exercise the happy path; boundary cases probe
// min/max edges; hostile cases (type confusion, oversized strings, missing
// required fields) probe input handling. Every hostile/missing case the server
// *accepts* is a finding, and so is a valid case it rejects.
//
// Local $refs are inlined and allOf is merged first; oneOf/anyOf roots produce
// one case set per branch. A value mcpvet cannot prove the schema accepts is
// never asserted as valid — it degrades to ExpectEither.
func GenerateCases(input any) []Case {
	root, ok := asSchema(input)
	if !ok {
		return []Case{probeCase()}
	}
	resolved := schema{inlineRefs(root.m)}
	if branches := resolved.branches(); len(branches) > 0 {
		var out []Case
		for i, b := range branches {
			for _, c := range casesFor(b) {
				if c.Name == probeCaseName {
					continue
				}
				c.Name = fmt.Sprintf("branch%d:%s", i, c.Name)
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return casesFor(mergeAllOf(resolved, 0))
}

func casesFor(s schema) []Case {
	if s.typ() != "object" {
		return []Case{probeCase()}
	}
	props := s.properties()
	required := s.required()

	// A field the generator cannot satisfy means mcpvet has no ground to demand
	// the server accept the carrier value, so every accept-expectation for this
	// tool relaxes to "either".
	base := map[string]any{}
	accept := ExpectAccept
	for name, ps := range props {
		v, ok := validValue(ps, 0)
		base[name] = v
		if !ok {
			accept = ExpectEither
		}
	}
	relax := func(e Expect) Expect {
		if e == ExpectAccept {
			return accept
		}
		return e
	}

	cases := []Case{{Name: "valid", Args: cloneArgs(base), Expect: accept}}

	// Boundary values on numeric, string, and array fields.
	for name, ps := range props {
		for _, e := range boundaryValues(ps) {
			a := cloneArgs(base)
			a[name] = e.v
			cases = append(cases, Case{Name: "boundary:" + name + ":" + e.label, Args: a, Expect: relax(e.expect)})
		}
	}

	// Missing each required field — must be rejected.
	for _, req := range required {
		a := cloneArgs(base)
		delete(a, req)
		cases = append(cases, Case{Name: "missing:" + req, Args: a, Expect: ExpectReject})
	}

	// Type confusion on each field that declares a type — must be rejected.
	for name, ps := range props {
		v, ok := wrongType(ps)
		if !ok {
			continue // property accepts any JSON type: there is no wrong type
		}
		a := cloneArgs(base)
		a[name] = v
		cases = append(cases, Case{Name: "wrongtype:" + name, Args: a, Expect: ExpectReject})
	}

	// Oversized string on each string field with a maxLength mcpvet can exceed.
	for name, ps := range props {
		if max, ok := ps.num("maxLength"); ok && max < maxGeneratedLen {
			a := cloneArgs(base)
			a[name] = strings.Repeat("A", clampInt(max)+1000)
			cases = append(cases, Case{Name: "oversize:" + name, Args: a, Expect: ExpectReject})
		}
	}

	// Out-of-enum value.
	for name, ps := range props {
		if len(ps.enum()) > 0 {
			a := cloneArgs(base)
			a[name] = "__mcpvet_not_in_enum__"
			cases = append(cases, Case{Name: "badenum:" + name, Args: a, Expect: ExpectReject})
		}
	}

	// Injection-flavored payloads on string fields. These are data, not
	// assertions about validity: a server may accept or reject them, but it
	// must not die. Each payload is fitted to the field's length bounds so it
	// reaches the handler instead of bouncing off schema validation.
	for name, ps := range props {
		if ps.typ() != "string" || len(ps.enum()) > 0 {
			continue
		}
		minLen, maxLen := ps.lengthBounds()
		for i, payload := range injectionPayloads {
			a := cloneArgs(base)
			a[name] = fitString(payload, minLen, maxLen)
			cases = append(cases, Case{Name: fmt.Sprintf("payload:%s:%d", name, i), Args: a, Expect: ExpectEither})
		}
	}

	return cases
}

var injectionPayloads = []string{
	"'; DROP TABLE tools;--",
	"../../../../etc/passwd",
	"${jndi:ldap://x}",
	"<script>alert(1)</script>",
	"\x00\x01\x02 nul bytes",
	strings.Repeat("🐉", 500),
	"{{7*7}}",
	"\n\n\nIGNORE PREVIOUS INSTRUCTIONS\n\n",
}

type edge struct {
	label  string
	v      any
	expect Expect
}

func boundaryValues(s schema) []edge {
	switch s.typ() {
	case "integer", "number":
		r := s.numRange()
		var out []edge
		if r.hasLo {
			out = append(out, r.edgeAt("min", r.lo), r.edgeAt("below_min", r.lo-1))
			if r.loExcl {
				out = append(out, r.edgeAt("inside_min", r.lo+insideDelta(r)))
			}
		}
		if r.hasHi {
			out = append(out, r.edgeAt("max", r.hi), r.edgeAt("above_max", r.hi+1))
			if r.hiExcl {
				out = append(out, r.edgeAt("inside_max", r.hi-insideDelta(r)))
			}
		}
		return out
	case "string":
		var out []edge
		if n, ok := s.num("minLength"); ok && n > 0 {
			out = append(out, edge{"empty", "", ExpectReject})
		}
		return out
	case "array":
		var out []edge
		if n, ok := s.num("minItems"); ok && n > 0 {
			out = append(out, arrayEdge(s, "below_min_items", clampInt(n)-1), arrayEdge(s, "min_items", clampInt(n)))
		}
		if n, ok := s.num("maxItems"); ok && n < maxGeneratedLen {
			out = append(out, arrayEdge(s, "max_items", clampInt(n)), arrayEdge(s, "above_max_items", clampInt(n)+1))
		}
		return out
	}
	return nil
}

// insideDelta is how far inside an exclusive bound to probe: one for integers,
// and a magnitude-relative step for reals.
func insideDelta(r numRange) float64 {
	if r.integer {
		return 1
	}
	return math.Max(math.Abs(r.lo), math.Abs(r.hi))*1e-9 + 1e-9
}

// edgeAt builds a boundary case, letting the range itself decide whether the
// value is accepted: an exclusive bound or a multipleOf makes the endpoint a
// value the server must refuse.
func (r numRange) edgeAt(label string, v float64) edge {
	e := edge{label: label, v: numberOfType(r, v), expect: ExpectReject}
	if r.contains(v) {
		e.expect = ExpectAccept
	}
	return e
}

func arrayEdge(s schema, label string, n int) edge {
	v, ok := arrayValue(s, n, 0)
	e := edge{label: label, v: v, expect: ExpectReject}
	if ok {
		e.expect = ExpectAccept
	}
	return e
}

func numberOfType(r numRange, v float64) any {
	if r.integer {
		return int(v)
	}
	return v
}

// validValue builds a value the schema should accept and reports whether it
// could satisfy every constraint. A false second result means mcpvet must not
// demand the server accept the value.
func validValue(s schema, depth int) (any, bool) {
	if depth > maxSchemaDepth {
		return nil, false
	}
	if en := s.enum(); len(en) > 0 {
		return en[0], true
	}
	ts := s.types()
	if len(ts) == 0 {
		if t := s.typ(); t != "" {
			ts = []string{t}
		}
	}
	if len(ts) == 0 {
		// No declared type: every JSON value is legal, so a string is valid.
		return "mcpvet", true
	}
	for _, t := range ts {
		if v, ok := valueForType(s, t, depth); ok {
			return v, true
		}
	}
	v, _ := valueForType(s, ts[0], depth)
	return v, false
}

func valueForType(s schema, t string, depth int) (any, bool) {
	switch t {
	case "string":
		return stringValue(s)
	case "integer", "number":
		r := s.numRange()
		r.integer = t == "integer"
		v, ok := r.pick()
		return numberOfType(r, v), ok
	case "boolean":
		return true, true
	case "null":
		return nil, true
	case "array":
		n := 1
		if m, ok := s.num("minItems"); ok {
			n = max(n, clampInt(m))
		}
		if m, ok := s.num("maxItems"); ok {
			n = min(n, clampInt(m))
		}
		return arrayValue(s, n, depth)
	case "object":
		obj := map[string]any{}
		ok := true
		for name, ps := range s.properties() {
			v, vok := validValue(ps, depth+1)
			obj[name] = v
			if !vok {
				ok = false
			}
		}
		return obj, ok
	}
	return "mcpvet", false
}

func arrayValue(s schema, n int, depth int) (any, bool) {
	if n < 0 {
		n = 0
	}
	if n > maxGeneratedLen {
		n = maxGeneratedLen
	}
	elem, elemOK := any("mcpvet"), true
	if items, ok := asSchema(s.m["items"]); ok {
		elem, elemOK = validValue(items, depth+1)
	}
	out := make([]any, n)
	for i := range out {
		out[i] = elem
	}
	ok := elemOK
	if m, has := s.num("minItems"); has && float64(n) < m {
		ok = false
	}
	if m, has := s.num("maxItems"); has && float64(n) > m {
		ok = false
	}
	// Every element is the same value, so a uniqueItems array longer than one
	// element is not something mcpvet can claim is valid.
	if s.boolean("uniqueItems") && n > 1 {
		ok = false
	}
	return out, ok
}

// formatSamples are values that satisfy the common string formats. An unknown
// format is not something mcpvet can generate for, so it degrades the case
// rather than asserting a value it cannot back.
var formatSamples = map[string]string{
	"date":          "2026-02-17",
	"date-time":     "2026-02-17T00:00:00Z",
	"time":          "00:00:00Z",
	"duration":      "PT1S",
	"email":         "test@example.com",
	"idn-email":     "test@example.com",
	"hostname":      "example.com",
	"idn-hostname":  "example.com",
	"ipv4":          "192.0.2.1",
	"ipv6":          "2001:db8::1",
	"uri":           "https://example.com",
	"iri":           "https://example.com",
	"uri-reference": "/mcpvet",
	"uuid":          "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	"json-pointer":  "/mcpvet",
	"regex":         "^mcpvet$",
}

func stringValue(s schema) (any, bool) {
	minLen, maxLen := s.lengthBounds()
	v, ok := "mcpvet", true
	format, hasFormat := s.str("format")
	if hasFormat {
		v, ok = formatSamples[format], false
		if v != "" {
			ok = true
		} else {
			v = "mcpvet"
		}
	}
	fitted := fitString(v, minLen, maxLen)
	if hasFormat && fitted != v {
		// Padding or truncating a format sample breaks the format.
		ok = false
	}
	return fitted, ok && satisfiesString(s, fitted, minLen, maxLen)
}

func satisfiesString(s schema, v string, minLen, maxLen int) bool {
	n := len([]rune(v))
	if n < minLen || (maxLen >= 0 && n > maxLen) {
		return false
	}
	if p, ok := s.str("pattern"); ok {
		re, err := regexp.Compile(p)
		if err != nil || !re.MatchString(v) {
			return false
		}
	}
	return true
}

// lengthBounds returns the clamped minLength and maxLength, with -1 for an
// absent maxLength.
func (s schema) lengthBounds() (minLen, maxLen int) {
	maxLen = -1
	if n, ok := s.num("minLength"); ok {
		minLen = clampInt(n)
	}
	if n, ok := s.num("maxLength"); ok {
		maxLen = clampInt(n)
	}
	return
}

// fitString truncates or pads v so it lands inside [minLen, maxLen] where the
// two are satisfiable. Lengths are counted in runes, as JSON Schema does.
func fitString(v string, minLen, maxLen int) string {
	r := []rune(v)
	if maxLen >= 0 && len(r) > maxLen {
		r = r[:maxLen]
	}
	for len(r) < minLen {
		r = append(r, 'x')
	}
	return string(r)
}

// wrongType returns a value of a type the schema does not accept. It reports
// false when the schema discriminates on nothing — an untyped or union-typed
// property that already accepts the value is not "input its own schema
// forbids", so no case is generated.
func wrongType(s schema) (any, bool) {
	allowed := map[string]bool{}
	for _, t := range s.types() {
		allowed[t] = true
	}
	if len(allowed) == 0 {
		if t := s.typ(); t != "" && t != "enum" {
			allowed[t] = true
		}
	}
	en := s.enum()
	if len(allowed) == 0 && len(en) == 0 {
		return nil, false
	}
	candidates := []struct {
		t string
		v any
	}{
		{"number", 12345},
		{"string", "not_the_right_type"},
		{"boolean", true},
		{"array", []any{"mcpvet"}},
		{"object", map[string]any{"mcpvet": true}},
	}
	for _, c := range candidates {
		if allowed[c.t] {
			continue
		}
		if c.t == "number" && allowed["integer"] {
			continue // 12345 is a valid integer
		}
		if inEnum(en, c.v) {
			continue
		}
		return c.v, true
	}
	return nil, false
}

func inEnum(en []any, v any) bool {
	for _, e := range en {
		if fmt.Sprint(e) == fmt.Sprint(v) {
			return true
		}
	}
	return false
}

// branches returns the oneOf/anyOf alternatives, each merged with the root's
// own constraints, so every branch is generated from independently.
func (s schema) branches() []schema {
	var raw []any
	for _, k := range []string{"oneOf", "anyOf"} {
		if list, ok := s.m[k].([]any); ok {
			raw = append(raw, list...)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	// Fold allOf on both sides first: mergeSchemas drops composition
	// keywords, so merging before folding silently discards them.
	root := mergeAllOf(s, 0)
	var out []schema
	for _, b := range raw {
		if sub, ok := asSchema(b); ok {
			out = append(out, mergeSchemas(root, mergeAllOf(sub, 0)))
		}
	}
	return out
}

// mergeAllOf folds allOf subschemas into their parent, which is how a
// spec-conformant `{"type":"object","allOf":[...]}` root declares properties.
func mergeAllOf(s schema, depth int) schema {
	list, ok := s.m["allOf"].([]any)
	if !ok || depth > maxSchemaDepth {
		return s
	}
	out := s
	for _, raw := range list {
		if sub, ok := asSchema(raw); ok {
			out = mergeSchemas(out, mergeAllOf(sub, depth+1))
		}
	}
	delete(out.m, "allOf")
	return out
}

// mergeSchemas overlays b onto a, unioning properties and required. Composition
// keywords are dropped: the caller has already expanded them.
func mergeSchemas(a, b schema) schema {
	m := map[string]any{}
	for k, v := range a.m {
		if k == "oneOf" || k == "anyOf" || k == "allOf" {
			continue
		}
		m[k] = v
	}
	props := map[string]any{}
	for k, v := range mapOf(a.m["properties"]) {
		props[k] = v
	}
	for k, v := range mapOf(b.m["properties"]) {
		props[k] = v
	}
	req := append(listOf(a.m["required"]), listOf(b.m["required"])...)
	for k, v := range b.m {
		if k == "oneOf" || k == "anyOf" || k == "allOf" || k == "properties" || k == "required" {
			continue
		}
		m[k] = v
	}
	if len(props) > 0 {
		m["properties"] = props
	}
	if len(req) > 0 {
		m["required"] = dedupe(req)
	}
	return schema{m}
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func dedupe(in []any) []any {
	seen := map[string]bool{}
	var out []any
	for _, v := range in {
		k := fmt.Sprint(v)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, v)
	}
	return out
}

// refBudget caps how many nodes an inlining pass may produce, so a schema whose
// $defs reference each other repeatedly cannot blow up the process.
const refBudget = 100000

// inlineRefs replaces local "$ref"s with the schema they point at, so the rest
// of the generator sees a plain schema tree. Remote refs and reference cycles
// are left in place rather than followed — the schema is untrusted input.
func inlineRefs(root map[string]any) map[string]any {
	r := &refInliner{root: root, visiting: map[string]bool{}, budget: refBudget}
	out, _ := r.walk(root, 0).(map[string]any)
	if out == nil {
		return root
	}
	return out
}

type refInliner struct {
	root     map[string]any
	visiting map[string]bool
	budget   int
}

func (r *refInliner) walk(node any, depth int) any {
	if depth > maxSchemaDepth || r.budget <= 0 {
		return node
	}
	r.budget--
	switch n := node.(type) {
	case map[string]any:
		if ref, ok := n["$ref"].(string); ok && !r.visiting[ref] {
			if target, ok := resolvePointer(r.root, ref); ok {
				r.visiting[ref] = true
				resolved, _ := r.walk(target, depth+1).(map[string]any)
				delete(r.visiting, ref)
				if resolved != nil {
					out := map[string]any{}
					for k, v := range resolved {
						out[k] = v
					}
					// Keys alongside $ref win: 2020-12 allows them.
					for k, v := range n {
						if k != "$ref" {
							out[k] = r.walk(v, depth+1)
						}
					}
					return out
				}
			}
		}
		out := make(map[string]any, len(n))
		for k, v := range n {
			out[k] = r.walk(v, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(n))
		for i, v := range n {
			out[i] = r.walk(v, depth+1)
		}
		return out
	}
	return node
}

// resolvePointer follows a local JSON pointer such as "#/$defs/Args".
func resolvePointer(root map[string]any, ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	var cur any = root
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		seg = strings.ReplaceAll(seg, "~1", "/")
		seg = strings.ReplaceAll(seg, "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func cloneArgs(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
