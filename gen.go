package mcpvet

import (
	"fmt"
	"strings"
)

// Case is one generated tool input plus what mcpvet expects the server to do
// with it.
type Case struct {
	Name  string         // e.g. "valid", "missing:city", "hostile:oversize:name"
	Args  map[string]any // the tool arguments
	Valid bool           // true if the schema should accept these args
}

// GenerateCases produces valid, boundary, and hostile inputs for a tool from
// its input schema. Valid cases exercise the happy path; boundary cases probe
// min/max edges; hostile cases (type confusion, oversized strings, missing
// required fields, unexpected extra fields) probe input handling. Every
// hostile/missing case that the server *accepts* is a finding.
func GenerateCases(input any) []Case {
	s, ok := asSchema(input)
	if !ok || s.typ() != "object" {
		return []Case{{Name: "valid:empty", Args: map[string]any{}, Valid: true}}
	}
	props := s.properties()
	required := s.required()

	base := map[string]any{}
	for name, ps := range props {
		base[name] = validValue(ps)
	}

	cases := []Case{{Name: "valid", Args: cloneArgs(base), Valid: true}}

	// Boundary values on numeric/string fields.
	for name, ps := range props {
		for _, edge := range boundaryValues(ps) {
			a := cloneArgs(base)
			a[name] = edge.v
			cases = append(cases, Case{Name: "boundary:" + name + ":" + edge.label, Args: a, Valid: edge.valid})
		}
	}

	// Missing each required field — must be rejected.
	for _, req := range required {
		a := cloneArgs(base)
		delete(a, req)
		cases = append(cases, Case{Name: "missing:" + req, Args: a, Valid: false})
	}

	// Type confusion on each field — must be rejected.
	for name, ps := range props {
		a := cloneArgs(base)
		a[name] = wrongType(ps)
		cases = append(cases, Case{Name: "wrongtype:" + name, Args: a, Valid: false})
	}

	// Oversized string on each string field with a maxLength.
	for name, ps := range props {
		if max, ok := ps.num("maxLength"); ok {
			a := cloneArgs(base)
			a[name] = strings.Repeat("A", clampInt(max)+1000)
			cases = append(cases, Case{Name: "oversize:" + name, Args: a, Valid: false})
		}
	}

	// Out-of-enum value.
	for name, ps := range props {
		if len(ps.enum()) > 0 {
			a := cloneArgs(base)
			a[name] = "__mcpvet_not_in_enum__"
			cases = append(cases, Case{Name: "badenum:" + name, Args: a, Valid: false})
		}
	}

	// Injection-flavored payloads on string fields (should be accepted as data
	// but must never crash the handler).
	for name, ps := range props {
		if ps.typ() == "string" && len(ps.enum()) == 0 {
			for i, payload := range injectionPayloads {
				a := cloneArgs(base)
				a[name] = payload
				cases = append(cases, Case{Name: fmt.Sprintf("payload:%s:%d", name, i), Args: a, Valid: true})
			}
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
	label string
	v     any
	valid bool
}

func boundaryValues(s schema) []edge {
	switch s.typ() {
	case "integer", "number":
		min, max, hasMin, hasMax := s.numberBounds()
		var out []edge
		if hasMin {
			out = append(out, edge{"min", min, true}, edge{"below_min", min - 1, false})
		}
		if hasMax {
			out = append(out, edge{"max", max, true}, edge{"above_max", max + 1, false})
		}
		return out
	case "string":
		var out []edge
		if n, ok := s.num("minLength"); ok && n > 0 {
			out = append(out, edge{"empty", "", false})
		}
		return out
	}
	return nil
}

func validValue(s schema) any {
	if en := s.enum(); len(en) > 0 {
		return en[0]
	}
	switch s.typ() {
	case "string":
		if f, ok := s.str("format"); ok {
			switch f {
			case "date":
				return "2026-02-17"
			case "date-time":
				return "2026-02-17T00:00:00Z"
			case "email":
				return "test@example.com"
			case "uri":
				return "https://example.com"
			}
		}
		if n, ok := s.num("minLength"); ok {
			return strings.Repeat("x", clampInt(n))
		}
		return "mcpvet"
	case "integer", "number":
		min, max, hasMin, hasMax := s.numberBounds()
		if hasMin && hasMax {
			return int((min + max) / 2)
		}
		if hasMin {
			return int(min)
		}
		return 1
	case "boolean":
		return true
	case "array":
		if items, ok := asSchema(s.m["items"]); ok {
			return []any{validValue(items)}
		}
		return []any{}
	case "object":
		obj := map[string]any{}
		for name, ps := range s.properties() {
			obj[name] = validValue(ps)
		}
		return obj
	}
	return "mcpvet"
}

func wrongType(s schema) any {
	switch s.typ() {
	case "string", "enum":
		return 12345 // number where a string is expected
	default:
		return "not_the_right_type"
	}
}

func cloneArgs(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
