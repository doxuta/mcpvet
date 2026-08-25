// Package mcpvet is a contract-testing and drift-detection tool for Model
// Context Protocol (MCP) servers: it snapshots a server's tool surface into a
// lockfile so CI fails when tools, descriptions, or input schemas silently
// change, and it fuzzes each tool with inputs generated from that tool's own
// JSON Schema — valid, boundary, and hostile — to find handlers that panic,
// hang, or accept what their schema forbids.
//
// Schemas are handled as decoded JSON (`map[string]any`) rather than a typed
// model, so mcpvet works against any server's schema, not only the drafts a
// particular SDK understands.
package mcpvet

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// schema is a read-only view over a decoded JSON Schema object.
type schema struct{ m map[string]any }

func asSchema(v any) (schema, bool) {
	m, ok := v.(map[string]any)
	return schema{m}, ok
}

func (s schema) str(key string) (string, bool) {
	v, ok := s.m[key].(string)
	return v, ok
}

func (s schema) num(key string) (float64, bool) {
	switch v := s.m[key].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	}
	return 0, false
}

func (s schema) typ() string {
	if t, ok := s.str("type"); ok {
		return t
	}
	// A schema with "properties" but no explicit type is an object.
	if _, ok := s.m["properties"]; ok {
		return "object"
	}
	if _, ok := s.m["enum"]; ok {
		return "enum"
	}
	return ""
}

func (s schema) properties() map[string]schema {
	out := map[string]schema{}
	props, ok := s.m["properties"].(map[string]any)
	if !ok {
		return out
	}
	for name, raw := range props {
		if sub, ok := asSchema(raw); ok {
			out[name] = sub
		}
	}
	return out
}

func (s schema) required() []string {
	raw, ok := s.m["required"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	sort.Strings(out)
	return out
}

func (s schema) enum() []any {
	raw, ok := s.m["enum"].([]any)
	if !ok {
		return nil
	}
	return raw
}

// Fingerprint is a stable, human-diffable summary of a schema: sorted keys,
// types, bounds, required flags. Two schemas that would accept the same
// inputs produce the same fingerprint, so map ordering never causes false
// drift.
func (s schema) fingerprint() string {
	var b strings.Builder
	s.writeFingerprint(&b)
	return b.String()
}

func (s schema) writeFingerprint(b *strings.Builder) {
	t := s.typ()
	b.WriteString(t)
	if en := s.enum(); en != nil {
		vals := make([]string, len(en))
		for i, v := range en {
			vals[i] = fmt.Sprint(v)
		}
		sort.Strings(vals)
		fmt.Fprintf(b, "{enum:%s}", strings.Join(vals, ","))
	}
	for _, key := range []string{"minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems", "pattern", "format"} {
		if v, ok := s.m[key]; ok {
			fmt.Fprintf(b, "[%s=%v]", key, v)
		}
	}
	switch t {
	case "object":
		req := map[string]bool{}
		for _, r := range s.required() {
			req[r] = true
		}
		props := s.properties()
		names := make([]string, 0, len(props))
		for n := range props {
			names = append(names, n)
		}
		sort.Strings(names)
		b.WriteByte('{')
		for _, n := range names {
			b.WriteString(n)
			if req[n] {
				b.WriteByte('!')
			}
			b.WriteByte(':')
			props[n].writeFingerprint(b)
			b.WriteByte(';')
		}
		b.WriteByte('}')
	case "array":
		if items, ok := asSchema(s.m["items"]); ok {
			b.WriteString("[]")
			items.writeFingerprint(b)
		}
	}
}

func (s schema) numberBounds() (min, max float64, hasMin, hasMax bool) {
	min, hasMin = s.num("minimum")
	max, hasMax = s.num("maximum")
	if !hasMin {
		min = -1e6
	}
	if !hasMax {
		max = 1e6
	}
	return
}

func clampInt(f float64) int {
	if math.IsNaN(f) {
		return 0
	}
	return int(f)
}
