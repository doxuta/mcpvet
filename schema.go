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
	"encoding/json"
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

func (s schema) boolean(key string) bool {
	v, _ := s.m[key].(bool)
	return v
}

// types returns every JSON type the schema declares. A string "type" yields
// one entry; an array-valued "type" (a union, e.g. ["string","null"]) yields
// all of them, sorted so member order never causes false drift.
func (s schema) types() []string {
	switch t := s.m["type"].(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, v := range t {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// typ is the single type to dispatch generation on. A union declares no single
// type, so it returns "" — callers that need the members use types().
func (s schema) typ() string {
	if ts := s.types(); len(ts) > 0 {
		if len(ts) > 1 {
			return ""
		}
		return ts[0]
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

// typeLabel is how a schema's type is rendered in a fingerprint: the union
// members when it declares several, otherwise the single type. A type that was
// inferred rather than declared is marked with a leading "~". The distinction
// is load-bearing: {"type":"object","properties":...} rejects a string, while
// the same schema without "type" accepts it, so the two must not share a
// fingerprint.
func (s schema) typeLabel() string {
	if ts := s.types(); len(ts) > 1 {
		return strings.Join(ts, "|")
	}
	t := s.typ()
	// "enum" is a sentinel typ() invents, never a declared JSON type, so it
	// already reads as inferred and needs no marker.
	if _, declared := s.m["type"]; !declared && t != "" && t != "enum" {
		return "~" + t
	}
	return t
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

// annotationKeys are the keywords that carry documentation only: they never
// change which inputs a schema accepts, so they must not cause drift.
// EVERY other key — known or unknown — widens the fingerprint.
var annotationKeys = map[string]bool{
	"title": true, "description": true, "$comment": true,
	"examples": true, "default": true, "deprecated": true,
	"readOnly": true, "writeOnly": true,
	"$schema": true, "$id": true,
}

// namedSchemaKeys map a caller-chosen name to a subschema. Their keys are
// names, not keywords, so annotation filtering must not be applied to them.
var namedSchemaKeys = map[string]bool{
	"properties": true, "patternProperties": true,
	"$defs": true, "definitions": true, "dependentSchemas": true,
}

// unorderedSchemaKeys hold a set of subschemas whose order is not semantic
// (unlike prefixItems and tuple-form items, where position matters).
var unorderedSchemaKeys = map[string]bool{"oneOf": true, "anyOf": true, "allOf": true}

// maxSchemaDepth bounds recursion over an untrusted schema.
const maxSchemaDepth = 64

// Fingerprint is a stable, human-diffable summary of a schema: sorted keys,
// types, bounds, required flags, and every other non-annotation keyword the
// schema carries, including ones mcpvet does not otherwise understand.
//
// The invariant that matters for the CI gate is the strict one: two schemas
// with the same fingerprint accept the same inputs. An unknown or unhandled
// keyword therefore widens the fingerprint rather than being dropped —
// dropping it would let a real widening be reported as a docs-only change.
// For the same reason values keep their JSON type (the number 1 and the string
// "1" render differently) and an inferred type is marked "~object" rather than
// rendering like a declared one. Key order and description edits still never
// cause drift.
func (s schema) fingerprint() string {
	var b strings.Builder
	s.writeFingerprint(&b, 0)
	return b.String()
}

func (s schema) writeFingerprint(b *strings.Builder, depth int) {
	if depth > maxSchemaDepth {
		b.WriteString("...")
		return
	}
	t := s.typ()
	b.WriteString(s.typeLabel())
	if en := s.enum(); en != nil {
		vals := make([]string, len(en))
		for i, v := range en {
			vals[i] = scalarFingerprint(v)
		}
		sort.Strings(vals)
		fmt.Fprintf(b, "{enum:%s}", strings.Join(vals, ","))
	}

	// Objects and arrays keep their structural rendering, which is what makes
	// a drift diff readable.
	emitted := map[string]bool{"type": true, "enum": true}
	switch t {
	case "object":
		emitted["properties"], emitted["required"] = true, true
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
			props[n].writeFingerprint(b, depth+1)
			b.WriteByte(';')
		}
		b.WriteByte('}')
	case "array":
		if items, ok := asSchema(s.m["items"]); ok {
			emitted["items"] = true
			b.WriteString("[]")
			items.writeFingerprint(b, depth+1)
		}
	}

	// Everything else the schema asserts, in sorted key order.
	for _, k := range sortedKeys(s.m) {
		if emitted[k] || annotationKeys[k] {
			continue
		}
		b.WriteByte('[')
		b.WriteString(k)
		b.WriteByte('=')
		if k == "required" {
			b.WriteString(strings.Join(s.required(), ","))
		} else {
			writeValueFingerprint(b, k, s.m[k], depth+1)
		}
		b.WriteByte(']')
	}
}

func writeValueFingerprint(b *strings.Builder, key string, v any, depth int) {
	if depth > maxSchemaDepth {
		b.WriteString("...")
		return
	}
	switch val := v.(type) {
	case map[string]any:
		if namedSchemaKeys[key] {
			for _, n := range sortedKeys(val) {
				b.WriteString(n)
				b.WriteByte(':')
				writeValueFingerprint(b, "", val[n], depth+1)
				b.WriteByte(';')
			}
			return
		}
		schema{val}.writeFingerprint(b, depth)
	case []any:
		parts := make([]string, len(val))
		for i, e := range val {
			var sub strings.Builder
			writeValueFingerprint(&sub, "", e, depth+1)
			parts[i] = sub.String()
		}
		if unorderedSchemaKeys[key] {
			sort.Strings(parts)
		}
		b.WriteString(strings.Join(parts, ","))
	default:
		b.WriteString(scalarFingerprint(val))
	}
}

// scalarFingerprint renders a JSON scalar keeping its type, so that values of
// different types never collapse to the same token: 1 and "1", true and
// "true", null and the string "null" are distinct inputs and must stay
// distinct here.
//
// The error branch is reachable only through BuildLock with a Go-constructed
// schema, since JSON cannot express NaN or ±Inf. It still renders the value,
// because collapsing NaN, +Inf and -Inf to one token would reintroduce inside
// this function the exact defect it exists to remove.
func scalarFingerprint(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unencodable %T %v>", v, v)
	}
	return string(b)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// numRange is the numeric range a schema accepts, keeping the exclusivity of
// each bound. Absent bounds are never fabricated: callers must check hasLo and
// hasHi.
type numRange struct {
	lo, hi        float64
	hasLo, hasHi  bool
	loExcl, hiExcl bool
	integer       bool
	multipleOf    float64
	hasMultipleOf bool
}

func (s schema) numRange() numRange {
	r := numRange{integer: s.typ() == "integer"}
	if v, ok := s.num("minimum"); ok {
		r.lo, r.hasLo = v, true
	}
	if v, ok := s.num("exclusiveMinimum"); ok && (!r.hasLo || v >= r.lo) {
		r.lo, r.hasLo, r.loExcl = v, true, true
	}
	if v, ok := s.num("maximum"); ok {
		r.hi, r.hasHi = v, true
	}
	if v, ok := s.num("exclusiveMaximum"); ok && (!r.hasHi || v <= r.hi) {
		r.hi, r.hasHi, r.hiExcl = v, true, true
	}
	if v, ok := s.num("multipleOf"); ok && v > 0 {
		r.multipleOf, r.hasMultipleOf = v, true
	}
	return r
}

// contains reports whether v satisfies the range, including multipleOf and
// integrality.
func (r numRange) contains(v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	if r.integer && v != math.Trunc(v) {
		return false
	}
	if r.hasLo && (v < r.lo || (r.loExcl && v == r.lo)) {
		return false
	}
	if r.hasHi && (v > r.hi || (r.hiExcl && v == r.hi)) {
		return false
	}
	if r.hasMultipleOf {
		if _, frac := math.Modf(v / r.multipleOf); frac != 0 {
			return false
		}
	}
	return true
}

// pick returns a value inside the range, or false when the range admits none
// that mcpvet can find.
func (r numRange) pick() (float64, bool) {
	var v float64
	switch {
	case r.hasLo && r.hasHi:
		v = r.lo + (r.hi-r.lo)/2
	case r.hasLo:
		v = r.lo
		if r.loExcl {
			v = r.lo + 1
		}
	case r.hasHi:
		v = r.hi
		if r.hiExcl {
			v = r.hi - 1
		}
	default:
		v = 1
	}
	if r.integer {
		v = math.Round(v)
	}
	if r.contains(v) {
		return v, true
	}
	// Walk outward from the candidate looking for a value that satisfies every
	// constraint: the step is multipleOf when set, else 1 for integers.
	step := 1.0
	if r.hasMultipleOf {
		step = r.multipleOf
		v = math.Round(v/step) * step
		if r.contains(v) {
			return v, true
		}
	} else if !r.integer {
		// A fractional range with no multipleOf: the midpoint is the answer if
		// anything is, except when an exclusive bound landed exactly on it.
		if r.hasLo && r.loExcl && r.lo == v {
			v = math.Nextafter(v, math.Inf(1))
		} else if r.hasHi && r.hiExcl && r.hi == v {
			v = math.Nextafter(v, math.Inf(-1))
		}
		return v, r.contains(v)
	}
	for i := 1; i <= 4096; i++ {
		for _, cand := range [2]float64{v + float64(i)*step, v - float64(i)*step} {
			if r.contains(cand) {
				return cand, true
			}
		}
	}
	return v, false
}

// maxGeneratedLen caps every generated string and array so an absurd bound in
// an untrusted schema cannot exhaust memory.
const maxGeneratedLen = 1 << 16

// clampInt turns a schema-supplied count into a usable, bounded repeat count.
// Schemas come from the server under audit, so a negative or astronomical
// bound must be normalized here rather than reaching strings.Repeat.
func clampInt(f float64) int {
	if math.IsNaN(f) || f <= 0 {
		return 0
	}
	if f > maxGeneratedLen {
		return maxGeneratedLen
	}
	return int(f)
}
