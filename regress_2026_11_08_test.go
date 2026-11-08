package mcpvet

import "testing"

// A property that is only composition declares no type, so wrongType saw "any
// value" and generated no type-confusion case. Optional[int] from pydantic is
// anyOf:[{integer},{null}]: a server that accepted the string "12" for it, or
// coerced it, passed mcpvet with nothing asserted about that field. The union
// of the branches' types is what the property accepts; anything outside it must
// be refused.
func TestWrongTypeOnComposedProperty(t *testing.T) {
	for _, tc := range []struct {
		name, schema, field string
		want                bool // a wrongtype case must exist
		forbidden           []string
	}{
		{"pydantic Optional[int]", `{"type":"object","properties":{"limit":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null}}}`, "limit", true, []string{"integer", "number", "null"}},
		{"pydantic Optional[str]", `{"type":"object","properties":{"q":{"anyOf":[{"type":"string"},{"type":"null"}]}},"required":["q"]}`, "q", true, []string{"string", "null"}},
		{"Optional[enum] via $ref", `{"$defs":{"Mode":{"type":"string","enum":["a","b"]}},"type":"object","properties":{"m":{"anyOf":[{"$ref":"#/$defs/Mode"},{"type":"null"}]}}}`, "m", true, []string{"string", "null"}},
		{"oneOf int|bool", `{"type":"object","properties":{"v":{"oneOf":[{"type":"integer"},{"type":"boolean"}]}}}`, "v", true, []string{"integer", "number", "boolean"}},
		{"allOf only", `{"type":"object","properties":{"v":{"allOf":[{"type":"integer"},{"minimum":5}]}}}`, "v", true, []string{"integer", "number"}},
		{"nested anyOf", `{"type":"object","properties":{"v":{"anyOf":[{"anyOf":[{"type":"string"},{"type":"integer"}]},{"type":"null"}]}}}`, "v", true, []string{"string", "integer", "number", "null"}},
		// An enum member from a branch is accepted whatever its type: 12345 is
		// the first candidate wrongType would try.
		{"enum branch", `{"type":"object","properties":{"v":{"anyOf":[{"enum":[12345]},{"type":"null"}]}}}`, "v", true, []string{"null", "integer"}},
		// A branch that accepts anything leaves no wrong type to send.
		{"untyped branch", `{"type":"object","properties":{"v":{"anyOf":[{"type":"integer"},{"description":"anything"}]}}}`, "v", false, nil},
		// "properties" without "type" accepts a string. The validator used to
		// hide this, but a recursive $defs entry switches it off for the whole
		// tool, and a correct server then got accepted_invalid on field a.
		{"inferred object, recursive $defs", `{"$defs":{"N":{"type":"object","properties":{"next":{"$ref":"#/$defs/N"}}}},"type":"object","properties":{"a":{"properties":{"x":{"type":"string"}}},"k":{"anyOf":[{"type":"integer"},{"type":"null"}]}}}`, "a", false, nil},
		{"branches cover every candidate", `{"type":"object","properties":{"v":{"anyOf":[{"type":"number"},{"type":"string"},{"type":"boolean"},{"type":"array"},{"type":"object"}]}}}`, "v", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cases := GenerateCases(mustSchema(t, tc.schema))
			c, ok := caseNamed(cases, "wrongtype:"+tc.field)
			if ok != tc.want {
				t.Fatalf("wrongtype:%s present = %v, want %v; cases: %v", tc.field, ok, tc.want, names(cases))
			}
			if !ok {
				return
			}
			if c.Expect != ExpectReject {
				t.Errorf("wrongtype:%s expects %v, want reject", tc.field, c.Expect)
			}
			got := jsonTypeOf(c.Args[tc.field])
			for _, f := range tc.forbidden {
				if got == f {
					t.Errorf("wrongtype:%s sent a %s, which the schema accepts", tc.field, got)
				}
			}
		})
	}
}

func jsonTypeOf(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case int:
		return "integer"
	case float64:
		if x == float64(int64(x)) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

// A recursive model (pydantic emits one for any self-referencing class) keeps a
// $ref after inlining, and validValue read the unwalked node as "any value": it
// sent {"next":"mcpvet"} for a field that must be an object and called that
// valid, so a correct server got rejected_valid. Optional[Self] still has a
// value mcpvet can prove: one level inlined, with null where the cycle closes.
func TestRecursiveRefIsNotProvenValid(t *testing.T) {
	direct := GenerateCases(mustSchema(t, `{"$defs":{"N":{"type":"object","properties":{"next":{"$ref":"#/$defs/N"}}}},"type":"object","properties":{"n":{"$ref":"#/$defs/N"}}}`))
	if c, _ := caseNamed(direct, "valid"); c.Expect == ExpectAccept {
		t.Errorf("valid case asserted accept on an unwalked recursive ref: %#v", c.Args)
	}
	optional := GenerateCases(mustSchema(t, `{"$defs":{"N":{"type":"object","properties":{"next":{"anyOf":[{"$ref":"#/$defs/N"},{"type":"null"}]}}}},"type":"object","properties":{"n":{"anyOf":[{"$ref":"#/$defs/N"},{"type":"null"}]}}}`))
	c, _ := caseNamed(optional, "valid")
	n, _ := c.Args["n"].(map[string]any)
	if next, has := n["next"]; c.Expect != ExpectAccept || !has || next != nil {
		t.Errorf("Optional[Self]: valid = %v %#v, want accept with n = {next: null}", c.Expect, c.Args)
	}
}
