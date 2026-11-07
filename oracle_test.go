package mcpvet

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
)

// oracleSchemas are tool input schemas in the shapes real servers emit. The
// generator's cases are graded inside GenerateCases by this same validator, so
// TestOracleExpectations proves that gate is wired, not that the validator is
// right; the pins below it hold the generator to the values it must produce.
var oracleSchemas = map[string]string{
	"plain":             `{"type":"object","properties":{"city":{"type":"string"},"n":{"type":"integer","minimum":1,"maximum":10}},"required":["city"]}`,
	"pydantic_opt_int":  `{"type":"object","properties":{"limit":{"anyOf":[{"type":"integer"},{"type":"null"}],"default":null}}}`,
	"pydantic_opt_str":  `{"type":"object","properties":{"q":{"anyOf":[{"type":"string"},{"type":"null"}],"default":null}},"required":["q"]}`,
	"pydantic_opt_ref":  `{"$defs":{"Mode":{"type":"string","enum":["a","b"]}},"type":"object","properties":{"m":{"anyOf":[{"$ref":"#/$defs/Mode"},{"type":"null"}]}}}`,
	"prop_oneof":        `{"type":"object","properties":{"v":{"oneOf":[{"type":"integer"},{"type":"boolean"}]}}}`,
	"prop_allof":        `{"type":"object","properties":{"v":{"allOf":[{"type":"integer"},{"minimum":5}]}}}`,
	"nullable_union":    `{"type":"object","properties":{"v":{"type":["integer","null"],"minimum":3}}}`,
	"root_oneof_req":    `{"type":"object","properties":{"path":{"type":"string"},"url":{"type":"string"}},"oneOf":[{"required":["path"]},{"required":["url"]}]}`,
	"root_anyof_req":    `{"type":"object","properties":{"path":{"type":"string"},"url":{"type":"string"}},"anyOf":[{"required":["path"]},{"required":["url"]}]}`,
	"root_oneof_tagged": `{"oneOf":[{"type":"object","properties":{"kind":{"const":"a"},"x":{"type":"integer"}},"required":["kind","x"]},{"type":"object","properties":{"kind":{"const":"b"},"y":{"type":"string"}},"required":["kind","y"]}]}`,
	"nested_required":   `{"type":"object","properties":{"o":{"type":"object","required":["k"]}}}`,
	"nested_closed":     `{"type":"object","properties":{"o":{"type":"object","properties":{"a":{"type":"string"}},"additionalProperties":false,"required":["a"]}}}`,
	"array_of_opt":      `{"type":"object","properties":{"l":{"type":"array","items":{"anyOf":[{"type":"integer"},{"type":"null"}]},"minItems":1}}}`,
	"not":               `{"type":"object","properties":{"s":{"type":"string","not":{"const":"mcpvet"}}}}`,
	"dependent":         `{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"},"c":{"type":"string"}},"dependentRequired":{"a":["z"]}}`,
	"if_then":           `{"type":"object","properties":{"a":{"type":"string"}},"if":{"required":["a"]},"then":{"required":["q"]}}`,
	"min_props":         `{"type":"object","minProperties":2,"properties":{"a":{"type":"string"}}}`,
	"max_props":         `{"type":"object","maxProperties":1,"properties":{"a":{"type":"string"},"b":{"type":"string"}}}`,
	"closed_required":   `{"type":"object","additionalProperties":{"type":"integer"},"required":["z"]}`,
	"tuple":             `{"type":"object","properties":{"t":{"type":"array","prefixItems":[{"type":"integer"},{"type":"boolean"}],"minItems":2}}}`,
	"contains":          `{"type":"object","properties":{"l":{"type":"array","contains":{"type":"integer"}}}}`,
	"unique":            `{"type":"object","properties":{"l":{"type":"array","uniqueItems":true,"minItems":2,"items":{"type":"integer"}}}}`,
	"enum_int":          `{"type":"object","properties":{"e":{"type":"integer","enum":[1,2]}},"required":["e"]}`,
	"enum_untyped_str":  `{"type":"object","properties":{"e":{"enum":["x",1,null]}}}`,
	"const_prop":        `{"type":"object","properties":{"c":{"const":3}},"required":["c"]}`,
	"int_fraction_lo":   `{"type":"object","properties":{"n":{"type":"integer","minimum":-0.5,"maximum":0.5}}}`,
	"exclusive":         `{"type":"object","properties":{"n":{"type":"number","exclusiveMinimum":0,"exclusiveMaximum":1}}}`,
	"multiple":          `{"type":"object","properties":{"n":{"type":"integer","multipleOf":7,"minimum":1}}}`,
	"pattern_miss":      `{"type":"object","properties":{"s":{"type":"string","pattern":"^[0-9]+$"}}}`,
	"pattern_maxlen":    `{"type":"object","properties":{"s":{"type":"string","maxLength":3}}}`,
	"pattern_props":     `{"type":"object","patternProperties":{"^x":{"type":"integer"}},"properties":{"xa":{"type":"string"}}}`,
	"property_names":    `{"type":"object","propertyNames":{"pattern":"^z"},"properties":{"a":{"type":"string"}}}`,
	"ref_allof":         `{"$defs":{"B":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}},"allOf":[{"$ref":"#/$defs/B"},{"properties":{"n":{"type":"integer"}}}],"type":"object"}`,
	"root_oneof_shared": `{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"],"oneOf":[{"properties":{"a":{"type":"string"}},"required":["a"]},{"properties":{"b":{"type":"string"}},"required":["b"]}]}`,
}

func TestOracleExpectations(t *testing.T) {
	names := make([]string, 0, len(oracleSchemas))
	for n := range oracleSchemas {
		names = append(names, n)
	}
	sort.Strings(names)
	total, asserted := 0, 0
	for _, name := range names {
		raw := oracleSchemas[name]
		var js jsonschema.Schema
		if err := json.Unmarshal([]byte(raw), &js); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rs, err := js.Resolve(nil)
		if err != nil {
			t.Fatalf("%s: resolve: %v", name, err)
		}
		var input any
		json.Unmarshal([]byte(raw), &input)
		for _, c := range GenerateCases(input) {
			total++
			if c.Expect == ExpectEither {
				continue
			}
			asserted++
			b, _ := json.Marshal(c.Args)
			var inst any
			json.Unmarshal(b, &inst)
			verr := rs.Validate(inst)
			switch {
			case c.Expect == ExpectAccept && verr != nil:
				t.Errorf("%s/%s: mcpvet demands accept, schema rejects %s: %v", name, c.Name, b, verr)
			case c.Expect == ExpectReject && verr == nil:
				t.Errorf("%s/%s: mcpvet demands reject, schema accepts %s", name, c.Name, b)
			}
		}
	}
	t.Logf("%d schemas, %d cases, %d asserted", len(names), total, asserted)
}

// The commonest optional parameter in Python MCP servers. The generator used to
// see no "type" and offer a string, so a correct server failed with
// rejected_valid. The gate alone would hide that by relaxing the case: the pin
// is that the case is still asserted, with a value of the right type.
func TestOptionalKeepsItsAssertion(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		want        any
	}{
		{"pydantic_opt_int", "limit", 1},
		{"pydantic_opt_str", "q", "mcpvet"},
		{"pydantic_opt_ref", "m", "a"},
		{"prop_oneof", "v", 1},
		{"prop_allof", "v", 5},
	} {
		var input any
		if err := json.Unmarshal([]byte(oracleSchemas[tc.name]), &input); err != nil {
			t.Fatal(err)
		}
		valid, ok := caseNamed(GenerateCases(input), "valid")
		if !ok {
			t.Fatalf("%s: no valid case", tc.name)
		}
		if valid.Expect != ExpectAccept {
			t.Errorf("%s: valid case relaxed to %v, args %v", tc.name, valid.Expect, valid.Args)
		}
		if got := valid.Args[tc.field]; got != tc.want {
			t.Errorf("%s: %s = %#v, want %#v", tc.name, tc.field, got, tc.want)
		}
	}
}

// Filling in both alternatives of an exclusive pair breaks the schema, so the
// carrier must drop to required fields rather than give the assertion up.
func TestExclusiveFieldsKeepAValidCase(t *testing.T) {
	var input any
	if err := json.Unmarshal([]byte(oracleSchemas["root_oneof_req"]), &input); err != nil {
		t.Fatal(err)
	}
	cases := GenerateCases(input)
	for name, want := range map[string]string{"branch0:valid": "path", "branch1:valid": "url"} {
		c, ok := caseNamed(cases, name)
		if !ok {
			t.Fatalf("no %s", name)
		}
		if _, has := c.Args[want]; !has || len(c.Args) != 1 || c.Expect != ExpectAccept {
			t.Errorf("%s: args %v, expect %v", name, c.Args, c.Expect)
		}
	}
	for _, name := range []string{"branch0:missing:path", "branch1:missing:url"} {
		if c, ok := caseNamed(cases, name); !ok || c.Expect != ExpectReject {
			t.Errorf("%s: %+v, want a reject of the empty object", name, c)
		}
	}
}

// jsonschema-go v0.4.3 overflows the stack on a $ref cycle (fatal, no recover)
// and takes 2^n steps on a chain of branching refs. A server under audit can
// send either, so the gate must never hand them over. A regression here kills
// or hangs the test binary rather than failing an assertion.
func TestHostileRefsNeverReachTheValidator(t *testing.T) {
	fan := `{"$defs":{`
	for i := 0; i < 40; i++ {
		fan += fmt.Sprintf(`"d%d":{"anyOf":[{"$ref":"#/$defs/d%d"},{"$ref":"#/$defs/d%d"}]},`, i, i+1, i+1)
	}
	fan += `"d40":{"type":"string"}},"type":"object","properties":{"a":{"$ref":"#/$defs/d0"}}}`
	for name, raw := range map[string]string{
		"self":   `{"$defs":{"A":{"$ref":"#/$defs/A"}},"type":"object","properties":{"a":{"$ref":"#/$defs/A"}}}`,
		"root":   `{"type":"object","allOf":[{"$ref":"#"}]}`,
		"mutual": `{"$defs":{"A":{"$ref":"#/$defs/B"},"B":{"anyOf":[{"$ref":"#/$defs/A"}]}},"type":"object","properties":{"a":{"$ref":"#/$defs/A"}}}`,
		"anchor": `{"$defs":{"A":{"$anchor":"a","$dynamicRef":"#a"}},"type":"object","properties":{"a":{"$dynamicRef":"#a"}}}`,
		"fan":    fan,
	} {
		var input any
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatal(err)
		}
		if len(GenerateCases(input)) == 0 {
			t.Errorf("%s: no cases", name)
		}
	}
}
