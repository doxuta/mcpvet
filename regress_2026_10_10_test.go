package mcpvet

import (
	"context"
	"testing"
	"time"
)

// Regression test for the sibling of the const defect (regress_2026_10_08).
//
// casesFor built the "valid" case from "properties" alone, so a name listed
// in "required" but absent from "properties" was never included. JSON Schema
// 2020-12 §6.5.3 makes "required" independent of "properties": the instance
// must carry the name regardless. The case still asserted ExpectAccept, so a
// server that validates its own schema rejected it and mcpvet reported a
// false rejected_valid finding that fails `fuzz` against a correct server.
func TestValidCaseIncludesRequiredButUndeclaredProperty(t *testing.T) {
	tests := []struct {
		name, schema string
	}{
		{"declared sibling", `{"type":"object","properties":{"a":{"type":"string"}},"required":["a","b"]}`},
		{"no properties at all", `{"type":"object","required":["b"]}`},
		{"additionalProperties true", `{"type":"object","required":["b"],"additionalProperties":true}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, ok := caseNamed(GenerateCases(mustSchema(t, tc.schema)), "valid")
			if !ok {
				t.Fatal("no valid case generated")
			}
			if valid.Expect != ExpectAccept {
				t.Fatalf("valid case is %v, want accept: the schema is satisfiable", valid.Expect)
			}
			if _, has := valid.Args["b"]; !has {
				t.Errorf("valid case asserts the server must accept %v, but the schema requires b", valid.Args)
			}
		})
	}
}

// Under an additionalProperties schema the undeclared name is still required,
// and its value is bound by that schema, not by a placeholder.
func TestUndeclaredRequiredPropertyHonoursAdditionalPropertiesSchema(t *testing.T) {
	s := mustSchema(t, `{"type":"object","required":["n"],"additionalProperties":{"type":"integer","minimum":5}}`)
	valid, ok := caseNamed(GenerateCases(s), "valid")
	if !ok {
		t.Fatal("no valid case generated")
	}
	if valid.Expect != ExpectAccept {
		t.Fatalf("valid case is %v, want accept: the schema is satisfiable", valid.Expect)
	}
	if n, isInt := valid.Args["n"].(int); !isInt || n < 5 {
		t.Errorf("valid case asserts the server must accept n=%#v, but the schema only accepts integers >= 5", valid.Args["n"])
	}
}

// required + additionalProperties:false with an undeclared name admits no
// instance, so mcpvet has no ground to demand the server accept anything.
func TestUnsatisfiableRequiredDoesNotAssertAccept(t *testing.T) {
	s := mustSchema(t, `{"type":"object","properties":{"a":{"type":"string"}},"required":["a","b"],"additionalProperties":false}`)
	for _, c := range GenerateCases(s) {
		if c.Expect == ExpectAccept {
			t.Errorf("case %s asserts accept against a schema no instance satisfies", c.Name)
		}
	}
}

// The same defect, observed from the outside: a well-behaved server whose
// tool requires a name it does not declare was reported as broken.
func TestUndeclaredRequiredToolProducesNoFalseFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_UNDECLARED_REQUIRED_TOOL", "1")

	report, err := Vet(context.Background(), Options{
		Command: bin, Fuzz: true, Timeout: 3 * time.Second,
		SkipTools: []string{"greet", "lookup_city", "slow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Tool == "tagged" {
			t.Errorf("false finding against a server that merely enforces its required list: %s %s (case %s)", f.Kind, f.Detail, f.Case)
		}
	}
}
