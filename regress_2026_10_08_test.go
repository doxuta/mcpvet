package mcpvet

import (
	"context"
	"testing"
	"time"
)

// Regression test for the defect found in the October 2026 audit.
//
// "const" is JSON Schema's one-member enum: per JSON Schema 2020-12 §6.1.3,
// "An instance validates successfully against this keyword if its value is
// equal to the value of the keyword." validValue handled enum but not const,
// so a field such as {"type":"string","const":"circle"} — what pydantic emits
// for Literal["circle"] and zod for a discriminated-union tag — was filled
// with the placeholder "mcpvet" and the case asserted ExpectAccept. A server
// that validates its own schema (the go-sdk's typed AddTool does) rejects it,
// and mcpvet reported a false rejected_valid finding that fails `fuzz`.
func TestValidCaseHonoursConst(t *testing.T) {
	s := mustSchema(t, `{"type":"object","properties":{
		"kind":{"type":"string","const":"circle"},
		"n":{"const":7}
	},"required":["kind","n"]}`)
	valid, ok := caseNamed(GenerateCases(s), "valid")
	if !ok {
		t.Fatal("no valid case generated")
	}
	if valid.Expect != ExpectAccept {
		t.Fatalf("valid case is %v, want accept: const is fully satisfiable", valid.Expect)
	}
	if got := valid.Args["kind"]; got != "circle" {
		t.Errorf(`valid case asserts the server must accept kind=%#v, but the schema only accepts "circle"`, got)
	}
	if got := valid.Args["n"]; got != float64(7) {
		t.Errorf("valid case asserts the server must accept n=%#v, but the schema only accepts 7", got)
	}
}

// The same defect, observed from the outside: a well-behaved server whose
// tool carries a const field was reported as broken.
func TestConstToolProducesNoFalseFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_CONST_TOOL", "1")

	report, err := Vet(context.Background(), Options{
		Command: bin, Fuzz: true, Timeout: 3 * time.Second,
		SkipTools: []string{"greet", "lookup_city", "slow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Tool == "shape" {
			t.Errorf("false finding against a server that merely enforces its const: %s %s (case %s)", f.Kind, f.Detail, f.Case)
		}
	}
}
