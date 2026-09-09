package mcpvet

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Regression tests for the defects found in the August 2026 audit. Each one
// fails against the code as it stood before the corresponding fix.

// A server that paginates its tool list used to be read one page deep, hiding
// every later tool from the lock, the drift gate and the fuzzer.
func TestListToolsFollowsPagination(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_MANY_TOOLS", "40")

	report, err := Vet(context.Background(), Options{Command: bin, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if report.ToolCount != 43 { // 3 base tools + 40 extra
		t.Fatalf("tool count = %d, want 43 — pagination is being truncated", report.ToolCount)
	}
}

// An unknown-to-mcpvet keyword that changes the accepted input set used to be
// dropped from the fingerprint, so real drift passed the CI gate classified as
// a docs-only change.
func TestFingerprintCoversUnknownKeywords(t *testing.T) {
	cases := []struct{ name, a, b string }{
		{"uniqueItems", `{"type":"array","items":{"type":"string"}}`, `{"type":"array","items":{"type":"string"},"uniqueItems":true}`},
		{"additionalProps", `{"type":"object","properties":{"x":{"type":"string"}}}`, `{"type":"object","properties":{"x":{"type":"string"}},"additionalProperties":false}`},
		{"const", `{"type":"string"}`, `{"type":"string","const":"only-this"}`},
		{"oneOf", `{"type":"object","properties":{"x":{"type":"string"}}}`, `{"type":"object","properties":{"x":{"type":"string"}},"oneOf":[{"required":["x"]}]}`},
		{"patternProps", `{"type":"object"}`, `{"type":"object","patternProperties":{"^s_":{"type":"string"}}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sa, _ := asSchema(mustSchema(t, c.a))
			sb, _ := asSchema(mustSchema(t, c.b))
			if sa.fingerprint() == sb.fingerprint() {
				t.Fatalf("%s does not affect the fingerprint: %s", c.name, sa.fingerprint())
			}
		})
	}
}

// Documentation edits must still never cause drift, including inside
// subschemas the exhaustive walk now visits.
func TestFingerprintStillIgnoresNestedDocs(t *testing.T) {
	a := `{"type":"object","properties":{"x":{"type":"array","items":{"type":"string","description":"before","title":"T"}}}}`
	b := `{"type":"object","properties":{"x":{"type":"array","items":{"type":"string","description":"after"}}}}`
	sa, _ := asSchema(mustSchema(t, a))
	sb, _ := asSchema(mustSchema(t, b))
	if sa.fingerprint() != sb.fingerprint() {
		t.Fatalf("documentation edit caused drift:\n%s\n%s", sa.fingerprint(), sb.fingerprint())
	}
}

// A hostile schema (negative or absurd bounds) used to panic the process
// inside clampInt.
func TestGeneratorSurvivesHostileBounds(t *testing.T) {
	hostile := []string{
		`{"type":"object","properties":{"a":{"type":"string","minLength":-5}}}`,
		`{"type":"object","properties":{"a":{"type":"string","maxLength":-1}}}`,
		`{"type":"object","properties":{"a":{"type":"string","maxLength":1e300}}}`,
		`{"type":"object","properties":{"a":{"type":"array","items":{"type":"string"},"minItems":-3}}}`,
		`{"type":"object","properties":{"a":{"type":"integer","minimum":5,"maximum":1}}}`,
	}
	for _, h := range hostile {
		cases := GenerateCases(mustSchema(t, h)) // must not panic
		if len(cases) == 0 {
			t.Fatalf("no cases for %s", h)
		}
		for _, c := range cases {
			for _, v := range c.Args {
				if s, ok := v.(string); ok && len(s) > 1<<20 {
					t.Fatalf("generated a %d-byte string from %s", len(s), h)
				}
			}
		}
	}
}

// An injection payload that violates the field's own maxLength used to be
// marked valid, so schema validation bounced it and mcpvet reported a false
// finding instead of exercising the handler.
func TestPayloadsFitTheirConstraints(t *testing.T) {
	s := mustSchema(t, `{"type":"object","properties":{"note":{"type":"string","maxLength":20}},"required":["note"]}`)
	for _, c := range GenerateCases(s) {
		if !strings.HasPrefix(c.Name, "payload:") {
			continue
		}
		v, _ := c.Args["note"].(string)
		if len([]rune(v)) > 20 {
			t.Fatalf("%s produced a %d-rune value for a maxLength:20 field", c.Name, len([]rune(v)))
		}
		if c.Expect == ExpectAccept {
			t.Fatalf("%s asserts the server must accept hostile data", c.Name)
		}
	}
}

// A value mcpvet cannot prove the schema accepts must never be asserted as
// acceptable — that is what produced false findings.
func TestUnsatisfiableFieldRelaxesExpectation(t *testing.T) {
	pattern := `^[A-Z]{3}-[0-9]{9}$`
	s := mustSchema(t, `{"type":"object","properties":{"code":{"type":"string","pattern":"`+pattern+`"}},"required":["code"]}`)
	re := regexp.MustCompile(pattern)
	for _, c := range GenerateCases(s) {
		if c.Name == "valid" && c.Expect == ExpectAccept {
			v, _ := c.Args["code"].(string)
			if !re.MatchString(v) {
				t.Fatalf("case %q asserts acceptance of %q, which the pattern rejects", c.Name, v)
			}
		}
	}
}

// A tool that returns IsError for input its own schema accepts used to be
// reported as clean, because runCase only ever inspected invalid cases.
func TestRejectedValidIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_ALWAYS_ERROR", "1")

	report, err := Vet(context.Background(), Options{Command: bin, Fuzz: true, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		if f.Kind == "rejected_valid" {
			return
		}
	}
	t.Fatalf("a tool that errors on every input was reported clean; findings: %+v", report.Findings)
}

// allOf inside a oneOf/anyOf branch, or next to one at the root, used to be
// discarded: branches() merged the branch into the root before folding allOf,
// and the merge drops composition keywords. The branch then generated an
// empty "valid" case that asserted acceptance, so a server that correctly
// rejected the missing required field was reported as a false finding.
func TestBranchesKeepAllOf(t *testing.T) {
	find := func(cases []Case, name string) (Case, bool) {
		for _, c := range cases {
			if c.Name == name {
				return c, true
			}
		}
		return Case{}, false
	}

	t.Run("allOf inside each branch", func(t *testing.T) {
		s := mustSchema(t, `{"type":"object","oneOf":[
			{"allOf":[{"properties":{"a":{"type":"string"}},"required":["a"]}]},
			{"allOf":[{"properties":{"b":{"type":"integer"}},"required":["b"]}]}]}`)
		cases := GenerateCases(s)
		for i, field := range []string{"a", "b"} {
			valid, ok := find(cases, fmt.Sprintf("branch%d:valid", i))
			if !ok {
				t.Fatalf("no valid case for branch %d: %v", i, names(cases))
			}
			if _, ok := valid.Args[field]; !ok {
				t.Errorf("branch %d valid case lacks %q: %v", i, field, valid.Args)
			}
			if _, ok := find(cases, fmt.Sprintf("branch%d:missing:%s", i, field)); !ok {
				t.Errorf("branch %d has no missing:%s case — its allOf was dropped: %v", i, field, names(cases))
			}
		}
	})

	t.Run("allOf next to oneOf at the root", func(t *testing.T) {
		s := mustSchema(t, `{"type":"object",
			"allOf":[{"properties":{"id":{"type":"string"}},"required":["id"]}],
			"oneOf":[{"properties":{"a":{"type":"string"}},"required":["a"]}]}`)
		cases := GenerateCases(s)
		valid, ok := find(cases, "branch0:valid")
		if !ok {
			t.Fatalf("no branch0:valid: %v", names(cases))
		}
		for _, field := range []string{"id", "a"} {
			if _, ok := valid.Args[field]; !ok {
				t.Errorf("valid case lacks %q: %v", field, valid.Args)
			}
		}
		if _, ok := find(cases, "branch0:missing:id"); !ok {
			t.Errorf("root allOf's required field is not probed: %v", names(cases))
		}
	})
}

func names(cases []Case) []string {
	out := make([]string, len(cases))
	for i, c := range cases {
		out[i] = c.Name
	}
	return out
}
