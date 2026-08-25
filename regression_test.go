package mcpvet

import (
	"context"
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
