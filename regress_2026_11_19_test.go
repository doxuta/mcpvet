package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression test for input-schema roots that generate test cases, so
// schema_not_object stayed silent, yet break the tool for agents.
//
// root_combinator: the Anthropic Messages API refuses a tool input_schema with
// anyOf, oneOf or allOf at the top level ("input_schema does not support
// oneOf, allOf, or anyOf at the top level", 400), whether or not the root also
// says "type": "object", and the tool list goes out on every request, so one
// such tool fails every turn. vestige 6.2.0 added root allOf blocks of if/then
// to three tools of an otherwise working MCP server and broke it for every
// client that forwards schemas verbatim (samvallad33/vestige#846, 2026-11-18;
// the same 400 in aaif-goose/goose#12773 and anomalyco/opencode#47543).
// Claude Code 2.1.328 fixed such tools going missing on third-party providers.
//
// root_not_object: MCP requires inputSchema to be {"type": "object", ...}
// (schema.ts 2026-07-28, Tool.inputSchema); a bare "properties" or a $ref root
// still describes an object, so nothing reported it.
func TestInputSchemaRootAgentsTripOnIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	obj := func(field, typ string) string {
		return `{"type":"object","properties":{"` + field + `":{"type":"` + typ + `"}},"required":["` + field + `"]}`
	}

	cases := []struct {
		name, schema, kind string
		untyped            bool // the detail must also name the missing "type": "object"
	}{
		// The wire form of vestige 6.2.2's curate tool, reduced (vestige#846).
		{"vestige typed root allOf", `{"type":"object","properties":{"action":{"type":"string"},"params":{"type":"object"}},` +
			`"required":["action"],"allOf":[{"if":{"type":"object"},"then":{"type":"object"}}]}`, "root_combinator", false},
		// "Exactly one of these fields" (opencode#47543).
		{"typed root anyOf of required", `{"type":"object","properties":{"route":{"type":"string"},"file":{"type":"string"}},` +
			`"anyOf":[{"required":["route"]},{"required":["file"]}]}`, "root_combinator", false},
		{"typed root oneOf", `{"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"}},` +
			`"oneOf":[{"required":["id"]},{"required":["name"]}]}`, "root_combinator", false},
		// A union type at the root of a zod or pydantic model.
		{"bare anyOf", `{"anyOf":[` + obj("id", "string") + `,` + obj("name", "string") + `]}`, "root_combinator", true},
		{"bare allOf", `{"allOf":[` + obj("id", "string") + `]}`, "root_combinator", true},
		{"bare properties", `{"properties":{"id":{"type":"string"}},"required":["id"]}`, "root_not_object", false},
		{"$ref root", `{"$ref":"#/$defs/Q","$defs":{"Q":` + obj("id", "string") + `}}`, "root_not_object", false},
	}
	clean := map[string]string{
		"plain object": obj("id", "string"),
		// pydantic's Optional[int]: a combinator below the root is accepted.
		"nested anyOf": `{"type":"object","properties":{"n":{"anyOf":[{"type":"integer"},{"type":"null"}]}}}`,
		"anyOf in $defs": `{"type":"object","properties":{"q":{"$ref":"#/$defs/Q"}},` +
			`"$defs":{"Q":{"anyOf":[{"type":"string"},{"type":"integer"}]}}}`,
	}

	run := func(t *testing.T, schema string, fuzz bool) (found, other []Finding) {
		t.Setenv("MCPVET_ROOT_SCHEMA", schema)
		report, err := Vet(context.Background(), Options{
			Command: bin, Fuzz: fuzz, Timeout: 3 * time.Second,
			SkipTools: []string{"greet", "lookup_city", "slow"},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range report.Findings {
			if f.Kind == "root_combinator" || f.Kind == "root_not_object" {
				found = append(found, f)
			} else {
				other = append(other, f)
			}
		}
		return found, other
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found, other := run(t, c.schema, false)
			if len(other) != 0 {
				t.Errorf("lock found more than the root: %+v", other)
			}
			if len(found) != 1 || found[0].Tool != "rooted" || found[0].Kind != c.kind || !found[0].Breaking {
				t.Fatalf("want one breaking %s finding on rooted, got %+v", c.kind, found)
			}
			d := found[0].Detail
			if c.kind == "root_combinator" && !strings.Contains(d, "Anthropic Messages API") {
				t.Errorf("detail does not name the API that refuses it: %s", d)
			}
			if got := strings.Contains(d, `"type": "object", which MCP requires`); got != (c.untyped || c.kind == "root_not_object") {
				t.Errorf("MCP type rule named=%v: %s", got, d)
			}
		})
	}
	for name, s := range clean {
		t.Run(name, func(t *testing.T) {
			if found, other := run(t, s, false); len(found)+len(other) != 0 {
				t.Fatalf("flagged a well-formed root: %+v %+v", found, other)
			}
		})
	}
	// Fuzzing still runs on such a root and the finding is not repeated per case.
	t.Run("fuzz", func(t *testing.T) {
		if found, _ := run(t, cases[0].schema, true); len(found) != 1 {
			t.Fatalf("fuzz: want one root finding, got %+v", found)
		}
	})
	// A schema nothing can be generated from stays schema_not_object alone.
	for _, s := range []string{
		`{"$schema":"http://json-schema.org/draft-07/schema#"}`,
		`{"type":["object","null"],"properties":{"id":{"type":"string"}}}`,
	} {
		t.Run("no double report "+s, func(t *testing.T) {
			found, other := run(t, s, false)
			if len(found) != 0 || len(other) != 1 || other[0].Kind != "schema_not_object" {
				t.Fatalf("want schema_not_object alone, got %+v %+v", found, other)
			}
		})
	}
}
