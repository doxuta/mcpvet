package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression test for a gap found by running mcpvet against real servers.
//
// @modelcontextprotocol/server-filesystem 2025.8.21 advertised 13 of its 14
// tools with the input schema {"$schema": "http://json-schema.org/draft-07/schema#"}
// and nothing else: no "type", no "properties". An agent reading that tool list
// sees no parameters at all, and the schema accepts any input. MCP requires an
// input schema of type "object", and the Go SDK refuses to register anything
// else. mcpvet locked it, `check` printed OK, and `fuzz` sent one empty-args
// probe that asserts nothing and also printed OK. CoverageGap, written to turn
// that probe into a visible warning, was never called.
func TestUntypedInputSchemaIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_UNTYPED_SCHEMA_TOOL", "1")

	for _, fuzz := range []bool{false, true} {
		report, err := Vet(context.Background(), Options{
			Command: bin, Fuzz: fuzz, Timeout: 3 * time.Second,
			SkipTools: []string{"greet", "lookup_city", "slow"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var found []Finding
		for _, f := range report.Findings {
			if f.Tool == "untyped" && f.Kind == "schema_not_object" {
				found = append(found, f)
			}
			if f.Tool != "untyped" {
				t.Errorf("fuzz=%v: finding against a well-formed tool: %s %s", fuzz, f.Tool, f.Kind)
			}
		}
		if len(found) != 1 {
			t.Fatalf("fuzz=%v: want exactly one schema_not_object finding for the untyped tool, got %+v", fuzz, report.Findings)
		}
		if !report.Failed() {
			t.Errorf("fuzz=%v: a tool with no usable input schema passed the gate", fuzz)
		}
	}
}

// A schema that resolves to an object only through oneOf branches or a local
// $ref is well-formed and must not be flagged.
func TestObjectSchemasAreNotFlagged(t *testing.T) {
	for _, s := range []string{
		`{"type":"object"}`,
		`{"properties":{"a":{"type":"string"}}}`,
		`{"oneOf":[{"type":"object","properties":{"a":{"type":"string"}}},{"type":"object","properties":{"b":{"type":"integer"}}}]}`,
		`{"$ref":"#/$defs/A","$defs":{"A":{"type":"object","properties":{"a":{"type":"string"}}}}}`,
	} {
		if gap := CoverageGap(GenerateCases(mustSchema(t, s))); gap != "" {
			t.Errorf("%s flagged: %s", s, gap)
		}
	}
	for _, s := range []string{
		`{"$schema":"http://json-schema.org/draft-07/schema#"}`,
		`{}`,
		`{"type":"string"}`,
	} {
		if CoverageGap(GenerateCases(mustSchema(t, s))) == "" {
			t.Errorf("%s not flagged", s)
		}
	}
}

// The drift report printed the old shape of such a schema as an empty string,
// so "was:" was followed by nothing and the reader could not tell a missing
// schema from a rendering bug.
func TestDriftNamesAnEmptyShape(t *testing.T) {
	old := Lock{Tools: []ToolLock{{Name: "read_file", SchemaHash: "a", SchemaShape: ""}}}
	cur := Lock{Tools: []ToolLock{{Name: "read_file", SchemaHash: "b", SchemaShape: "object{path!:string;}"}}}
	drifts := Diff(old, cur)
	if len(drifts) == 0 {
		t.Fatal("no drift reported")
	}
	if d := drifts[0].Detail; !strings.Contains(d, "was: (no type: accepts any input)") {
		t.Errorf("empty old shape is not named:\n%s", d)
	}
}

// Second gap from the same run. @modelcontextprotocol/server-everything's
// simulate-research-query declares execution.taskSupport "required": a client
// must call it as an MCP task (spec 2025-11-25), and a plain call gets a tool
// error. The Go SDK's Tool type has no field for it, so mcpvet never saw it,
// fuzzed the tool with plain calls, and reported a false rejected_valid that
// failed `fuzz` against the reference server.
func TestTaskRequiredToolIsNotFuzzed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_TASK_REQUIRED_TOOL", "1")

	report, err := Vet(context.Background(), Options{
		Command: bin, Fuzz: true, Timeout: 3 * time.Second,
		SkipTools: []string{"lookup_city", "slow"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range report.Findings {
		t.Errorf("false finding: %s %s %s (case %s)", f.Tool, f.Kind, f.Detail, f.Case)
	}
	if len(report.TaskOnly) != 1 || report.TaskOnly[0] != "research" {
		t.Errorf("task-only tools = %v, want [research]", report.TaskOnly)
	}
	var locked string
	for _, tl := range report.Lock.Tools {
		if tl.Name == "research" {
			locked = tl.TaskSupport
		}
		if tl.Name == "greet" && tl.TaskSupport != "" {
			t.Errorf("greet locked with task support %q, want none", tl.TaskSupport)
		}
	}
	if locked != "required" {
		t.Errorf("research locked with task support %q, want required", locked)
	}
}

// A tool that starts requiring tasks can no longer be called by a client that
// does not speak them, so the change is breaking drift. A lockfile written
// before the field existed records nothing, which means "forbidden" — the
// spec's default — and must not drift against a server that says forbidden.
func TestTaskSupportDrift(t *testing.T) {
	old := Lock{Tools: []ToolLock{{Name: "research"}, {Name: "echo"}}}
	cur := Lock{Tools: []ToolLock{{Name: "research", TaskSupport: "required"}, {Name: "echo"}}}
	drifts := Diff(old, cur)
	if len(drifts) != 1 || drifts[0].Tool != "research" || drifts[0].Kind != "task_support_changed" || !drifts[0].Breaking() {
		t.Fatalf("drifts = %+v, want one breaking task_support_changed for research", drifts)
	}
	if !strings.Contains(drifts[0].Detail, `"forbidden" → "required"`) {
		t.Errorf("detail does not name both values: %s", drifts[0].Detail)
	}
}
