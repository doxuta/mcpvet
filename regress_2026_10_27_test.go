package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression test for a schema mcpvet passed as OK. A tool whose outputSchema
// points at a $defs entry it never defines (Google's Stitch MCP server did this
// for upload_design_md) is listed by Claude Code 2.1.305, but every call to it
// fails in the client: "Tool 'upload' has an invalid outputSchema: can't
// resolve reference #/$defs/ScreenInstance from id #", although the server
// answered. mcpvet never looked at outputSchema, so lock, check and fuzz all
// said OK.
func TestDanglingRefIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	for _, where := range []string{"output", "input"} {
		t.Run(where, func(t *testing.T) {
			t.Setenv("MCPVET_DANGLING_REF", where)
			r, err := Vet(context.Background(), Options{Command: bin, Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			var got []Finding
			for _, f := range r.Findings {
				if f.Kind == "unresolved_ref" {
					got = append(got, f)
				}
			}
			if len(got) != 1 || got[0].Tool != "upload" || got[0].Case != where+"Schema" || !r.Failed() {
				t.Fatalf("want one unresolved_ref finding on upload/%sSchema, got %+v", where, r.Findings)
			}
			if !strings.Contains(got[0].Detail, "#/$defs/ScreenInstance") {
				t.Errorf("detail should name the reference: %q", got[0].Detail)
			}
		})
	}
}

func TestUnresolvedRefs(t *testing.T) {
	for _, c := range []struct {
		name   string
		schema any
		want   string
	}{
		{"resolves", map[string]any{"$defs": map[string]any{"A": map[string]any{}}, "properties": map[string]any{"a": map[string]any{"$ref": "#/$defs/A"}}}, ""},
		{"missing def", map[string]any{"$defs": map[string]any{"A": map[string]any{}}, "items": map[string]any{"$ref": "#/$defs/B"}}, "#/$defs/B"},
		{"draft-07 definitions", map[string]any{"definitions": map[string]any{"A": true}, "anyOf": []any{map[string]any{"$ref": "#/definitions/A"}}}, ""},
		{"escaped pointer", map[string]any{"$defs": map[string]any{"a/b": map[string]any{}}, "items": map[string]any{"$ref": "#/$defs/a~1b"}}, ""},
		{"root", map[string]any{"items": map[string]any{"$ref": "#"}}, ""},
		// Not checked: anchors, remote refs, and anything under a nested $id,
		// whose base is no longer this document.
		{"anchor", map[string]any{"items": map[string]any{"$ref": "#node"}}, ""},
		{"remote", map[string]any{"items": map[string]any{"$ref": "https://example.com/s.json"}}, ""},
		{"nested id", map[string]any{"items": map[string]any{"$id": "https://example.com/x", "$ref": "#/$defs/X"}}, ""},
		// Data, not schema: a "$ref" key inside const, enum, default or examples.
		{"const data", map[string]any{"const": map[string]any{"$ref": "#/nowhere"}, "default": map[string]any{"$ref": "#/nowhere"}}, ""},
		// Property names are names, not keywords: one called "$id" must not
		// end the walk and hide its broken sibling.
		{"property named $id", map[string]any{"properties": map[string]any{"$id": map[string]any{"type": "string"}, "x": map[string]any{"$ref": "#/$defs/X"}}}, "#/$defs/X"},
	} {
		got := strings.Join(unresolvedRefs(c.schema), ",")
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
