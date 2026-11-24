package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression test for tool names the Anthropic Messages API refuses.
//
// The API's tool definition says the name "Must match the regex
// ^[a-zA-Z0-9_-]{1,128}$" (platform.claude.com, define-tools, read
// 2026-11-24). MCP's naming guidance also allows the dot, and lists
// admin.tools.list as a valid example, so a spec-following server can ship a
// name that a client forwarding names as they are turns into a 400 on every
// request ("tools.19.custom.name: String should match pattern", dotted MCP
// tool names in github/copilot-cli#2581; the same through Bedrock in
// coder/coder#26325). mcpvet locked such names without a word.
func TestToolNameTheAPIRefusesIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	run := func(t *testing.T, name string) (found, other []Finding) {
		t.Setenv("MCPVET_TOOL_NAME", name)
		report, err := Vet(context.Background(), Options{
			Command: bin, Timeout: 3 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range report.Findings {
			if f.Kind == "name_refused" {
				found = append(found, f)
			} else {
				other = append(other, f)
			}
		}
		return found, other
	}

	refused := map[string]string{
		"dot (MCP's own example)": "admin.tools.list",
		"space":                   "list users",
		"slash":                   "users/list",
		"non-ASCII":               "liệt_kê",
		"129 characters":          strings.Repeat("a", 129),
	}
	for label, name := range refused {
		t.Run(label, func(t *testing.T) {
			found, other := run(t, name)
			if len(other) != 0 {
				t.Errorf("found more than the name: %+v", other)
			}
			if len(found) != 1 || found[0].Tool != name || !found[0].Breaking {
				t.Fatalf("want one breaking name_refused on %q, got %+v", name, found)
			}
			if d := found[0].Detail; !strings.Contains(d, "^[a-zA-Z0-9_-]{1,128}$") || !strings.Contains(d, "Anthropic Messages API") {
				t.Errorf("detail does not quote the rule and the API: %s", d)
			}
		})
	}
	for _, name := range []string{"getUser", "DATA_EXPORT_v2", "x-y_z", strings.Repeat("a", 128)} {
		t.Run("clean "+name[:min(len(name), 16)], func(t *testing.T) {
			if found, other := run(t, name); len(found)+len(other) != 0 {
				t.Fatalf("flagged a name the API accepts: %+v %+v", found, other)
			}
		})
	}
}
