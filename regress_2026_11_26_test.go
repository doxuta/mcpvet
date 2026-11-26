package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression tests for servers on MCP 2026-07-28.
//
// That revision has no ping: @modelcontextprotocol/server-everything 2.3.1
// (npm latest, 2026-11-18) answers it with -32601 "Method not found".
// sessionDied asked ping whether the server was still there after a tool
// call failed, so every JSON-RPC error from such a server read as a dead
// session: mcpvet v0.9.0 reported 8 crashes on server-everything 2.3.1, and
// each "crash" skipped the rest of that tool's cases.
//
// Seven of those eight tools answered -32021, which the 2026-07-28 schema
// defines as MissingRequiredClientCapabilityError: the tool needs a client
// capability (elicitation, sampling) that mcpvet's client does not declare.
// That is the server behaving correctly, so it is not a finding either.

func fuzzTool(t *testing.T, env ...string) (*Report, map[string][]Finding) {
	t.Helper()
	bin := buildTestServer(t)
	for _, k := range env {
		t.Setenv(k, "1")
	}
	r, err := Vet(context.Background(), Options{Command: bin, Fuzz: true, Timeout: 3 * time.Second, SkipTools: []string{"slow"}})
	if err != nil {
		t.Fatal(err)
	}
	byTool := map[string][]Finding{}
	for _, f := range r.Findings {
		byTool[f.Tool] = append(byTool[f.Tool], f)
	}
	return r, byTool
}

func TestPinglessServerAnsweringAnErrorIsAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	for _, env := range [][]string{
		{"MCPVET_PROTOCOL_REJECT"},                   // control: ping works
		{"MCPVET_PROTOCOL_REJECT", "MCPVET_NO_PING"}, // 2026-07-28
	} {
		t.Run(strings.Join(env, "+"), func(t *testing.T) {
			r, byTool := fuzzTool(t, env...)
			if got := byTool["strict"]; len(got) != 0 {
				t.Errorf("strict rejects bad input with -32602 and accepts good input, want no findings, got %+v", got)
			}
			if len(r.NotRun) != 0 {
				t.Errorf("NotRun = %v, want none", r.NotRun)
			}
		})
	}
}

func TestMissingClientCapabilityIsNotFuzzed(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	for _, env := range [][]string{
		{"MCPVET_NEEDS_ELICITATION"},
		{"MCPVET_NEEDS_ELICITATION", "MCPVET_NO_PING"},
	} {
		t.Run(strings.Join(env, "+"), func(t *testing.T) {
			r, byTool := fuzzTool(t, env...)
			if got := byTool["ask"]; len(got) != 0 {
				t.Errorf("ask answers -32021 as MCP requires, want no findings, got %+v", got)
			}
			if got := strings.Join(r.NeedsClient, ","); got != "ask (elicitation)" {
				t.Errorf("NeedsClient = %q, want %q", got, "ask (elicitation)")
			}
			if len(byTool["lookup_city"]) == 0 {
				t.Error("lookup_city's known finding is missing: tools after ask were not fuzzed")
			}
		})
	}
}

// Control: a server that exits is still a crash when it has no ping.
func TestPinglessServerThatExitsIsACrash(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	_, byTool := fuzzTool(t, "MCPVET_CRASH_TOOL", "MCPVET_NO_PING")
	if got := byTool["boom"]; len(got) != 1 || got[0].Kind != "crash" {
		t.Errorf("boom: want exactly one crash finding, got %+v", got)
	}
}
