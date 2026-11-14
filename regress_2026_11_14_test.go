package mcpvet

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression test for a cascade found on 2026-11-14: once one tool's case
// killed the server, every later case of every tool was reported as a crash
// against a dead session. On the test server one real crash in "boom" became
// 28 crash findings, 27 of them blamed on greet and lookup_city, and
// lookup_city's real accepted_invalid was never seen.
func TestCrashDoesNotCascade(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_CRASH_TOOL", "1")
	r, err := Vet(context.Background(), Options{Command: bin, Fuzz: true, Timeout: 2 * time.Second, SkipTools: []string{"slow"}})
	if err != nil {
		t.Fatal(err)
	}
	byTool := map[string][]Finding{}
	for _, f := range r.Findings {
		byTool[f.Tool] = append(byTool[f.Tool], f)
	}
	// boom crashes on both missing:n and wrongtype:n; after the first, the
	// rest of its cases are skipped, so exactly one crash is reported.
	if got := byTool["boom"]; len(got) != 1 || got[0].Kind != "crash" {
		t.Errorf("boom: want exactly one crash finding, got %+v", got)
	}
	if got := byTool["greet"]; len(got) != 0 {
		t.Errorf("greet is well-behaved, want no findings, got %d (first: %+v)", len(got), got[0])
	}
	found := false
	for _, f := range byTool["lookup_city"] {
		if f.Kind == "crash" {
			t.Errorf("lookup_city never crashes, got %+v", f)
		}
		found = found || f.Kind == "accepted_invalid"
	}
	if !found {
		t.Error("lookup_city's accepted_invalid was not reported: tools after the crash were not fuzzed")
	}
	if len(r.NotRun) != 0 {
		t.Errorf("the restart worked, want no tools left unrun, got %v", r.NotRun)
	}
}

// If the server does not start again after the crash, the crash is still
// reported and the tools that were never called are named, instead of the
// whole run failing with a connect error and losing the finding.
func TestCrashThenNoRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_CRASH_TOOL", "1")
	t.Setenv("MCPVET_START_ONCE", filepath.Join(t.TempDir(), "started"))
	r, err := Vet(context.Background(), Options{Command: bin, Fuzz: true, Timeout: 2 * time.Second, SkipTools: []string{"slow"}})
	if err != nil {
		t.Fatalf("a failed restart must not lose the report: %v", err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Tool != "boom" || r.Findings[0].Kind != "crash" {
		t.Errorf("want the one crash on boom, got %+v", r.Findings)
	}
	if got := strings.Join(r.NotRun, ","); got != "greet,lookup_city" {
		t.Errorf("NotRun = %q, want greet,lookup_city", got)
	}
	if r.RestartError == "" {
		t.Error("RestartError is empty")
	}
}
