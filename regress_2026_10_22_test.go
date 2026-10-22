package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression test for a gap that Claude Code 2.1.307 turned into a behaviour
// change. That release retries an HTTP MCP tool call whose connection closed
// mid-call, but only when the tool is annotated read-only or idempotent. The
// lockfile did not record a tool's annotations at all, so a server update that
// marked a tool idempotentHint: true changed how the client retries (and, in
// clients that auto-approve read-only tools, whether it asks) while `check`
// printed OK.
func TestAnnotationFlipIsBreakingDrift(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	ctx := context.Background()

	before, err := Vet(ctx, Options{Command: bin, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCPVET_ANNOTATION_DRIFT", "1")
	after, err := Vet(ctx, Options{Command: bin, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	drifts := Diff(before.Lock, after.Lock)
	if len(drifts) != 1 || drifts[0].Tool != "greet" || drifts[0].Kind != "annotations_changed" || !drifts[0].Breaking() {
		t.Fatalf("expected one breaking annotations drift on greet, got %+v", drifts)
	}
	if !strings.Contains(drifts[0].Detail, "idempotentHint false → true") {
		t.Errorf("detail should name the hint that flipped: %q", drifts[0].Detail)
	}
}

// Hints are compared after the spec defaults are applied, so a server that
// starts spelling out the defaults has not changed anything.
func TestExplicitDefaultAnnotationsAreNotDrift(t *testing.T) {
	no := BuildLock(ServerInfo{}, []ToolSurface{{Name: "a"}})
	f, tr := false, true
	explicit := BuildLock(ServerInfo{}, []ToolSurface{{Name: "a", Annotations: &Hints{ReadOnly: &f, Destructive: &tr, Idempotent: &f, OpenWorld: &tr}}})
	if d := Diff(no, explicit); len(d) != 0 {
		t.Fatalf("explicit defaults reported as drift: %+v", d)
	}
}

// A lock written before annotations were recorded has no annotations field.
// Checking it must not flag every annotated tool; `lock` again starts recording.
func TestLockWithoutAnnotationsIsNotDrift(t *testing.T) {
	tr := true
	live := BuildLock(ServerInfo{}, []ToolSurface{{Name: "a", Annotations: &Hints{ReadOnly: &tr}}})
	old := live
	old.Tools = []ToolLock{live.Tools[0]}
	old.Tools[0].Annotations = ""
	if d := Diff(old, live); len(d) != 0 {
		t.Fatalf("pre-annotation lock reported drift: %+v", d)
	}
}
