package mcpvet

import (
	"path/filepath"
	"testing"
)

// Regression test for a bug found by following mcpvet's own Claude Code skill.
//
// The skill keeps one lockfile per server under .mcpvet/, so its first command
// is `mcpvet lock -lock .mcpvet/filesystem.lock.json -- ...`. In a project that
// has no .mcpvet/ yet, WriteLock failed with "no such file or directory" after
// the server had been started and listed: the documented first step could not
// succeed on a fresh checkout.
func TestWriteLockCreatesParentDirectories(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".mcpvet", "nested", "server.lock.json")
	want := Lock{Version: 1, Server: ServerInfo{Name: "srv", Version: "1.0.0"}}

	if err := WriteLock(path, want); err != nil {
		t.Fatalf("WriteLock into a directory that does not exist yet: %v", err)
	}
	got, err := ReadLock(path)
	if err != nil {
		t.Fatalf("ReadLock: %v", err)
	}
	if got.Server != want.Server {
		t.Errorf("round trip: got server %+v, want %+v", got.Server, want.Server)
	}
}
