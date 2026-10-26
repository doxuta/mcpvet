//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Stopping mcpvet must stop the server it started. Reproduced 2026-10-26:
// SIGTERM to `mcpvet check -- sleep 300` ended mcpvet at once and left the
// sleep running, re-parented to init. A CI runner or an agent harness that
// cancels a step sends exactly that signal, and a real server left behind
// keeps its ports, files and CPU (our own stack once had a hook child orphaned
// this way at 98% CPU for 18 days).
func TestSignalStopsTheServer(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "mcpvet")
	build(t, bin, ".")
	pidFile := filepath.Join(dir, "server.pid")

	cmd := exec.Command(bin, "check", "-timeout", "60s", "-lock", filepath.Join(dir, "x.lock.json"),
		"--", "sh", "-c", `echo $$ > "$0"; exec sleep 300`, pidFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	for deadline := time.Now().Add(10 * time.Second); pid == 0; {
		if b, err := os.ReadFile(pidFile); err == nil && strings.HasSuffix(string(b), "\n") {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		} else if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("server never started")
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })

	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	// mcpvet may exit before the server does; the SDK closes stdin, waits up
	// to 5 s, then sends SIGTERM.
	for deadline := time.Now().Add(9 * time.Second); syscall.Kill(pid, 0) == nil; {
		if time.Now().After(deadline) {
			t.Fatalf("server pid %d still running after mcpvet got SIGTERM", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
