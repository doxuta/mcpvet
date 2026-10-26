package mcpvet

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Regression tests for a gap logged on 2026-10-23 and reproduced on
// 2026-10-26: -timeout bounded each fuzz call but not the connect handshake or
// tools/list. `mcpvet check -timeout 2s -- sleep 300` (a command that never
// answers initialize, like a server stuck on a prompt or a missing env var)
// was still waiting after 2m10s. In CI that is a job that hangs until the
// runner's own limit instead of a red line naming the server.

// vetWithin runs Vet and fails the test if it has not returned by limit.
func vetWithin(t *testing.T, limit time.Duration, opts Options) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := Vet(context.Background(), opts)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("Vet still running after %s (Timeout %s, StartTimeout %s)", limit, opts.Timeout, opts.StartTimeout)
		return nil
	}
}

// The limit allows the timeout under test plus the SDK's 5 s grace between closing the
// server's stdin and SIGTERM, plus slack for a loaded CI runner.
const shutdownSlack = 9 * time.Second

func TestTimeoutBoundsInitialize(t *testing.T) {
	err := vetWithin(t, 500*time.Millisecond+shutdownSlack,
		Options{Command: "sleep", Args: []string{"300"}, StartTimeout: 500 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "no initialize response within 500ms") {
		t.Fatalf("want an error naming the initialize timeout, got %v", err)
	}
}

func TestTimeoutBoundsToolsList(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_HANG_LIST", "1")
	err := vetWithin(t, 500*time.Millisecond+shutdownSlack,
		Options{Command: bin, Timeout: 500 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "list tools: no response within 500ms") {
		t.Fatalf("want an error naming the tools/list timeout, got %v", err)
	}
}

// The first version of this fix bounded the handshake by -timeout and broke
// the README's own `fuzz -timeout 3s -- npx -y ...`: on an empty npm cache npx
// spends 9 s downloading server-sequential-thinking before it can answer. A
// short per-call timeout must not cut a slow start.
func TestSlowStartIsNotBoundedByCallTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a helper binary")
	}
	bin := buildTestServer(t)
	t.Setenv("MCPVET_SLOW_START", "1s")
	if err := vetWithin(t, 1*time.Second+shutdownSlack,
		Options{Command: bin, Timeout: 200 * time.Millisecond}); err != nil {
		t.Fatalf("a server that takes 1s to start failed under a 200ms call timeout: %v", err)
	}
}
