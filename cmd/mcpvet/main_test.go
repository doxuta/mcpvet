package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/doxuta/mcpvet"
)

// Every name in the text report is a name the audited server chose. A server
// that does not want its drift read can put a carriage return, an ANSI erase
// sequence or a bidi override in a tool name and rewrite the lines around it —
// including the "OK" line that says the surface is unchanged.
func TestPrintReportEscapesServerText(t *testing.T) {
	r := &mcpvet.Report{
		Server:    mcpvet.ServerInfo{Name: "srv\x1b[2K", Version: "1.0.0"},
		ToolCount: 1,
		CaseCount: 1,
		Drifts: []mcpvet.Drift{{
			Tool:   "greet\r  greet                  description_changed   nothing to see",
			Kind:   "description_changed",
			Detail: "description rewritten (23 → 105 chars)",
		}},
		Findings: []mcpvet.Finding{{
			Tool:   "lookup",
			Case:   "missing:city\nOK — tool surface matches the lockfile",
			Kind:   "accepted_invalid",
			Detail: "server accepted input its own schema forbids",
		}},
	}

	var buf bytes.Buffer
	printReport(&buf, r, "fuzz")
	out := buf.String()

	for _, line := range strings.Split(out, "\n") {
		if strings.ContainsFunc(line, func(c rune) bool { return !unicode.IsPrint(c) }) {
			t.Errorf("report line carries raw control characters from the server: %q", line)
		}
	}
	// The layout is fixed: a header, a blank line and a heading per section,
	// one line per drift, and two per finding. Server text must not add to it.
	if got, want := strings.Count(strings.TrimSuffix(out, "\n"), "\n"), 7; got != want {
		t.Errorf("report has %d newlines, want %d — server text injected a line:\n%s", got, want, out)
	}
}

func build(t *testing.T, out, pkg string) {
	t.Helper()
	if o, err := exec.Command("go", "build", "-o", out, pkg).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, o)
	}
}

// The report is not the only human-facing line mcpvet writes: an error on the
// way to the report is printed by die, and the error text a failed tools/list
// carries is written by the server. A server that does not want to be audited
// can therefore answer tools/list with an error message that ends in a newline
// and mcpvet's own "OK" line, and forge a clean run on stderr — the same
// forgery the report path escapes, at the sink it did not cover.
//
// The whole binary is exercised on purpose: the gap was an uncovered call
// site, so a test that stops at a helper would not have caught it.
func TestBinaryEscapesServerErrorText(t *testing.T) {
	if testing.Short() {
		t.Skip("builds helper binaries")
	}
	dir := t.TempDir()
	server := filepath.Join(dir, "testserver")
	vet := filepath.Join(dir, "mcpvet")
	build(t, server, "../../internal/testserver")
	build(t, vet, ".")

	const ok = "OK — tool surface matches the lockfile"
	forged := "mcpvet: " + ok
	// What a hostile server returns as its tools/list error message: an erased
	// tail so the real error scrolls away, then a forged success line.
	payload := "backend unavailable\r\x1b[2K\n" + forged

	cmd := exec.Command(vet, "check", "-lock", filepath.Join(dir, "mcp.lock.json"), "--", server)
	cmd.Env = append(os.Environ(), "MCPVET_HOSTILE_LIST_ERROR="+payload)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err == nil {
		t.Fatal("mcpvet exited 0 although the server failed tools/list")
	}
	out := stderr.String()
	if !strings.Contains(out, "list tools") {
		t.Fatalf("the server error never reached stderr: %q", out)
	}

	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if line == forged {
			t.Errorf("the server forged mcpvet's own success line on stderr: %q", line)
		}
		if strings.ContainsFunc(line, func(r rune) bool { return !unicode.IsPrint(r) }) {
			t.Errorf("stderr line carries raw control characters from the server: %q", line)
		}
	}
	if got := strings.Count(out, "\n"); got != 1 {
		t.Errorf("stderr is %d lines, want 1 — the server injected a line: %q", got, out)
	}

	// die escapes every error now, not only the ones carrying server text, so
	// the other half of SafeText's bargain is checked here too: printable text
	// passes through untouched. Without this, a regressed fast path would turn
	// every message mcpvet prints into a quoted Go literal and no test would
	// notice. This run reaches die by the other route — a healthy server and a
	// missing lockfile.
	lockPath := filepath.Join(dir, "mcp.lock.json")
	honest := exec.Command(vet, "check", "-lock", lockPath, "--", server)
	stderr.Reset()
	honest.Stderr = &stderr
	if err := honest.Run(); err == nil {
		t.Fatal("mcpvet exited 0 with no lockfile to check against")
	}
	if got, want := stderr.String(), "mcpvet: no lockfile at "+lockPath+" — run `mcpvet lock` first\n"; got != want {
		t.Errorf("mcpvet's own error no longer prints as itself:\n got %q\nwant %q", got, want)
	}
}
