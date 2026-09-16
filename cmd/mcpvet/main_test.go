package main

import (
	"bytes"
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
