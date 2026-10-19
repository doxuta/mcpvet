// Command mcpvet is contract testing and drift detection for MCP servers.
//
//	mcpvet lock  -- npx -y some-mcp-server     # snapshot the tool surface
//	mcpvet check -- npx -y some-mcp-server     # fail if it drifted (CI)
//	mcpvet fuzz  -- npx -y some-mcp-server     # schema-driven input testing
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/doxuta/mcpvet"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	lockPath := fs.String("lock", "mcp.lock.json", "lockfile path")
	timeout := fs.Duration("timeout", 10*time.Second, "per-call timeout")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	skip := fs.String("skip", "", "comma-separated tool names never to call")
	fs.Parse(os.Args[2:])

	args := fs.Args()
	if len(args) == 0 {
		usage()
	}

	opts := mcpvet.Options{
		Command: args[0],
		Args:    args[1:],
		Timeout: *timeout,
		Fuzz:    mode == "fuzz",
	}
	if *skip != "" {
		opts.SkipTools = splitComma(*skip)
	}

	switch mode {
	case "lock", "check", "fuzz":
	default:
		usage()
	}

	report, err := mcpvet.Vet(context.Background(), opts)
	if err != nil {
		die(err)
	}

	if mode == "lock" {
		die(mcpvet.WriteLock(*lockPath, report.Lock))
		fmt.Printf("mcpvet: locked %d tools from %s %s → %s\n",
			report.ToolCount, mcpvet.SafeText(report.Server.Name), mcpvet.SafeText(report.Server.Version), *lockPath)
		for _, f := range report.Findings {
			fmt.Fprintf(os.Stderr, "mcpvet: warning: %s: %s\n", mcpvet.SafeText(f.Tool), f.Detail)
		}
		return
	}

	if old, err := mcpvet.ReadLock(*lockPath); err == nil {
		report.Drifts = mcpvet.Diff(old, report.Lock)
	} else if !os.IsNotExist(err) {
		die(err)
	} else if mode == "check" {
		die(fmt.Errorf("no lockfile at %s — run `mcpvet lock` first", *lockPath))
	}

	if *jsonOut {
		json.NewEncoder(os.Stdout).Encode(report)
	} else {
		printReport(os.Stdout, report, mode)
	}
	if report.Failed() {
		os.Exit(1)
	}
}

// printReport writes the human-facing report. Every name here is a name the
// audited server chose, so it goes through mcpvet.SafeText; the Detail fields
// are mcpvet's own text with the server's values already escaped inside them,
// and keep their layout.
func printReport(w io.Writer, r *mcpvet.Report, mode string) {
	fmt.Fprintf(w, "mcpvet: %s %s — %d tools", mcpvet.SafeText(r.Server.Name), mcpvet.SafeText(r.Server.Version), r.ToolCount)
	if mode == "fuzz" {
		fmt.Fprintf(w, ", %d generated cases", r.CaseCount)
	}
	fmt.Fprintln(w)

	if len(r.Drifts) > 0 {
		fmt.Fprintln(w, "\nDRIFT vs lockfile:")
		for _, d := range r.Drifts {
			mark := " "
			if d.Breaking() {
				mark = "!"
			}
			fmt.Fprintf(w, " %s %-24s %-20s %s\n", mark, mcpvet.SafeText(d.Tool), d.Kind, d.Detail)
		}
	}
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "\nFINDINGS:")
		for _, f := range r.Findings {
			fmt.Fprintf(w, " ! %-24s %-18s %s\n     case: %s\n", mcpvet.SafeText(f.Tool), f.Kind, f.Detail, mcpvet.SafeText(f.Case))
		}
	}
	if len(r.TaskOnly) > 0 && mode == "fuzz" {
		names := make([]string, len(r.TaskOnly))
		for i, n := range r.TaskOnly {
			names[i] = mcpvet.SafeText(n)
		}
		fmt.Fprintf(w, "\nnot fuzzed (execution.taskSupport is required; mcpvet does not speak MCP tasks): %s\n", strings.Join(names, ", "))
	}
	if !r.Failed() {
		fmt.Fprintln(w, "\nOK — tool surface matches the lockfile"+fuzzSuffix(mode))
	}
}

func fuzzSuffix(mode string) string {
	if mode == "fuzz" {
		return " and every generated case behaved"
	}
	return ""
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: mcpvet lock|check|fuzz [flags] -- <server command...>

  lock    snapshot the server's tool surface into a lockfile
  check   compare the live server against the lockfile (CI gate)
  fuzz    check + schema-driven valid/boundary/hostile input testing

flags: -lock PATH  -timeout DUR  -skip tool1,tool2  -json`)
	os.Exit(2)
}

// die is the report path's other human-facing sink, and the text it prints is
// server-chosen too: Vet wraps whatever error a failed connect or tools/list
// returned, and that message is the server's. So it is escaped here, at the
// sink, and not at the two Vet return sites — that keeps %w intact for
// errors.Is (sessionDied depends on it) and leaves a library caller the real
// value, for the same reason -json keeps it.
func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpvet:", mcpvet.SafeText(err.Error()))
		os.Exit(1)
	}
}
