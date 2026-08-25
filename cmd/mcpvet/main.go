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
	"os"
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
			report.ToolCount, report.Server.Name, report.Server.Version, *lockPath)
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
		printReport(report, mode)
	}
	if report.Failed() {
		os.Exit(1)
	}
}

func printReport(r *mcpvet.Report, mode string) {
	fmt.Printf("mcpvet: %s %s — %d tools", r.Server.Name, r.Server.Version, r.ToolCount)
	if mode == "fuzz" {
		fmt.Printf(", %d generated cases", r.CaseCount)
	}
	fmt.Println()

	if len(r.Drifts) > 0 {
		fmt.Println("\nDRIFT vs lockfile:")
		for _, d := range r.Drifts {
			mark := " "
			if d.Breaking() {
				mark = "!"
			}
			fmt.Printf(" %s %-24s %-20s %s\n", mark, d.Tool, d.Kind, d.Detail)
		}
	}
	if len(r.Findings) > 0 {
		fmt.Println("\nFINDINGS:")
		for _, f := range r.Findings {
			fmt.Printf(" ! %-24s %-18s %s\n     case: %s\n", f.Tool, f.Kind, f.Detail, f.Case)
		}
	}
	if !r.Failed() {
		fmt.Println("\nOK — tool surface matches the lockfile" + fuzzSuffix(mode))
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

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcpvet:", err)
		os.Exit(1)
	}
}
