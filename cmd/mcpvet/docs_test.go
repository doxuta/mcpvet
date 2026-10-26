package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

// The Claude Code skill is executed, not read: an agent copies its commands
// verbatim. Every `mcpvet` line inside a code block in the skill and the
// README must name a real mode, use only real flags with valid values, and
// carry a server command after `--`.
func TestDocumentedCommandsParse(t *testing.T) {
	for _, path := range []string{"../../skills/mcpvet/SKILL.md", "../../README.md"} {
		cmds := documentedCommands(t, path)
		if len(cmds) == 0 {
			t.Errorf("%s: no mcpvet commands found in code blocks", path)
		}
		for _, c := range cmds {
			fields := strings.Fields(c)
			mode := fields[1]
			switch mode {
			case "lock", "check", "fuzz":
			default:
				t.Errorf("%s: %q: unknown mode %q", path, c, mode)
				continue
			}
			fs, _, _, _, _, _ := newFlags(mode, flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			if err := fs.Parse(fields[2:]); err != nil {
				t.Errorf("%s: %q: %v", path, c, err)
				continue
			}
			if len(fs.Args()) == 0 {
				t.Errorf("%s: %q: no server command after the flags", path, c)
			}
			// After "--" everything goes to the server. An mcpvet flag there
			// is silently ignored; for -skip that means the tool the reader
			// meant to protect gets called.
			for _, a := range fs.Args() {
				if name, ok := strings.CutPrefix(a, "-"); ok && fs.Lookup(strings.SplitN(name, "=", 2)[0]) != nil {
					t.Errorf("%s: %q: %s comes after -- and is passed to the server, not to mcpvet", path, c, a)
				}
			}
		}
	}
}

// documentedCommands returns the mcpvet invocations in a markdown file's
// fenced code blocks, with any shell prompt and trailing comment removed.
func documentedCommands(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "```") {
			inBlock = !inBlock
			continue
		}
		if !inBlock {
			continue
		}
		line = strings.TrimPrefix(line, "$ ")
		line = strings.TrimPrefix(line, "- run: ")
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "mcpvet ") {
			out = append(out, line)
		}
	}
	return out
}

// The README's CI example used to read `mcpvet fuzz -- ./your-server -skip
// delete_everything`: -skip went to the server and fuzz called the tool. Run
// against the test server that way, it reported 28 cases instead of 25.
func TestMisplacedSkipStopsFuzz(t *testing.T) {
	cases := []struct {
		mode    string
		args    []string
		wantErr bool
	}{
		{"fuzz", []string{"-skip", "delete_everything"}, true},
		{"fuzz", []string{"--skip=delete_everything"}, true},
		{"fuzz", []string{"-json"}, false},               // warned, not fatal
		{"check", []string{"-skip", "x"}, false},         // check calls no tool
		{"fuzz", []string{"/srv", "--root", "/"}, false}, // the server's own flags
	}
	for _, c := range cases {
		fs, _, _, _, _, _ := newFlags(c.mode, flag.ContinueOnError)
		err := misplacedFlags(fs, c.mode, c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("%s -- server %v: err = %v, want error %v", c.mode, c.args, err, c.wantErr)
		}
	}
}
