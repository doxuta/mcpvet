package mcpvet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Lock is the snapshot of a server's tool surface — the "package-lock" for an
// agent's tools. Descriptions are hashed as well as schemas: a silently
// rewritten description is a prompt-injection vector even when the schema is
// unchanged.
type Lock struct {
	Version int        `json:"version"`
	Server  ServerInfo `json:"server"`
	Tools   []ToolLock `json:"tools"`
}

// ServerInfo identifies the server that produced the lock.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ToolLock is one tool's locked surface.
type ToolLock struct {
	Name            string `json:"name"`
	DescriptionHash string `json:"description_sha256"`
	DescriptionLen  int    `json:"description_len"`
	SchemaHash      string `json:"input_schema_sha256"`
	SchemaShape     string `json:"input_schema_shape"`
	Required        string `json:"required,omitempty"`
	TaskSupport     string `json:"task_support,omitempty"` // "" is the spec default, forbidden
}

const lockVersion = 1

// BuildLock snapshots the given tools.
func BuildLock(server ServerInfo, tools []ToolSurface) Lock {
	l := Lock{Version: lockVersion, Server: server}
	for _, t := range tools {
		tl := ToolLock{
			Name:            t.Name,
			DescriptionHash: hash(t.Description),
			DescriptionLen:  len(t.Description),
			TaskSupport:     t.TaskSupport,
		}
		if s, ok := asSchema(t.InputSchema); ok {
			tl.SchemaShape = s.fingerprint()
			tl.Required = strings.Join(s.required(), ",")
		}
		tl.SchemaHash = hash(jsonToken(t.InputSchema))
		l.Tools = append(l.Tools, tl)
	}
	sort.Slice(l.Tools, func(i, j int) bool { return l.Tools[i].Name < l.Tools[j].Name })
	return l
}

// ToolSurface is the part of an MCP tool mcpvet inspects.
type ToolSurface struct {
	Name        string
	Description string
	InputSchema any
	TaskSupport string // execution.taskSupport; "" when absent or "forbidden"
}

// Drift is one difference between a stored lock and the live server.
//
// Tool is the name the server reported, verbatim; a caller that prints it must
// pass it through SafeText first. Detail is composed by mcpvet and every
// server-supplied value inside it is already escaped, so it prints as-is.
type Drift struct {
	Tool   string `json:"tool"`
	Kind   string `json:"kind"` // added, removed, description_changed, schema_changed, required_changed
	Detail string `json:"detail"`
}

// Diff compares a stored lock against a freshly built one.
func Diff(old, new Lock) []Drift {
	var out []Drift
	oldByName := map[string]ToolLock{}
	for _, t := range old.Tools {
		oldByName[t.Name] = t
	}
	newByName := map[string]ToolLock{}
	for _, t := range new.Tools {
		newByName[t.Name] = t
	}
	for _, t := range new.Tools {
		o, ok := oldByName[t.Name]
		if !ok {
			out = append(out, Drift{t.Name, "added", "tool is not in the lockfile"})
			continue
		}
		if o.DescriptionHash != t.DescriptionHash {
			out = append(out, Drift{t.Name, "description_changed",
				fmt.Sprintf("description rewritten (%d → %d chars) — review for injected instructions", o.DescriptionLen, t.DescriptionLen)})
		}
		if o.SchemaHash != t.SchemaHash {
			detail := "input schema changed"
			if o.SchemaShape != t.SchemaShape {
				detail = fmt.Sprintf("input schema shape changed:\n    was: %s\n    now: %s",
					shapeText(o.SchemaShape), shapeText(t.SchemaShape))
			} else {
				detail = "input schema bytes changed but shape is equivalent (docs/annotations only)"
			}
			out = append(out, Drift{t.Name, "schema_changed", detail})
		}
		if o.TaskSupport != t.TaskSupport {
			out = append(out, Drift{t.Name, "task_support_changed",
				fmt.Sprintf("execution.taskSupport %q → %q", taskText(o.TaskSupport), taskText(t.TaskSupport))})
		}
		if o.Required != t.Required {
			out = append(out, Drift{t.Name, "required_changed",
				fmt.Sprintf("required fields %q → %q", o.Required, t.Required)})
		}
	}
	for _, t := range old.Tools {
		if _, ok := newByName[t.Name]; !ok {
			out = append(out, Drift{t.Name, "removed", "tool disappeared from the server"})
		}
	}
	return out
}

// Breaking reports whether a drift breaks callers (as opposed to a cosmetic
// change): removals, schema shape changes, new required fields, and a change
// in whether the tool must be called as an MCP task.
func (d Drift) Breaking() bool {
	switch d.Kind {
	case "removed", "required_changed", "task_support_changed":
		return true
	case "schema_changed":
		return strings.Contains(d.Detail, "shape changed")
	case "description_changed":
		return true // descriptions steer the model; treat rewrites as breaking
	}
	return false
}

// WriteLock saves a lock as indented JSON, creating its directory if needed.
func WriteLock(path string, l Lock) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// ReadLock loads a lock from disk.
func ReadLock(path string) (Lock, error) {
	var l Lock
	b, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("parse %s: %w", path, err)
	}
	if l.Version != lockVersion {
		return l, fmt.Errorf("lockfile version %d, this build understands %d", l.Version, lockVersion)
	}
	return l, nil
}

// SafeText renders a string the audited server chose — a tool name, a schema
// shape, the text of an error it returned — for a human-facing line of the
// report. mcpvet's whole subject is a server that rewrites its own surface: a
// server that puts a carriage return or an ANSI erase sequence in a tool name
// can otherwise scroll the drift that reports it off the screen, and a bare
// newline lets it forge mcpvet's own "OK" line underneath a finding. Text that
// is entirely printable is returned unchanged, so an honest server's report
// reads exactly as before; anything else is rendered as a quoted Go string
// literal, which escapes every control character and every invisible rune
// (bidi overrides included) while still showing the operator what was sent.
//
// Every human-facing line mcpvet writes must go through this, and they are:
// the text report (printReport), the `lock` success line, and die, which
// prints the error a failed connect or tools/list returned — server text as
// much as a tool name is. Values composed into a Drift or Finding Detail are
// escaped where the Detail is built, so the Detail itself prints as-is.
//
// The -json output is deliberately not routed through this: encoding/json
// already escapes these bytes, and a machine consumer needs the real value.
func SafeText(s string) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return s
	}
	return strconv.Quote(s)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// shapeText renders a fingerprint for the drift report. A schema that asserts
// nothing fingerprints to "", which would print as a blank line.
func shapeText(shape string) string {
	if shape == "" {
		return "(no type: accepts any input)"
	}
	return SafeText(shape)
}

// taskText names an empty task support by the spec default it stands for.
// It is printed with %q, which escapes whatever the server sent.
func taskText(ts string) string {
	if ts == "" {
		return "forbidden"
	}
	return ts
}
