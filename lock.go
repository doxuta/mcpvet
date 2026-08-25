package mcpvet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
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
		}
		if s, ok := asSchema(t.InputSchema); ok {
			tl.SchemaShape = s.fingerprint()
			tl.Required = strings.Join(s.required(), ",")
		}
		tl.SchemaHash = hash(canonicalJSON(t.InputSchema))
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
}

// Drift is one difference between a stored lock and the live server.
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
				detail = fmt.Sprintf("input schema shape changed:\n    was: %s\n    now: %s", o.SchemaShape, t.SchemaShape)
			} else {
				detail = "input schema bytes changed but shape is equivalent (docs/annotations only)"
			}
			out = append(out, Drift{t.Name, "schema_changed", detail})
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
// change): removals, schema shape changes, and new required fields.
func (d Drift) Breaking() bool {
	switch d.Kind {
	case "removed", "required_changed":
		return true
	case "schema_changed":
		return strings.Contains(d.Detail, "shape changed")
	case "description_changed":
		return true // descriptions steer the model; treat rewrites as breaking
	}
	return false
}

// WriteLock saves a lock as indented JSON.
func WriteLock(path string, l Lock) error {
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
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
		return l, fmt.Errorf("mcpvet: parse %s: %w", path, err)
	}
	if l.Version != lockVersion {
		return l, fmt.Errorf("mcpvet: lockfile version %d, this build understands %d", l.Version, lockVersion)
	}
	return l, nil
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// canonicalJSON marshals with sorted keys (encoding/json sorts map keys), so
// the hash is stable across runs.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
