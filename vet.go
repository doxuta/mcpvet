package mcpvet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Finding is one problem mcpvet found while exercising a server.
//
// Tool is the name the server reported and Case embeds the field names from
// its schema, both verbatim; a caller that prints them must pass them through
// SafeText first. Detail is composed by mcpvet and already escapes any server
// text it embeds, so it prints as-is.
type Finding struct {
	Tool     string `json:"tool"`
	Case     string `json:"case"`
	Kind     string `json:"kind"` // crash, hang, accepted_invalid, rejected_valid, schema_not_object
	Detail   string `json:"detail"`
	Breaking bool   `json:"breaking"`
}

// Report is the outcome of a vet run.
type Report struct {
	Server    ServerInfo `json:"server"`
	ToolCount int        `json:"tool_count"`
	CaseCount int        `json:"case_count"`
	Findings  []Finding  `json:"findings"`
	Drifts    []Drift    `json:"drifts,omitempty"`
	// TaskOnly are tools that declare execution.taskSupport "required" and
	// so cannot be called without MCP tasks, which mcpvet does not speak.
	// fuzz leaves them out rather than reporting their refusals.
	TaskOnly []string `json:"task_only,omitempty"`
	Lock     Lock     `json:"-"`
}

// Failed reports whether the run should fail CI.
func (r Report) Failed() bool {
	if len(r.Findings) > 0 {
		return true
	}
	for _, d := range r.Drifts {
		if d.Breaking() {
			return true
		}
	}
	return false
}

// Options configure a vet run.
type Options struct {
	// Command and Args launch a stdio MCP server (e.g. "npx", "-y", "some-mcp").
	Command string
	Args    []string
	// Timeout bounds each individual tool call; a call that exceeds it is a
	// "hang" finding.
	Timeout time.Duration
	// Fuzz enables generated-input testing. Without it, mcpvet only snapshots
	// and diffs the tool surface (safe against servers with side effects).
	Fuzz bool
	// SkipTools are tool names never to call (destructive tools).
	SkipTools []string
}

// Vet connects to the server, snapshots its tools, and optionally fuzzes them.
func Vet(ctx context.Context, opts Options) (*Report, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpvet", Version: "v0.1.0"}, nil)
	cmd := exec.Command(opts.Command, opts.Args...)
	tap := &taskTap{support: map[string]string{}}
	session, err := client.Connect(ctx, tapTransport{&mcp.CommandTransport{Command: cmd}, tap}, nil)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer session.Close()

	info := ServerInfo{Name: "unknown"}
	if init := session.InitializeResult(); init != nil && init.ServerInfo != nil {
		info = ServerInfo{Name: init.ServerInfo.Name, Version: init.ServerInfo.Version}
	}

	// Paginate: a single ListTools call returns only the first page, which
	// would let a server hide tools from the lock, the drift gate and the
	// fuzzer. The SDK's iterator follows nextCursor to exhaustion.
	var tools []*mcp.Tool
	for t, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list tools: %w", err)
		}
		tools = append(tools, t)
	}

	skip := map[string]bool{}
	for _, s := range opts.SkipTools {
		skip[s] = true
	}

	var surfaces []ToolSurface
	for _, t := range tools {
		surfaces = append(surfaces, ToolSurface{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: decodeSchema(t.InputSchema),
			TaskSupport: tap.get(t.Name),
			Annotations: hints(t.Annotations),
		})
	}

	report := &Report{
		Server:    info,
		ToolCount: len(surfaces),
		Lock:      BuildLock(info, surfaces),
	}
	// A schema nothing can be generated from is checked without calling the
	// tool, so lock and check report it too: the agent sees no parameters.
	for _, s := range surfaces {
		if gap := CoverageGap(GenerateCases(s.InputSchema)); gap != "" {
			report.Findings = append(report.Findings, Finding{s.Name, "inputSchema", "schema_not_object", gap, true})
		}
	}
	if !opts.Fuzz {
		return report, nil
	}

	for _, s := range surfaces {
		if skip[s.Name] {
			continue
		}
		if s.TaskSupport == "required" {
			report.TaskOnly = append(report.TaskOnly, s.Name)
			continue
		}
		for _, c := range GenerateCases(s.InputSchema) {
			report.CaseCount++
			if f := runCase(ctx, session, s.Name, c, opts.Timeout); f != nil {
				report.Findings = append(report.Findings, *f)
			}
		}
	}
	return report, nil
}

func runCase(ctx context.Context, session *mcp.ClientSession, tool string, c Case, timeout time.Duration) *Finding {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res, err := session.CallTool(callCtx, &mcp.CallToolParams{Name: tool, Arguments: c.Args})
	if callCtx.Err() == context.DeadlineExceeded {
		return &Finding{tool, c.Name, "hang",
			fmt.Sprintf("no response within %s — an agent would stall here", timeout), true}
	}
	if err != nil {
		// Transport death (the session is gone) is a crash; a JSON-RPC error
		// response means the server is alive and answered, which for a
		// schema-invalid case is the correct behaviour.
		if sessionDied(ctx, session, err) {
			return &Finding{tool, c.Name, "crash",
				fmt.Sprintf("server broke the session: %s", SafeText(err.Error())), true}
		}
		if c.Expect == ExpectAccept {
			return &Finding{tool, c.Name, "rejected_valid",
				fmt.Sprintf("schema-valid input rejected at protocol level: %s", SafeText(err.Error())), false}
		}
		return nil // rejected, as the schema requires (or allows)
	}
	switch c.Expect {
	case ExpectReject:
		if res == nil || !res.IsError {
			return &Finding{tool, c.Name, "accepted_invalid",
				"server accepted input its own schema forbids", false}
		}
	case ExpectAccept:
		// A handler that errors on input its own schema accepts is broken in
		// the direction that silently passed before this check existed.
		if res != nil && res.IsError {
			return &Finding{tool, c.Name, "rejected_valid",
				"server returned a tool error for input its own schema accepts", false}
		}
	}
	return nil
}

// sessionDied reports whether the session itself is gone, as opposed to the
// server answering with an error. It asks the session directly instead of
// matching English substrings in the message: classifying by text misreports
// an ordinary domain error ("connection refused by the database") as a crash,
// and misses a death whose message happens not to contain the magic words.
func sessionDied(ctx context.Context, session *mcp.ClientSession, callErr error) bool {
	if errors.Is(callErr, mcp.ErrConnectionClosed) {
		return true
	}
	// Ask the server whether it is still there. A live server answers a ping
	// even when it has just rejected a tool call.
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return session.Ping(pingCtx, nil) != nil
}

// decodeSchema normalizes whatever the SDK hands back (typed schema, raw
// JSON, or map) into plain decoded JSON.
func decodeSchema(v any) any {
	switch s := v.(type) {
	case nil:
		return map[string]any{}
	case map[string]any:
		return s
	case json.RawMessage:
		var out any
		if json.Unmarshal(s, &out) == nil {
			return out
		}
		return map[string]any{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return map[string]any{}
	}
	return out
}

// taskTap records each tool's execution.taskSupport from the raw tools/list
// responses. The Go SDK's Tool type has no field for it (v1.7.0 and v1.8.0),
// so it is gone by the time session.Tools returns. "forbidden" is the spec's
// default and is recorded as nothing.
type taskTap struct {
	mcp.Connection
	mu      sync.Mutex
	support map[string]string
}

func (c *taskTap) Read(ctx context.Context) (jsonrpc.Message, error) {
	msg, err := c.Connection.Read(ctx)
	if r, ok := msg.(*jsonrpc.Response); ok && err == nil && r.Result != nil {
		var res struct {
			Tools []struct {
				Name      string `json:"name"`
				Execution struct {
					TaskSupport string `json:"taskSupport"`
				} `json:"execution"`
			} `json:"tools"`
		}
		if json.Unmarshal(r.Result, &res) == nil {
			c.mu.Lock()
			for _, t := range res.Tools {
				if ts := t.Execution.TaskSupport; ts != "" && ts != "forbidden" {
					c.support[t.Name] = ts
				}
			}
			c.mu.Unlock()
		}
	}
	return msg, err
}

func (c *taskTap) get(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.support[name]
}

type tapTransport struct {
	mcp.Transport
	tap *taskTap
}

func (t tapTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	t.tap.Connection = conn
	return t.tap, nil
}

// hints converts the SDK's annotations. The SDK decodes readOnlyHint and
// idempotentHint as plain bools, which is safe here: their absence and the
// spec default are both false.
func hints(a *mcp.ToolAnnotations) *Hints {
	if a == nil {
		return nil
	}
	return &Hints{ReadOnly: &a.ReadOnlyHint, Destructive: a.DestructiveHint, Idempotent: &a.IdempotentHint, OpenWorld: a.OpenWorldHint}
}
