package mcpvet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
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
	Kind     string `json:"kind"` // crash, hang, accepted_invalid, rejected_valid, schema_not_object, root_combinator, root_not_object, unresolved_ref, name_refused
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
	// NeedsClient are tools that answered MCP's -32021
	// MissingRequiredClientCapabilityError: they need a client capability
	// (elicitation, sampling, ...) mcpvet's client does not declare, so fuzz
	// stops calling them. Each entry is "tool (capability, ...)".
	NeedsClient []string `json:"needs_client,omitempty"`
	// NotRun are tools fuzz never called because the server crashed and
	// did not start again (RestartError says why).
	NotRun       []string `json:"not_run,omitempty"`
	RestartError string   `json:"restart_error,omitempty"`
	Lock         Lock     `json:"-"`
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
	// Timeout bounds the whole tools/list walk and each individual tool call;
	// a tool call that exceeds it is a "hang" finding, a listing that exceeds
	// it is an error.
	Timeout time.Duration
	// StartTimeout bounds launching the server and its initialize answer.
	// It is separate from Timeout because `npx -y` may download the server
	// first: 9 s for server-sequential-thinking on an empty npm cache.
	StartTimeout time.Duration
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
	if opts.StartTimeout <= 0 {
		opts.StartTimeout = 60 * time.Second
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "mcpvet", Version: "v0.1.0"}, nil)
	tap := &taskTap{support: map[string]string{}}
	// connect starts the server; fuzz calls it again after a crash.
	// The handshake and the listing are bounded too: a command that never
	// answers initialize (a server waiting on a prompt, or not an MCP server
	// at all) otherwise hangs a CI job until the runner kills it.
	connect := func() (*mcp.ClientSession, error) {
		cmd := exec.Command(opts.Command, opts.Args...)
		connCtx, cancel := context.WithTimeout(ctx, opts.StartTimeout)
		defer cancel()
		session, err := client.Connect(connCtx, tapTransport{&mcp.CommandTransport{Command: cmd}, tap}, nil)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil, fmt.Errorf("connect: no initialize response within %s — is %q an MCP stdio server?", opts.StartTimeout, opts.Command)
			}
			return nil, fmt.Errorf("connect: %w", err)
		}
		return session, nil
	}
	session, err := connect()
	if err != nil {
		return nil, err
	}
	defer func() { session.Close() }()

	info := ServerInfo{Name: "unknown"}
	if init := session.InitializeResult(); init != nil && init.ServerInfo != nil {
		info = ServerInfo{Name: init.ServerInfo.Name, Version: init.ServerInfo.Version}
	}

	// Paginate: a single ListTools call returns only the first page, which
	// would let a server hide tools from the lock, the drift gate and the
	// fuzzer. The SDK's iterator follows nextCursor to exhaustion.
	listCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	var tools []*mcp.Tool
	for t, err := range session.Tools(listCtx, nil) {
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return nil, fmt.Errorf("list tools: no response within %s", opts.Timeout)
			}
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
	// One that does describe an object, but through a root that agents trip
	// on, is reported once as root_combinator or root_not_object (RootGap).
	for _, s := range surfaces {
		if gap := NameGap(s.Name); gap != "" {
			report.Findings = append(report.Findings, Finding{s.Name, "name", "name_refused", gap, true})
		}
		if gap := CoverageGap(GenerateCases(s.InputSchema)); gap != "" {
			report.Findings = append(report.Findings, Finding{s.Name, "inputSchema", "schema_not_object", gap, true})
		} else if kind, gap := RootGap(s.InputSchema); kind != "" {
			report.Findings = append(report.Findings, Finding{s.Name, "inputSchema", kind, gap, true})
		}
	}
	// A $ref that points at nothing makes the schema invalid. In outputSchema
	// it costs the whole tool: Claude Code 2.1.305 lists it, then fails every
	// call in the client ("can't resolve reference") although the server
	// answered. The output schema is checked, not locked.
	for _, t := range tools {
		for _, side := range []struct {
			name   string
			schema any
			effect string
		}{
			{"inputSchema", t.InputSchema, "validators reject the schema and the agent gets no shape for that value"},
			{"outputSchema", t.OutputSchema, "clients that validate results fail every call"},
		} {
			for _, ref := range unresolvedRefs(decodeSchema(side.schema)) {
				report.Findings = append(report.Findings, Finding{t.Name, side.name, "unresolved_ref",
					fmt.Sprintf("$ref %s points at nothing in the %s: %s", SafeText(ref), side.name, side.effect), true})
			}
		}
	}
	if !opts.Fuzz {
		return report, nil
	}

	// A crash kills the session, and a dead session fails every later call:
	// without a restart one crash was reported once per remaining case, on
	// tools that never crashed, and their real findings were never seen.
	// So the server is started again before the next tool, and the rest of
	// the crashing tool's cases are skipped (one crash per tool, at most one
	// restart per tool).
	dead := false
	for _, s := range surfaces {
		if skip[s.Name] {
			continue
		}
		if s.TaskSupport == "required" {
			report.TaskOnly = append(report.TaskOnly, s.Name)
			continue
		}
		if dead && report.RestartError == "" {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			session.Close()
			next, err := connect()
			if err != nil {
				report.RestartError = SafeText(err.Error())
			} else {
				session, dead = next, false
			}
		}
		if dead {
			report.NotRun = append(report.NotRun, s.Name)
			continue
		}
		cases := GenerateCases(s.InputSchema)
		for i, c := range cases {
			// A cancelled run (SIGINT/SIGTERM in the CLI) stops here rather
			// than reporting every remaining case as a hang.
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			report.CaseCount++
			f := runCase(ctx, session, s.Name, c, opts.Timeout)
			if f == nil {
				continue
			}
			if f.Kind == needsClient {
				report.NeedsClient = append(report.NeedsClient, s.Name+" ("+f.Detail+")")
				break
			}
			if f.Kind == "crash" {
				dead = true
				if rest := len(cases) - i - 1; rest > 0 {
					f.Detail += fmt.Sprintf(" (%d later case(s) of this tool not run)", rest)
				}
				report.Findings = append(report.Findings, *f)
				break
			}
			report.Findings = append(report.Findings, *f)
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
		if caps, ok := missingClientCapability(err); ok {
			return &Finding{tool, c.Name, needsClient, caps, false}
		}
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
	// even when it has just rejected a tool call. MCP 2026-07-28 has no ping,
	// and a server on it answers "Method not found": still an answer, so
	// still alive.
	pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	err := session.Ping(pingCtx, nil)
	var answered *jsonrpc.Error
	return err != nil && !errors.As(err, &answered)
}

// needsClient marks a case the server refused with -32021; it never reaches
// Report.Findings.
const needsClient = "needs_client"

// missingClientCapability reports whether err is MCP's -32021
// MissingRequiredClientCapabilityError (schema 2026-07-28), and names the
// capabilities from its data.requiredCapabilities.
func missingClientCapability(err error) (string, bool) {
	var e *jsonrpc.Error
	if !errors.As(err, &e) || e.Code != -32021 {
		return "", false
	}
	var data struct {
		RequiredCapabilities map[string]json.RawMessage `json:"requiredCapabilities"`
	}
	_ = json.Unmarshal(e.Data, &data)
	names := make([]string, 0, len(data.RequiredCapabilities))
	for k := range data.RequiredCapabilities {
		names = append(names, SafeText(k))
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "a client capability", true
	}
	return strings.Join(names, ", "), true
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

// apiToolName is the Anthropic Messages API's rule for a tool name, quoted
// from its tool definition docs. MCP's naming guidance also allows the dot.
var apiToolName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// NameGap says why the Anthropic Messages API would refuse a tool name, or ""
// if it accepts it. Clients that forward names as they are send the whole
// tool list on every request, so one such name fails every turn.
func NameGap(name string) string {
	if apiToolName.MatchString(name) {
		return ""
	}
	gap := "name does not match ^[a-zA-Z0-9_-]{1,128}$, the Anthropic Messages API's rule for tool names: " +
		"clients that forward names as they are get a 400 on every request"
	if strings.Contains(name, ".") {
		gap += " (MCP's naming guidance allows the dot; the API does not)"
	}
	return gap
}
