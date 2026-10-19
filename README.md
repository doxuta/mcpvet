# mcpvet 🔍

**`go vet` for MCP servers.** A static Go binary for CI that snapshots an MCP
server's tool surface into a lockfile, fails the build when it silently
changes, and fuzzes every tool with inputs generated from that tool's own
JSON Schema.

Your agent trusts whatever tool descriptions and schemas a server hands it, at
every startup. Nothing pins them. A server that quietly rewrites a tool
description tomorrow — the MCP "rug pull" — reprograms your agent, and no test
you own will notice.

```
$ mcpvet lock -- npx -y some-mcp-server
mcpvet: locked 3 tools from some-mcp-server v1.0.0 → mcp.lock.json

# next day, the server updates itself:
$ mcpvet check -- npx -y some-mcp-server
mcpvet: some-mcp-server v1.0.0 — 3 tools

DRIFT vs lockfile:
 ! greet    description_changed  description rewritten (23 → 105 chars) — review for injected instructions
exit 1
```

And the contract side — inputs generated from each tool's schema, then checked
against what the server actually does with them:

```
$ mcpvet fuzz -timeout 3s -- ./my-mcp-server
mcpvet: testserver v1.0.0 — 3 tools, 28 generated cases

FINDINGS:
 ! lookup_city              accepted_invalid   server accepted input its own schema forbids
     case: missing:city
 ! lookup_city              accepted_invalid   server accepted input its own schema forbids
     case: wrongtype:city
 ! lookup_city              accepted_invalid   server accepted input its own schema forbids
     case: oversize:city
 ! slow                     hang               no response within 3s — an agent would stall here
     case: valid
exit 1
```

## Install

```bash
go install github.com/doxuta/mcpvet/cmd/mcpvet@latest
```

## Use in CI

```yaml
- run: mcpvet check -- npx -y @your/mcp-server   # gate on drift
- run: mcpvet fuzz  -- ./your-server -skip delete_everything
```

`check` exits non-zero on **breaking** drift (tool removed, schema shape
changed, new required field, description rewritten, a tool that now must be
called as an MCP task) and on a tool whose input schema is not `type: "object"`
(`schema_not_object`: the agent sees no parameters). Cosmetic changes are
reported but don't fail. `fuzz` additionally exits non-zero on findings.

## What it generates

From each tool's own input schema, per field:

| Category | Cases | Expected |
| --- | --- | --- |
| valid | mid-range values, format-aware (`date`, `email`, `uri`), first enum member, the `const` value | accepted |
| boundary | `minimum`/`maximum`, one past each, empty string vs `minLength` | edges accepted, past-edge rejected |
| hostile | missing required, type confusion, oversized strings, out-of-enum | **rejected** |
| payloads | SQL/path-traversal/JNDI/template/NUL/emoji/"ignore previous instructions" | treated as data, never a crash |

A server that *accepts* what its own schema forbids is a finding: the agent's
model reads that schema and will eventually send exactly what it promises is
invalid.

## Proof

Measured 2026-10-19 against the four reference servers in
[modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers),
run through `npx` exactly as in the examples above. `1.0.0` is npm's `latest`
for all four (published 2026-10-11).

| What | Server | Result |
| --- | --- | --- |
| drift, older release → `1.0.0` | `server-filesystem` 2025.8.21 | 29 drift lines, 28 breaking: 13 tools gained their whole schema, 2 descriptions rewritten (114 → 234, 332 → 424 chars) |
| | `server-memory` 2025.11.25 | 2: `create_entities` description 51 → 296 chars; `search_nodes.query` gained `maxLength: 2048` |
| | `server-everything` 2026.1.26 | 9: every tool dropped `additionalProperties: false`, so each schema now accepts more |
| `schema_not_object` | `server-filesystem` 2025.8.21 | 13 of 14 tools advertised `{"$schema": "…"}` and nothing else. Before 2026-10-19 mcpvet locked this and `check` printed OK |
| | all four at `1.0.0` | 0 |
| `fuzz` | `server-sequential-thinking` | 1 tool, 46 cases, 0 findings |
| | `server-everything` | 14 tools, 64 cases, 0 findings; `simulate-research-query` not fuzzed (requires MCP tasks). Before 2026-10-19 it was fuzzed with plain calls and reported as a false `rejected_valid`, failing the run |
| | `server-filesystem` (root: an empty temp dir) | 14 tools, 179 cases, 10 `rejected_valid` — see Limitations |

`server-memory` was locked and checked but not fuzzed: its tools write to the
server's own memory file. Each of the two 2026-10-19 bugs has a regression
test (`regress_2026_10_19_test.go`) that fails on the old code.

## Limitations

- **Semantic constraints are invisible to a schema.** The 10 `server-filesystem`
  findings are all valid-shaped paths that do not exist under the allowed root
  (`ENOENT`). The schema says "any string" and the server is right to refuse;
  mcpvet cannot know that. Treat `rejected_valid` as a prompt to read, or
  `-skip` the tool.
- **No MCP tasks.** Tools that declare `execution.taskSupport: "required"` are
  listed and locked but never called. The Go SDK has no field for it (v1.7.0,
  v1.8.0), so mcpvet reads it off the raw `tools/list` response.
- **Lockfiles written before 2026-10-19 record no task support.** A tool that
  already required tasks shows one `task_support_changed` drift on the first
  `check`; run `mcpvet lock` again.
- **stdio only.** No Streamable HTTP transport yet.
- Output schemas, resources and prompts are not locked.

## Design choices

- **Schemas are handled as decoded JSON**, not a typed model, so mcpvet vets
  any server's schema rather than only the drafts one SDK understands.
- **Shape fingerprint, not byte hash**, for the diff: key order and
  description edits inside a schema don't cause false drift, but a changed
  type, bound, or required field does. Both are stored — the byte hash still
  reports "docs-only change".
- **Descriptions are locked too.** A description rewrite is treated as
  breaking: descriptions are the part of the surface that steers the model.
- **Read-only by default.** `lock` and `check` never call a tool. Fuzzing is
  opt-in and `-skip` excludes destructive tools.

## Tiếng Việt

`mcpvet` là "package-lock cho tool của AI agent": chụp lại toàn bộ bề mặt tool
của một MCP server vào lockfile, CI sẽ fail khi server âm thầm đổi schema hay
đổi mô tả tool (kiểu rug-pull chèn lệnh vào agent), đồng thời sinh input từ
chính JSON Schema của tool — hợp lệ, biên, và độc hại — để bắt handler nào
nhận cả thứ mà schema của nó cấm, hoặc treo không trả lời.

MIT © Xuan Tai Doan — built with an AI coding agent under human review.
Uses the official [modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk).
