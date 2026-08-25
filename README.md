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
 ! lookup_city   accepted_invalid   server accepted input its own schema forbids
     case: missing:city
 ! lookup_city   accepted_invalid   server accepted input its own schema forbids
     case: oversize:city
 ! slow          hang               no response within 3s — an agent would stall here
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
changed, new required field, description rewritten); cosmetic changes are
reported but don't fail. `fuzz` additionally exits non-zero on findings.

## What it generates

From each tool's own input schema, per field:

| Category | Cases | Expected |
| --- | --- | --- |
| valid | mid-range values, format-aware (`date`, `email`, `uri`), first enum member | accepted |
| boundary | `minimum`/`maximum`, one past each, empty string vs `minLength` | edges accepted, past-edge rejected |
| hostile | missing required, type confusion, oversized strings, out-of-enum | **rejected** |
| payloads | SQL/path-traversal/JNDI/template/NUL/emoji/"ignore previous instructions" | treated as data, never a crash |

A server that *accepts* what its own schema forbids is a finding: the agent's
model reads that schema and will eventually send exactly what it promises is
invalid.

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
