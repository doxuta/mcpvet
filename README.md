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

### As a Claude Code plugin

The plugin carries one skill that tells the agent when to run mcpvet (adding,
enabling or upgrading an MCP server) and how to read the result. It still needs
the CLI above; the skill installs it with `go install` if it is missing.

```
/plugin install mcpvet --marketplace doxuta/mcpvet
```

Or from a shell, or for other agents through [skills](https://github.com/vercel-labs/skills):

```bash
claude plugin marketplace add doxuta/mcpvet && claude plugin install mcpvet@mcpvet
npx skills add doxuta/mcpvet
```

## Use in CI

```yaml
- run: mcpvet check -- npx -y @your/mcp-server   # gate on drift
- run: mcpvet fuzz -skip delete_everything -- ./your-server   # flags go before --
```

`check` exits non-zero on **breaking** drift (tool removed, schema shape
changed, new required field, description rewritten, a tool that now must be
called as an MCP task, a flipped behaviour hint such as `idempotentHint`), on a tool whose input schema is not `type: "object"`
(`schema_not_object`: the agent sees no parameters), and on a `$ref` in an
input or output schema that points at nothing (`unresolved_ref`). Cosmetic changes are
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

### Annotations (2026-10-22)

Claude Code 2.1.307 retries an HTTP tool call that was cut off mid-call, but
only for tools annotated read-only or idempotent, so those hints now change
what the client does. Until today the lockfile did not record them: a server
that flipped `idempotentHint` passed `check` with OK. It is now an
`annotations_changed` drift, and `regress_2026_10_22_test.go` fails on the old
code (mutation-checked: dropping the compare, the spec defaults, or the
old-lock guard each turns a test red).

Against `server-filesystem`, a 2025.8.21 lock checked against npm `latest`
(server 2.0.0, 2026-10-19) prints 14 `annotations_changed` lines, one per tool:
10 tools now claim `readOnlyHint: true`, `write_file` and `create_directory`
claim `idempotentHint: true`, and all 14 claim `openWorldHint: false`. What it
does not show: that pair already failed on schema drift, so the exit code is
the same as before; the new lines say which trust claims changed. 1.0.0 and
2.0.0 have identical surfaces, annotations included.

### Timeouts and shutdown (2026-10-26)

Until v0.4.0, `-timeout` bounded each fuzz call but not the start of the
server or `tools/list`. A command that never answers `initialize` hung the
run. Measured on macOS, same command, old binary against new:

| Command | v0.3.0 | v0.4.0 |
| --- | --- | --- |
| `-- python3`, the script name forgotten (python reads stdin and never answers) | `-timeout 3s`: still waiting at 30 s, killed by hand | `-start-timeout 4s`: exit 1 after 4 s, `no initialize response within 4s — is "python3" an MCP stdio server?` |
| SIGTERM to `mcpvet check -- sleep 300` | mcpvet exits, `sleep` left running under init | mcpvet exits 1, `sleep` stopped within the SDK's 5 s grace |
| `mcpvet fuzz -timeout 3s -- npx -y @modelcontextprotocol/server-sequential-thinking@1.0.0`, empty npm cache | 46 cases, OK | 46 cases, OK in 7 s |

The last row is why the start has its own `-start-timeout` (default 60 s):
the first version of this fix used `-timeout` for the start too, and npx's
9 s download on an empty cache failed the README's own `fuzz -timeout 3s`
example. `regress_2026_10_26_test.go` and `cmd/mcpvet/signal_test.go` fail
on v0.3.0; a mutation pass (handshake unbounded, listing unbounded, no
signal handling, wrong timeout on the start) turns each red. Not covered by
a test: a cancelled `fuzz` stopping before the next case.

### Dangling `$ref` (2026-10-27)

In June our own setup could not use Google's Stitch MCP server: one tool's
`outputSchema` referenced `#/$defs/ScreenInstance` without defining it, and
the Claude Code of that time rejected the whole `tools/list` (we ran it
behind a proxy that patched the schema). mcpvet never read `outputSchema`,
so it would have printed OK. Reproduced today with a test-server tool built
the same way, against Claude Code 2.1.305 (`claude -p`, stream-json `init`
event and one real call):

| `$ref #/$defs/ScreenInstance` undefined, in | Claude Code 2.1.305 | mcpvet v0.4.0 | mcpvet v0.5.0 |
| --- | --- | --- | --- |
| `outputSchema` | tool listed; every call fails in the client: `Tool 'upload' has an invalid outputSchema: can't resolve reference #/$defs/ScreenInstance from id #`, although the server answered | `check` OK | `unresolved_ref`, exit 1 |
| a property of `inputSchema` | tool listed, the call goes through | `check` OK | `unresolved_ref`, exit 1 |

So the failure is narrower than in June (one tool, not the server), and it
is silent until the agent calls the tool. No false positives on 7 public
servers, 53 tools, 2 `$ref`s that do resolve (`mcp-server-time`): the four
reference servers at `1.0.0` and `mcp-server-time`, `mcp-server-git`,
`mcp-server-fetch` through `uvx`, all 0 findings. `regress_2026_10_27_test.go`
fails on v0.4.0; a mutation pass (output schema not checked, `const`/`default`
read as schema, nested `$id` not skipped, anchors and remote refs checked,
property names read as keywords) turns each red.

### Plugin and skill (2026-10-20)

Installed from GitHub into a fresh, empty `HOME` (`mktemp -d`), Claude Code
2.1.292 and skills 1.7.4:

```
$ claude plugin marketplace add doxuta/mcpvet && claude plugin install mcpvet@mcpvet
✔ Successfully added marketplace: mcpvet (declared in user settings)
✔ Successfully installed plugin: mcpvet@mcpvet (scope: user)

$ npx skills add doxuta/mcpvet -a claude-code -y
◇  Found 1 skill
◇  Installed 1 skill
│  ✓ mcpvet (copied)
│    → ./.claude/skills/mcpvet
```

Following the skill's own commands found two bugs, both with tests that fail
on the old code:

- The skill's first command, `mcpvet lock -lock .mcpvet/filesystem.lock.json`,
  failed with "no such file or directory" in a project without `.mcpvet/`.
  The lockfile's directory is now created.
- This README's CI example put `-skip` after `--`, where it is passed to the
  server. Against the test server it ran 28 cases instead of 25: the tool it
  meant to spare was called. `fuzz` now refuses that line, and
  `cmd/mcpvet/docs_test.go` parses every `mcpvet` command in the README and the
  skill with the real flag set.

The skill's three commands were then run as written against
`server-filesystem@1.0.0`: lock 14 tools, check OK, fuzz 112 cases with the four
writing tools skipped (the same `ENOENT` findings as above). CI runs
`claude plugin validate --strict` on both manifests and the skill.

### Skill evals (2026-10-21)

`evals/` is a `claude plugin eval` suite: four prompts, each run three times
with the plugin and three times without it, graded by regular expressions only
(no judge model). Claude Code 2.1.305, agent model sonnet, 24 runs, $0.62:

| case | with | without | Δ |
|---|---|---|---|
| lock a server before trusting it (exact `lock` and `check` lines) | 1.00 | 0.00 | +1.00 |
| fuzz in CI without calling `delete_all_notes` (`-skip` before `--`, warns about real data) | 0.89 | 0.33 | +0.56 |
| `description_changed` in CI: read before re-locking, same lock path and command | 1.00 | 0.50 | +0.50 |
| unrelated Go question (the skill must not fire) | 1.00 | 1.00 | 0.00 |

Mean Δ +0.51. Without the plugin the model does not know the CLI, so the
command graders fail; the should-not-fire case shows the skill does not
trigger on an unrelated prompt.

The suite was checked by breaking the skill on purpose: with its fuzz example
rewritten to put `-skip` after `--`, the fuzz case fell from 0.89 to 0.67 and
2 of 3 runs were caught passing the flag to the server. What still fails: in 1
of 3 runs with the plugin the fuzz answer gave the right command but no warning
about real data, and in 1 of 3 mutated runs the model fixed the flag order on
its own, so the suite under-reports a broken example. Re-run it with:

```
claude plugin eval . --ablation with-without --no-publish
```

## Limitations

- **Semantic constraints are invisible to a schema.** The 10 `server-filesystem`
  findings are all valid-shaped paths that do not exist under the allowed root
  (`ENOENT`). The schema says "any string" and the server is right to refuse;
  mcpvet cannot know that. Treat `rejected_valid` as a prompt to read, or
  `-skip` the tool.
- **No MCP tasks.** Tools that declare `execution.taskSupport: "required"` are
  listed and locked but never called. The Go SDK has no field for it (v1.7.0,
  v1.8.0), so mcpvet reads it off the raw `tools/list` response.
- **Lockfiles written before 2026-10-22 record no annotations**, and `check`
  does not compare what it never recorded: run `mcpvet lock` again to start
  gating on `readOnlyHint`, `destructiveHint`, `idempotentHint` and
  `openWorldHint`.
- **Lockfiles written before 2026-10-19 record no task support.** A tool that
  already required tasks shows one `task_support_changed` drift on the first
  `check`; run `mcpvet lock` again.
- **The plugin needs Go.** There are no release binaries; the skill installs
  the CLI with `go install` and stops if Go is missing.
- **v0.1.0 (2026-08-26) was `@latest` until 2026-10-20.** Fixes made on main
  after it reached `go install …@latest` only with the v0.2.0 tag.
- **A stuck server costs up to `-start-timeout` plus 5 s.** On timeout or
  SIGTERM the SDK closes the server's stdin, waits 5 s, then sends SIGTERM to
  that one process; a server that spawned its own children and ignores
  SIGTERM can still leave them behind.
- **stdio only.** No Streamable HTTP transport yet.
- Output schemas, resources and prompts are not locked. Output schemas are
  checked for `unresolved_ref` only.
- **`unresolved_ref` checks local JSON pointers (`#/...`) only.** Anchors
  (`#name`), remote refs and anything under a nested `$id` are skipped: their
  base is not the tool's own schema, so a miss would prove nothing.

## Design choices

- **Schemas are handled as decoded JSON**, not a typed model, so mcpvet vets
  any server's schema rather than only the drafts one SDK understands.
- **Shape fingerprint, not byte hash**, for the diff: key order and
  description edits inside a schema don't cause false drift, but a changed
  type, bound, or required field does. Both are stored — the byte hash still
  reports "docs-only change".
- **Descriptions are locked too.** A description rewrite is treated as
  breaking: descriptions are the part of the surface that steers the model.
- **Annotations are locked with the spec defaults applied.** Clients act on
  the hints: Claude Code 2.1.307 retries an HTTP tool call cut off mid-call
  only when the tool is read-only or idempotent, so a server that starts
  calling a destructive tool idempotent can have it run twice when an HTTP
  connection drops mid-call. Any flip is
  breaking; spelling out a default is not a change.
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
