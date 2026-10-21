---
max_turns: 6
timeout_seconds: 180
allowed_tools: [Read, Glob, Grep, Skill]
runs: 3
---

I'm about to add `npx -y @modelcontextprotocol/server-filesystem@1.0.0 ./data` to this repo's .mcp.json. Before my agent trusts it, I want a record of the tools it exposes so that CI fails if a later version silently rewrites a tool description or changes a schema. Give me the exact commands to run now and in CI. Don't run anything yourself.
