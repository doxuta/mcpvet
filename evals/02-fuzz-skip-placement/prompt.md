---
max_turns: 6
timeout_seconds: 180
allowed_tools: [Read, Glob, Grep, Skill]
runs: 3
---

My MCP server runs as `./bin/notes-server` over stdio. I want to fuzz every tool with inputs generated from its own schemas, but it has a `delete_all_notes` tool that must never be called. Give me the single command line to put in CI. Don't run anything yourself.
