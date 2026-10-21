---
max_turns: 6
timeout_seconds: 180
allowed_tools: [Read, Glob, Grep, Skill]
runs: 3
---

After upgrading an MCP server, my CI step `mcpvet check -lock .mcpvet/fs.lock.json -- npx -y @modelcontextprotocol/server-filesystem@1.1.0 /tmp` now exits 1 and prints:

```
! description_changed  read_file
```

Can I just re-run the lock command so CI goes green again?
