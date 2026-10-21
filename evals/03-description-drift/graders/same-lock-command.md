---
type: regex
target: last_message
match: contains
---
mcpvet lock -lock \.mcpvet/fs\.lock\.json -- npx -y @modelcontextprotocol/server-filesystem@1\.1\.0
