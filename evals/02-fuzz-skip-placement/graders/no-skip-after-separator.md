---
type: regex
target: last_message
match: not_contains
---
mcpvet fuzz [^\n`]* -- \./bin/notes-server[^\n`]*-skip
