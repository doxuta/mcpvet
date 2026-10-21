---
type: regex
target: last_message
match: contains
flags: i
---
\b(read|review|inspect|diff|compare|look at)\b[^\n]{0,120}\bdescriptions?\b
