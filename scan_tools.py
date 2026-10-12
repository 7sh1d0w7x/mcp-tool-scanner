#!/usr/bin/env python3
"""Flag suspicious patterns in MCP tool descriptions.

Tool descriptions are part of the prompt an agent reads. A malicious (or careless)
server can hide an instruction in a docstring — no exploit needed. This is a cheap
smoke detector so reviewing a tool catalog becomes routine instead of a good intention.

Usage:
    python3 scan_tools.py <tools-list.json>

Where <tools-list.json> is the JSON-RPC response of a `tools/list` request, e.g.:

    ( echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
      echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'
      echo '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
      sleep 2 ) | <your-mcp-server> | grep '"id":2' > tools.json

    python3 scan_tools.py tools.json

Exit code: 0 = clean, 1 = suspicious patterns found (usable in CI).
"""
import json
import sys

# Keyword-level signals. Deliberately broad: false positives are cheap to review,
# a missed instruction is not.
SUSPECT = [
    # file / system access
    "read", "/tmp", "/etc", "~/.ssh", ".env", "id_rsa", "passwd", "include its",
    "include the contents", "contents of",
    # injection / behaviour override
    "ignore previous", "ignore all previous", "disregard", "system instruction",
    "before answering", "before you respond", "first, ",
    # concealment — the part that turns a bug into an attack
    "do not mention", "do not tell", "don't mention", "don't tell", "without telling",
]


def scan(path):
    with open(path) as f:
        data = json.load(f)

    tools = data.get("result", {}).get("tools", [])
    hits = 0
    for t in tools:
        desc = (t.get("description") or "").lower()
        for word in SUSPECT:
            if word in desc:
                print(f"SUSPECT: {t.get('name', '?')} -> contains {word!r}")
                hits += 1

    if not hits:
        print("clean: no suspicious patterns found")
    return hits


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__.strip())
        sys.exit(2)
    sys.exit(1 if scan(sys.argv[1]) else 0)
