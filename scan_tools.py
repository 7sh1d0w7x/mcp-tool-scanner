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

Accepted input
--------------
A JSON object shaped like a `tools/list` result:

    {"jsonrpc": "2.0", "id": 2, "result": {"tools": [ ... ], "nextCursor": "..."}}

Each entry of `result.tools` must be an object with:

    name         string, non-empty            (required by the MCP specification)
    inputSchema  object                       (required by the MCP specification)
    description  string or null               (optional)

Other fields (`title`, `outputSchema`, `annotations`, `_meta`, ...) are accepted
and ignored. An empty `tools` array is a valid catalog and scans clean.

Anything else is rejected as invalid input rather than reported as clean: a
scanner that says "clean" about something it could not read is worse than no
scanner. JSON-RPC error responses are rejected too.

Exit codes
----------
    0  valid catalog, no signals
    1  valid catalog, at least one signal
    2  invalid input or usage error (message on stderr)

Scope and limits
----------------
This is heuristic keyword matching. **No signal does not mean the server is safe.**
A cleverly worded instruction passes; a legitimate description may be flagged.
See README.md for the known false positives and false negatives.
"""
import json
import re
import sys

# Keyword-level signals. Deliberately broad: reviewing a false positive is cheap,
# missing a hidden instruction is not. Word-shaped signals use \b so that
# "thread" does not match "read"; phrases stay as plain substrings.
# Matching is case-insensitive (the scan reads prose, not identifiers).
SIGNAL_PATTERNS = [
    # file / system access
    (r"\bread\b", "file/system access"),
    (r"/tmp\b", "file/system access"),
    (r"/etc\b", "file/system access"),
    (r"~/\.ssh", "file/system access"),
    (r"\.env\b", "file/system access"),
    (r"id_rsa", "file/system access"),
    (r"passwd", "file/system access"),
    (r"include its", "file/system access"),
    (r"include the contents", "file/system access"),
    (r"contents of", "file/system access"),
    # injection / behaviour override
    (r"ignore previous", "behaviour override"),
    (r"ignore all previous", "behaviour override"),
    (r"disregard", "behaviour override"),
    (r"system instruction", "behaviour override"),
    (r"before answering", "behaviour override"),
    (r"before you respond", "behaviour override"),
    (r"first, ", "behaviour override"),
    # concealment — the part that turns a bug into an attack
    (r"do not mention", "concealment"),
    (r"do not tell", "concealment"),
    (r"don't mention", "concealment"),
    (r"don't tell", "concealment"),
    (r"without telling", "concealment"),
]

SIGNALS = [
    (re.compile(pattern, re.IGNORECASE), category)
    for pattern, category in SIGNAL_PATTERNS
]


class CatalogError(Exception):
    """The input is not a tools/list catalog we can scan."""


def _validate_tool(index, tool):
    where = f"result.tools[{index}]"

    if not isinstance(tool, dict):
        raise CatalogError(f"{where} must be an object, got {type(tool).__name__}")

    name = tool.get("name")
    if not isinstance(name, str) or not name:
        raise CatalogError(f'{where} is missing a non-empty string "name"')

    # The MCP specification marks Tool.inputSchema as required.
    if not isinstance(tool.get("inputSchema"), dict):
        raise CatalogError(
            f'{where} ("{name}") is missing "inputSchema" '
            "(required by the MCP specification)"
        )

    description = tool.get("description")
    if description is not None and not isinstance(description, str):
        raise CatalogError(
            f'{where} ("{name}") has a non-string "description" '
            f"({type(description).__name__})"
        )


def load_catalog(path):
    """Read and validate a tools/list response. Returns the list of tools."""
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as err:
        raise CatalogError(
            f"cannot read {path}: {err.strerror or err}"
        ) from None
    except UnicodeDecodeError as err:
        # A tools/list response is JSON text, and JSON text is UTF-8. Bytes that
        # do not decode are invalid input (exit 2), not a suspicious catalog.
        byte = err.object[err.start] if err.object else 0
        raise CatalogError(
            f"{path} is not valid UTF-8: byte 0x{byte:02x} at position {err.start} "
            "(a tools/list response is JSON text, which must be UTF-8)"
        ) from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as err:
        raise CatalogError(
            f"{path} is not valid JSON: {err.msg} "
            f"(line {err.lineno}, column {err.colno})"
        ) from None

    if not isinstance(data, dict):
        raise CatalogError(
            f"top-level JSON must be an object (a JSON-RPC response), "
            f"got {type(data).__name__}"
        )

    if "error" in data:
        error = data["error"]
        if isinstance(error, dict):
            code = error.get("code", "?")
            message = str(error.get("message", "")).strip()
            raise CatalogError(f"the server returned a JSON-RPC error: {code} {message}".rstrip())
        raise CatalogError("the server returned a JSON-RPC error")

    if "result" not in data:
        raise CatalogError(
            'missing "result" — this does not look like a tools/list response'
        )

    result = data["result"]
    if not isinstance(result, dict):
        raise CatalogError(f'"result" must be an object, got {type(result).__name__}')

    if "tools" not in result:
        raise CatalogError('missing "result.tools"')

    tools = result["tools"]
    if not isinstance(tools, list):
        raise CatalogError(
            f'"result.tools" must be an array, got {type(tools).__name__}'
        )

    for index, tool in enumerate(tools):
        _validate_tool(index, tool)

    return tools


def scan_tools(tools):
    """Return [(tool_name, matched_text, category)] for every signal found."""
    findings = []
    for tool in tools:
        description = tool.get("description") or ""
        for pattern, category in SIGNALS:
            match = pattern.search(description)
            if match:
                findings.append((tool.get("name", "?"), match.group(0), category))
    return findings


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    try:
        tools = load_catalog(argv[1])
    except CatalogError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    findings = scan_tools(tools)

    if not findings:
        print(f"clean: no suspicious patterns found ({len(tools)} tool(s) scanned)")
        return 0

    for name, matched, category in findings:
        print(f"SUSPECT: {name} -> matched {matched!r} ({category})")
    print(f"{len(findings)} signal(s) across {len(tools)} tool(s) — review by hand")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
