# Security policy

## What this tool is

`mcp-tool-scanner` reads a `tools/list` JSON response and flags patterns that look like
hidden instructions in tool descriptions. It is a static, read-only scan: it does not
connect to a server, execute tools, or send data anywhere.

## Reporting a problem

A missed pattern (false negative) or a wrong flag (false positive) is a normal issue —
the catalog is public data, so there is nothing to keep private.

If you find something that could affect **users of this tool** — a crash triggered by a
hostile catalog, or a way to make the scanner execute input — use the private advisory
form instead:
https://github.com/7sh1d0w7x/mcp-tool-scanner/security/advisories/new

## Scope

In scope: the scanner itself, its exit-code contract, and its handling of malformed input.
Out of scope: the MCP servers whose output you scan, and the tools the scanner reports on.

## No bounty

Small project, one maintainer. No bounty, but reports are read and answered.
