# MCP Check

[![MCP Check](https://mcp.nischaldhakal.com.np/badge/jh878eqit93e.svg)](https://mcp.nischaldhakal.com.np/r/jh878eqit93e)
[![npm](https://img.shields.io/npm/v/@dcodenischal/mcp-check?label=npm&color=cb3837)](https://www.npmjs.com/package/@dcodenischal/mcp-check)
[![MCP Check MCP connector](https://glama.ai/mcp/connectors/np.com.nischaldhakal/mcp-check/badges/score.svg)](https://glama.ai/mcp/connectors/np.com.nischaldhakal/mcp-check)
[![CI](https://github.com/DcodeNischal/mcp-check/actions/workflows/ci.yml/badge.svg)](https://github.com/DcodeNischal/mcp-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Grade any [MCP](https://modelcontextprotocol.io) server against the spec, and find out exactly how to
fix what's wrong.** Free, open source, no sign-up.

MCP Check connects to a server the way a real client would, then grades its protocol, tools, OAuth setup,
security and speed from A to F, with a plain fix for every problem. It also grades every public server in
the [official MCP Registry](https://registry.modelcontextprotocol.io) and keeps a searchable directory of
the results.

[![A report on MCP Check](docs/images/report.png)](https://mcp.nischaldhakal.com.np/r/jh878eqit93e)

## Use it

**On the web:** paste a server URL at **[mcp.nischaldhakal.com.np](https://mcp.nischaldhakal.com.np)**.
You can sign in with OAuth for protected servers, try every tool in the page, and share the report.

**In your agent:** MCP Check is an MCP server too. Add it to Claude, Cursor, VS Code or any MCP client:

```json
{ "mcpServers": { "mcp-check": { "url": "https://mcp.nischaldhakal.com.np/mcp" } } }
```

Then ask "check https://mcp.example.com/mcp" or "find an MCP server that sends email". It's listed in the
official registry as `np.com.nischaldhakal/mcp-check`.

**In your terminal**, including servers on `localhost`:

```bash
npx @dcodenischal/mcp-check https://mcp.example.com/mcp
```

**In CI**, failing the build when the grade drops:

```yaml
- uses: DcodeNischal/mcp-check@v1
  with:
    url: http://localhost:3000/mcp
    min-grade: B
```

More options for the CLI and the Action are in [cli/README.md](cli/README.md) and [action.yml](action.yml).

## What a report looks like

```
MCP Check  https://mcp.example.com/mcp

  Grade A  92/100  spec 2026-07-28 (stateless HTTP) · 3 tools · checked in 1.3s

  ! Tools say whether they change things (Tools)
    0 of 3 tools declare readOnlyHint or destructiveHint. Without them, clients must assume every tool may be destructive and ask users to confirm each call.
    Fix: Add annotations: { readOnlyHint: true } to tools that only read, and destructiveHint to tools that delete or overwrite.

  16 passed · 1 warning · 0 failed
```

## What it checks

| Area | Checks |
|---|---|
| Protocol | Which revision the server speaks (2026-07-28, Streamable HTTP, or the deprecated HTTP+SSE), server info, version negotiation, content types, notifications, `resultType`, and how it answers unknown methods |
| Tools | Descriptions, valid input and output schemas, described parameters, names, `readOnlyHint` / `destructiveHint`, how much of an agent's context the tool list takes, and how it answers calls to unknown tools |
| Auth | The `401` challenge, protected resource metadata (RFC 9728), authorization server metadata with a matching issuer, PKCE S256, and client registration (Client ID Metadata Documents or DCR) |
| Security | HTTPS, rejecting requests from other websites' origins, and not leaking stack traces or file paths in errors |
| Speed | Time to connect and to list tools |

Every rule traces back to the spec ([docs/spec-notes.md](docs/spec-notes.md)). Rules the spec says
servers MUST follow are failures when missed; see [how grading works](docs/architecture.md#grading).

## Put the grade on your README

Share a report from the website and you'll get a badge for your server that updates whenever it's
re-checked:

```markdown
[![MCP Check](https://mcp.nischaldhakal.com.np/badge/<id>.svg)](https://mcp.nischaldhakal.com.np/r/<id>)
```

## The directory

[mcp.nischaldhakal.com.np/servers](https://mcp.nischaldhakal.com.np/servers) lists every public server
from the official MCP Registry, plus servers people share, each re-checked weekly.

- **Search** by name, tool or meaning: "send email" also finds email servers that never say "send".
- **Alerts:** every server has a [feed](https://mcp.nischaldhakal.com.np/feed.xml), and you can add a
  webhook (Slack and Discord included) that fires when a grade changes.
- **Owners** can verify their server for a verified tick, or remove it, by serving one line at
  `https://<their-domain>/.well-known/mcp-check.txt`.

## Privacy and safety

- Tokens and custom headers are used for one check and never stored, logged or shown in reports. A report
  made with them is never listed and never replaces a server's public page; sharing it gives a random private
  link that's hidden from search engines and expires after 30 days.
- Online checks only contact public HTTPS addresses, including any URL a server hands back during OAuth
  discovery. Private and local addresses are refused (the CLI allows `localhost` on purpose).
- Grades can't be faked: a report is only saved with a signature from the Worker that produced it.
- Every request identifies itself as `MCP-Check/0.1 (+https://mcp.nischaldhakal.com.np)`.

## MCP Check and the MCP Inspector

The official [MCP Inspector](https://github.com/modelcontextprotocol/inspector) is the tool for poking at
a server interactively while you build it. MCP Check is for finding out what's wrong with a server and
keeping it right: a graded report against the spec with fixes, checks in CI, and a directory to compare
against. They work well together.

## Contributing

Bug reports, false-positive reports and new checks are all welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to run it locally and add a check, and
[docs/architecture.md](docs/architecture.md) for how it all fits together. Security issues: see
[SECURITY.md](SECURITY.md).

## License

MIT. Made by [Nischal Dhakal](https://nischaldhakal.com.np).
