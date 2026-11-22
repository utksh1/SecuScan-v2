# Connecting AI agents to SecuScan (MCP setup)

SecuScan ships a Model Context Protocol (MCP) server so Claude, Cursor,
VS Code Copilot and other MCP clients can read scan results, launch
**approved** scans and triage findings. This guide covers client setup and
the governance rules every agent operates under.

## 1. Get credentials

1. Create a dedicated scanner account (never give an agent an admin):
   `POST /api/v1/auth/users` as admin, or the admin UI.
2. Issue an **API key** for that account: `POST /api/v1/auth/api-keys` —
   the key is shown once. Scope is `full`; see below for the safer
   `mcp_scan` scope.
3. Store the key in the client config (never commit it).

## 2. Client setup

### Claude Code

```bash
claude mcp add secuscan \
  --transport http \
  --header "X-API-Key: <SECUSCAN-KEY>" \
  http://127.0.0.1:8080/mcp
```

### Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "secuscan": {
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "X-API-Key": "<SECUSCAN-KEY>" }
    }
  }
}
```

### VS Code (Copilot MCP)

```json
{
  "mcp": {
    "servers": {
      "secuscan": {
        "type": "http",
        "url": "http://127.0.0.1:8080/mcp",
        "headers": { "X-API-Key": "<SECUSCAN-KEY>" }
      }
    }
  }
}
```

### stdio transport (advanced)

The server also speaks JSON-RPC 2.0 over stdio (`secuscan-mcp` binary) for
clients that require local process transports.

## 3. Governance (what an agent can and cannot do)

- **Read tools** are open to any valid credential: list/get plugins, tasks,
  findings, workspaces, robots, attack surface, reports.
- **Scan launch** requires BOTH:
  - `consent_granted: true` in the tool call, and
  - a **one-use approval token** issued by an administrator via the admin
    API, bound to the requesting user and the exact scan inputs (plugin,
    target, settings) and the plugin version/engine.
- **Scopes**: API keys issued with `mcp_scan` scope can only call the
  approved-scan route — every other mutation is refused server-side
  (exhaustive allowlist, not a blocklist).
- **Annotations**: every tool declares `readOnlyHint`/`destructiveHint`;
  compliant clients can auto-gate destructive calls.
- **Schema enforcement**: arguments are validated against the advertised
  JSON schema at dispatch — malformed calls fail before touching the API.

## 4. Approving an agent scan (admin side)

```bash
# 1. the agent calls start_scan (without a valid token it is refused)
# 2. the admin reviews the requested plugin/target/inputs and issues:
curl -X POST http://127.0.0.1:8080/api/v1/mcp/approvals \
  -H "Authorization: Bearer <ADMIN-JWT>" \
  -H "content-type: application/json" \
  -d '{"user_id":"<AGENT-USER>","plugin_id":"nmap","inputs":{"target":"10.0.0.5"}}'
# 3. the one-use token goes back to the agent for the retry
```

Approvals expire; a changed plugin version/engine or any input modification
invalidates them. Every approval issuance and consumption is audited.

## 5. Limitations

- Scan launches poll up to the tool's `timeout_seconds` (default 600) —
  long scans are better launched via the UI/API and read through
  `list_tasks`/`get_raw_output`.
- No streaming console over MCP; use `get_raw_output` after completion.
- The agent never receives credentials: it operates with your API key and
  cannot read auth profiles or VPN configs.
