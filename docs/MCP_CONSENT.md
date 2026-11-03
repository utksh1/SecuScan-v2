# MCP Scan Approval Contract

SecuScan does **not** allow an MCP model to self-authorize scanning. The
`start_scan` and `start_people_hunter` tools require an opaque, one-use
approval issued separately by an authenticated administrator for a specific
scanner account and exact scan request.

## Trust boundary

- **Human approver:** a SecuScan admin logged in with a JWT. Must be a
  *different user account* from the scanner identity. API keys cannot issue
  approvals.
- **MCP scanner:** a distinct user with the `scanner` role, preferably using
  a dedicated `X-API-Key` credential (or a JWT for that scanner). The MCP
  server never exposes an approval-issuance tool.
- **API:** keeps only SHA-256 of the approval token, the approver and scanner
  user IDs, the request fingerprint, plugin/target/workspace, issuance and
  expiry timestamps, consumption time and resulting task ID.
- **Lifetime:** exactly one use, expiring after **5 minutes**. The approval
  is atomically consumed even if downstream task creation fails; ask for a
  fresh approval to retry. There is no implicit renewal or batch consent.
- **Scope:** fingerprint covers plugin ID, normalized inputs (including
  target, method, ports, options), preset, workspace and auth profile.
  Changing any meaningful dimension invalidates the approval. The ordinary
  plugin and network admission policies run *both* at approval time and just
  before task creation.

## Example: approve a local lab scan

First, an administrator creates a separate scanner-role account and obtains
its `user_id` using normal SecuScan administration. Configure the MCP server
with **that scanner account**, not the admin account. The following uses
placeholder values; do not paste real JWTs or approval tokens in logs or
issue comments.

An administrator sends the exact request through a trusted client/UI:

```http
POST /api/v1/mcp/scan-approvals
Authorization: Bearer <ADMIN_JWT>
Content-Type: application/json

{
  "issued_to_user_id": "<SCANNER_USER_ID>",
  "scan": {
    "plugin_id": "port-scanner",
    "inputs": {"target": "127.0.0.1", "ports": "8080"},
    "consent_granted": true
  }
}
```

The response includes a random `approval_token`, an `approval_id` for
auditing, expiry, target and intended scanner. Pass the token **privately**
to the `start_scan` MCP tool:

```json
{
  "plugin_id": "port-scanner",
  "target": "127.0.0.1",
  "inputs": {"ports": "8080"},
  "consent_granted": true,
  "approval_token": "<SINGLE_USE_APPROVAL_TOKEN>"
}
```

MCP calls `POST /api/v1/mcp/scans` with the scan and approval token.
It cannot generate or renew approval itself. The API verifies that the
calling scanner account, plugin, normalized inputs, workspace and preset all
match. It returns HTTP 403 on missing, expired, mismatched or replayed tokens.

## Workflow and exploit tools

`run_robot` and `run_sniper` are intentionally **not exposed** through
MCP until the server can approve an exact robot graph/exploit chain, target
set, credentials and testing mode. They remain accessible to appropriately
authorized users through the normal API/UI. `get_robot_run` and
`get_sniper_run` stay read-only MCP tools.

For scheduled scans use the existing human-configured schedule API and its
re-admission policy. A one-use MCP approval never authorizes a recurring
schedule, replay or agent retry. Every new MCP scan needs a new approval.

## Limitations and operational guidance

The ordinary direct `POST /api/v1/tasks` endpoint retains its pre-existing
consent workflow for human/API clients, and existing API keys do not yet have
per-endpoint scopes. Therefore a scanner credential leaked to an agent that
also has arbitrary HTTP tooling can still invoke the ordinary API. **Treat
MCP credentials as sensitive scanner-level credentials, isolate the agent,
and avoid giving it unrestricted network request tools or admin credentials.**
A future scoped-API-key change should prohibit direct task creation by
MCP-only keys. This feature protects the MCP tool workflow; it is not a
substitute for fully isolated credentials or network-level scanning controls.

Likewise, workspace existence checks in the shared admission pipeline are
not a complete multi-tenant membership boundary (tracked by Issue #7).
Use a separate scanner account with only approved workspace access and
restricted network policies.

Never send approval tokens in URLs. Audit approval rows and task
`options.mcp_approval_id` and `options.origin=mcp`; the raw token is never
persisted.
