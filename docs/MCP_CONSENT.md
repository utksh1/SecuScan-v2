# MCP Scan Approval Contract

SecuScan does **not** allow an MCP model to self-authorize scanning. The
`start_scan` and `start_people_hunter` tools require an opaque, one-use
approval issued separately by an authenticated administrator for a specific
scanner account and exact scan request.

## Trust boundary

- **Human approver:** a SecuScan admin logged in with a JWT. Must be a
  *different user account* from the scanner identity. API keys cannot issue
  approvals.
- **MCP scanner:** a distinct user with the `scanner` role using a
  dedicated `mcp_scan`-scoped `X-API-Key`, issued by an admin. Do not
  configure scanner JWTs, passwords, or legacy full-access API keys on the
  MCP agent. The server never exposes an approval-issuance tool.
- **API:** keeps only SHA-256 of the approval token, the approver and scanner
  user IDs, the request fingerprint, plugin/target/workspace, issuance and
  expiry timestamps, consumption time and resulting task ID.
- **Lifetime:** exactly one use, expiring after **5 minutes**. The approval
  is atomically consumed even if downstream task creation fails; ask for a
  fresh approval to retry. There is no implicit renewal or batch consent.
- **Scope:** fingerprint covers plugin ID and version, execution engine,
  capability and safety policy, normalized inputs (including target, method,
  ports and options), preset, workspace and auth profile. Changing any
  dimension invalidates the approval. The ordinary plugin and network
  admission policies run *both* at approval time and just before task
  creation.

## Scoped MCP credential issuance and revocation

Existing API keys retain the `full` scope for backwards compatibility.
They **must not** be configured on untrusted MCP agents. Administrators
should provision a separate scanner-role account (not an administrator)
and issue a restricted key with their own interactive JWT:

```http
POST /api/v1/admin/mcp-keys
Authorization: Bearer <ADMIN_JWT>
Content-Type: application/json

{
  "issued_to_user_id": "<SCANNER_USER_ID>",
  "name": "isolated-mcp-worker"
}
```

The response exposes the `scmcp_...` key **once**, with `scope:
"mcp_scan"`, the issuing administrator, and the scanner account. Store
it in the MCP worker's secret manager and configure `SECUSCAN_API_KEY`
(or the MCP CLI's `--api-key`) with this value. Do not give the worker
the scanner password, any ordinary full-access API key, or an admin JWT.

Administrators can list metadata without the secret using
`GET /api/v1/admin/mcp-keys`, and revoke a credential immediately with
`DELETE /api/v1/admin/mcp-keys/<KEY_ID>`. These management endpoints
require an **admin JWT**; no API key (even a legacy admin full-access
key) can issue or manage scoped keys.

The server checks the DB-backed `mcp_scan` scope for **every**
`X-API-Key` request to the v1 API, not only when requests originate
from the MCP client. The restricted key may call `POST /api/v1/mcp/scans`
only with the previously issued one-time approval. Read-only inspection
is available on an exact allowlist (plugin catalogue, tasks/findings,
workspaces, targets, asset inventory and selected status endpoints).
All other HTTP mutations, including direct tasks, retries, workflows,
schedules, robot and sniper execution, VPN mutations and credential
management, return HTTP 403. Supplying both `Authorization` and
`X-API-Key` is rejected rather than letting the server silently prefer
a privileged credential.

**Migration:** create a new dedicated scanner account and scoped
credential, update the MCP connector configuration, verify an approved
scan, then revoke any legacy key previously given to an agent. A DB
migration adds `scope='full'` to existing keys, so upgrades preserve
existing integrations until rotated. Revocation affects new requests;
already-started scans must be cancelled separately.

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

`run_robot` and `run_sniper` remain unavailable through MCP until
the server can approve an exact robot graph/exploit chain, target set,
credentials and testing mode. Mutation tools for triage, workspace
creation, target registration, reports, and VPN testing are also hidden
from the MCP catalogue because scoped keys cannot use them. These actions
remain accessible to appropriately authorized users through the normal
API/UI; existing read-only MCP status tools are retained.

For scheduled scans use the existing human-configured schedule API and its
re-admission policy. A one-use MCP approval never authorizes a recurring
schedule, replay or agent retry. Every new MCP scan needs a new approval.

## Limitations and operational guidance

Ordinary direct `POST /api/v1/tasks` and other scan-triggering endpoints
continue to work for legacy `full` API keys and human JWT sessions.
A scoped MCP key cannot invoke them. This is a **credential-level API
boundary**, but it does not constrain an agent that separately knows the
scanner account password, has a full-access key, or holds an unrelated
JWT. Run agent workers in network-isolated environments and provide
only the `mcp_scan` secret. Do not depend on tool descriptions for access
control.

Likewise, workspace existence checks in the shared admission pipeline are
not a complete multi-tenant membership boundary (tracked by Issue #7).
Use a separate scanner account with only approved workspace access and
restricted network policies.

Never send approval tokens in URLs. Audit approval rows and task
`options.mcp_approval_id` and `options.origin=mcp`; the raw token is never
persisted.
