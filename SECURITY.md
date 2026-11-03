# Security policy & responsible use

## Authorized use only

SecuScan is a dual-use security tool. Running scans against systems without explicit
permission may be unlawful. Before starting any task you must confirm you are authorized
to assess the target; plugins (and the instance as a whole) enforce a consent gate, and
the consent state is recorded with every task.

## Built-in protections

- **Consent gate** — per-plugin and/or instance-wide; task creation is refused without it.
- **Layered target policy** — global deny-list → global allow-list → plugin
  `allowed_targets`; denials are written to an admin-visible audit log.
- **Host canonicalization** — IPv4-mapped IPv6 and integer/hex IPv4 forms are normalized
  before matching; IPv4-shaped glob patterns never match hostnames.
- **Argv hardening** — no shell is ever involved; values starting with `-` are rejected
  unless a field explicitly opts in; NUL bytes rejected; argv length caps.
- **Executor isolation** — per-task temp working directories; scrubbed subprocess
  environments (platform secrets never reach wrapped tools); wall-clock timeouts;
  kill-on-cancel; output capture caps.
- **Auth** — Argon2id passwords; timing-safe login; 30/min login rate limit per IP+email;
  rotating refresh tokens (httpOnly cookie, hashed at rest, single use); revocation on
  password change; API keys hashed and shown once; RBAC (admin/scanner/viewer).
- **Input validation** — unknown fields rejected, strict patterns, select whitelists,
  integer bounds, 1 MiB request bodies, finding caps, event caps.

## JWT signing-key management

- Production startup is **fail-closed**: `SECUSCAN_ENV` defaults to
  `production`, where `SECUSCAN_JWT_SECRET` must be a persistent, randomly
  generated 64-hex-character key (32 bytes). Missing, placeholder, short,
  malformed, or obviously low-diversity values are rejected.
- `SECUSCAN_ENV=development` allows an auto-generated ephemeral signing key
  **only** when `SECUSCAN_ADDR` binds to loopback. An explicitly configured
  weak key is never accepted, even in development.
- Compose enforces the key at interpolation time and runs in production mode.
  Store the signing key in a secret manager or an ignored private `.env` file.
  Do not regenerate it on every restart. See
  [the deployment guide](docs/DEPLOYMENT.md).
- **Incident response:** if the previous publicly known Compose default was
  deployed, assume JWT signatures could have been forged. Generate a new key,
  redeploy all replicas with the same key, and revoke active refresh sessions /
  rotate other credentials as appropriate. Replacing only the signing key
  does not revoke refresh tokens stored independently in SQLite.
- The 64-hex format and basic diversity checks are **not** proof of randomness.
  Generate keys with `openssl rand -hex 32` or an equivalent CSPRNG.

## MCP agent authorization

MCP agents cannot self-approve scans. `start_scan` and
`start_people_hunter` require a human admin-issued **single-use approval
token** bound to a distinct scanner account, the target, normalized inputs,
preset, workspace, and auth profile. The REST API verifies the token,
re-runs the ordinary plugin/consent/network admission policy, atomically
consumes the token and links the approval to the resulting task audit.
Tokens expire after five minutes; a replay or changed scope is rejected.

The MCP server does not expose approval issuance. `run_robot` and
`run_sniper` are not exposed as MCP actions until they have equivalent
scope-bound human approval. See [MCP consent](docs/MCP_CONSENT.md) for the
authorization flow, test cases, and deployment assumptions.

**Remaining boundary:** a scanner API credential still has direct access
to existing REST scan endpoints outside the MCP tool interface; API keys
do not yet carry separate endpoint scopes. Isolate agent credentials and
restrict their network capabilities. Workspace membership enforcement is
a separate open hardening issue.

## Known trust boundaries

1. **DNS at admission time.** Hostname-based policy checks resolve at task creation; a
   DNS record can change after admission. For strict enforcement use IP/CIDR patterns.
   Native network scanners resolve once per host up front and probe resolved addresses.
2. **`X-Forwarded-For`** is trusted when present (for rate-limit keys). Only deploy
   behind a proxy you control, or remove the header at the edge.
3. **Wrapped tools keep their own risk profile.** nmap/nuclei/sqlmap execute with the
   permissions of the server process (inside the scrubbed environment). Deny risky
   capabilities instance-wide with `SECUSCAN_DENIED_CAPABILITIES=exploit`.
4. **Local tooling is not a sandbox.** For untrusted plugin manifests, review them
   before dropping them into `plugins/` (they cannot execute code, but they can invoke
   any binary on PATH with constructed arguments).
5. **SQLite file permissions** protect the database (including hashed tokens and
   report-job webhook secrets — the secrets must be stored verbatim to compute
   HMAC signatures, so they are not hashed like auth tokens); host the data
   directory accordingly.
6. **Webhook URLs are outbound requests made by the server.** Any scanner-role
   user can register an `http(s)://` callback and observe delivery results —
   treat the role with the same trust as scan targets (which already allow
   arbitrary network probing). Only absolute `http(s)://` URLs are accepted;
   no SSRF egress filtering is applied by design (self-hosted model).
7. **Report artifacts are stored unencrypted** on disk under the reports dir.
   They contain the same finding data as the API; protect the data directory.

## Reporting a vulnerability

Please open a private security advisory on the repository, or contact the maintainers
directly. Include reproduction steps and affected versions. We aim to respond within
72 hours. Do not test against systems you do not own while researching a report.
