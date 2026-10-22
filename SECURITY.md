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
