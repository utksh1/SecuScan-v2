# Deployment guide

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `SECUSCAN_ADDR` | `0.0.0.0:8080` | Listen address. Use `127.0.0.1:8080` for local-only. |
| `SECUSCAN_DB_URL` | `sqlite://./data/secuscan.db?mode=rwc` | SQLite URL; the directory is created. |
| `SECUSCAN_ENV` | `production` | Fail-closed startup. Set `development` explicitly for loopback-only ephemeral-secret development. |
| `SECUSCAN_JWT_SECRET` | **Required** | A persistent, randomly generated 64-character hex key (32 bytes). Missing/weak values abort startup in production. |
| `SECUSCAN_PLUGINS_DIR` | `./plugins` | Plugin manifest directory. |
| `SECUSCAN_FRONTEND_DIR` | `./frontend/dist` | Built SPA served by the API. |
| `SECUSCAN_DATA_DIR` | `./data` | Default data root. |
| `SECUSCAN_REPORTS_DIR` | `<data>/reports` | Where async report-job artifacts are written. |
| `SECUSCAN_ADMIN_EMAIL` | `admin@secuscan.local` | First-run admin email. |
| `SECUSCAN_ADMIN_PASSWORD` | *random, printed once* | First-run admin password. |
| `SECUSCAN_ALLOW_REGISTER` | `false` | Public registration toggle. |
| `SECUSCAN_COOKIE_SECURE` | `false` | Set `true` when serving over HTTPS. |
| `SECUSCAN_CORS_ORIGIN` | *(unset)* | Set for a split-domain frontend (e.g. `https://scans.example.com`). |
| `SECUSCAN_DENIED_CAPABILITIES` | *(empty)* | Comma list (e.g. `exploit,docker`) — plugins needing these are refused. |
| `SECUSCAN_MAX_CONCURRENT_TASKS` | `8` | Global running-task cap. |
| `SECUSCAN_SCHEDULE_TICK_SECS` | `30` | Scheduler wake-up interval for recurring scans (seconds). |
| `RUST_LOG` | `secuscan=info,tower_http=warn` | Logging. |

## JWT signing key: mandatory for deployments

SecuScan starts in `SECUSCAN_ENV=production` unless `development` is
explicitly selected. **Production does not generate fallback JWT secrets.**
The configured key must be 64 hexadecimal characters representing 32 bytes.
The validator also rejects obviously repeated/low-diversity keys. These format
checks cannot prove entropy: always generate keys with a cryptographic tool.

Generate and persist a key **once**, in an ignored, permission-restricted
environment file at the repository root:

```bash
umask 077
# Only initialize this file if it does not exist. Reuse it on every restart.
if [ ! -e .env ]; then
  printf 'SECUSCAN_JWT_SECRET=%s\n' "$(openssl rand -hex 32)" > .env
fi
chmod 600 .env
```

If `.env` already exists, ensure its `SECUSCAN_JWT_SECRET` entry is present,
nonempty, and matches the requirement. Do not paste real keys into issue comments
or GitHub Actions logs, and do not commit `.env` (`.gitignore` excludes it).
Use your deployment secret manager rather than a file when possible, but provide
the **same key** to each server replica and after every restart.

Changing this signing key invalidates previously issued access JWTs. Rotating the
signing key alone does *not* necessarily revoke independently stored refresh
tokens; follow the authentication incident-response procedures when a key may
have been exposed. The former Compose placeholder
`change-me-openssl-rand-hex-32` is public and must **never** be used.

## Build & run (from source)

```bash
cargo build --release
cd frontend && npm ci && npm run build && cd ..
set -a
. ./.env
set +a
SECUSCAN_ENV=production SECUSCAN_ADMIN_PASSWORD='choose-a-strong-admin-password' \
  ./target/release/secuscan-server
```

The server serves the API at `/api/v1` and SPA at `/`. If the JWT key is
missing or malformed, startup logs a configuration error and exits with status 1
before creating the database or listening for traffic.

For **local development only** you may intentionally use an ephemeral key:

```bash
SECUSCAN_ENV=development SECUSCAN_ADDR=127.0.0.1:8080 \
  ./target/debug/secuscan-server
```

This dev fallback is rejected on non-loopback bindings. Sessions do not survive
restarts in this mode. A configured JWT key is validated in both environments.

## Docker Compose

```bash
# Initialize .env once using the snippet above.
docker compose --env-file .env -f docker/docker-compose.yml config --quiet
docker compose --env-file .env -f docker/docker-compose.yml up --build -d
```

Compose requires a nonempty `SECUSCAN_JWT_SECRET` **during interpolation**;
it will refuse to start without one. The application additionally rejects
bad/weak keys on startup. Keep `.env` persistent when upgrading or restarting.
The image is multi-stage (Node → Cargo → slim runtime), stores SQLite in a
volume, and runs as a non-root user with ports bound to `127.0.0.1` by default.

## Reverse proxy (HTTPS)

```
server {
    listen 443 ssl http2;
    server_name scans.example.com;
    ssl_certificate     /etc/letsencrypt/live/scans.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/scans.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Connection "";   # SSE: no buffering
        proxy_buffering off;
        proxy_read_timeout 3600s;         # long scans keep the console open
    }
}
```

Behind a proxy, set `SECUSCAN_COOKIE_SECURE=true` and `SECUSCAN_CORS_ORIGIN` only if the
frontend is served from a different origin.

## Operations notes

- **Backups**: the entire state is `data/secuscan.db` (+ WAL files). Stop the server or
  use `sqlite3 ... ".backup ..."` for consistent copies.
- **Logs**: structured to stdout; policy-blocked targets also live in the admin audit
  view (`GET /api/v1/admin/audit`).
- **Upgrades**: migrations run automatically at startup. Orphaned tasks from an unclean
  shutdown are marked failed at boot.
- **Scaling**: this is a single-node, local-first tool by design. The task executor is
  already decoupled behind `secuscan-exec`; multi-node workers are a roadmap item.


## Out-of-band (OOB) blind-vulnerability detection

Set `SECUSCAN_PUBLIC_URL` to the base URL scan targets can reach
(`https://oob.example.com` publicly, or the VPN-reachable address for internal
scans). It is required by the HTTP Request Logger and XSS Exploiter and arms
the website scanner's blind SSRF/XXE probes — without it those tools fail
loudly instead of emitting dead callbacks.

OOB hits are recorded at `/api/v1oob/:secret` (no auth; anyone with the
unguessable 16-hex secret can hit it), correlated to the originating task via
the per-scan marker, and automatically open a validated finding. Each handler
stores at most 500 hits (further callbacks get HTTP 429). Reverse proxies must
forward the OOB path unchanged and must not strip `Sec-Fetch-Dest` headers.
