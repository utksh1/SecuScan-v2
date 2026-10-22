# Deployment guide

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `SECUSCAN_ADDR` | `0.0.0.0:8080` | Listen address. Use `127.0.0.1:8080` for local-only. |
| `SECUSCAN_DB_URL` | `sqlite://./data/secuscan.db?mode=rwc` | SQLite URL; the directory is created. |
| `SECUSCAN_JWT_SECRET` | *ephemeral* | **Set in production** or sessions die on every restart. |
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
| `RUST_LOG` | `secuscan=info,tower_http=warn` | Logging. |

## Build & run (from source)

```bash
cargo build --release
cd frontend && npm ci && npm run build && cd ..
SECUSCAN_JWT_SECRET=$(openssl rand -hex 32) \
SECUSCAN_ADMIN_PASSWORD=change-me \
./target/release/secuscan-server
```

The single binary serves the API at `/api/v1` and the SPA at `/`.

## Docker

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

The image is a multi-stage build (node → cargo → slim runtime), stores the database in a
volume, and runs as a non-root user. Ports are bound to `127.0.0.1` by default.

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
