# Multi-stage build: frontend (node) → backend (cargo) → slim runtime.
FROM node:20-slim AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM rust:1-slim AS backend
WORKDIR /build
# Install the plugins source for the CLI validation step (kept in the final image via copy below)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY plugins ./plugins
RUN cargo build --release --bin secuscan-server --bin secuscan

FROM debian:bookworm-slim AS runtime
# ca-certificates for HTTPS scanning; tini for correct signal handling.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /usr/sbin/nologin secuscan

WORKDIR /app
COPY --from=backend /build/target/release/secuscan-server ./secuscan-server
COPY --from=backend /build/target/release/secuscan ./secuscan
COPY --from=backend /build/plugins ./plugins
COPY --from=frontend /build/dist ./frontend/dist

USER secuscan
ENV SECUSCAN_ADDR=127.0.0.1:8080 \
    SECUSCAN_DB_URL=sqlite:///app/data/secuscan.db?mode=rwc \
    SECUSCAN_PLUGINS_DIR=/app/plugins \
    SECUSCAN_FRONTEND_DIR=/app/frontend/dist \
    SECUSCAN_DATA_DIR=/app/data
VOLUME ["/app/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--", "./secuscan-server"]
