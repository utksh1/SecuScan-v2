.PHONY: build test fmt fmt-check clippy plugins-check frontend frontend-test verify e2e docker clean

build: frontend
	cargo build --release --workspace

test:
	cargo test --workspace --locked

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings

plugins-check:
	cargo run -q -p secuscan-cli --locked -- plugins validate ./plugins

frontend:
	cd frontend && npm ci && npm run build

frontend-test:
	cd frontend && npm ci && npm run typecheck && npm test

# Run all local static checks, then the product-surface E2E.
# Requires a local Rust toolchain, Node >= 20 and an available port 8080.
verify: fmt-check clippy test plugins-check frontend-test e2e

e2e: frontend
	cargo build --locked --release --bin secuscan-server
	node scripts/verify.mjs

docker:
	docker compose -f docker/docker-compose.yml up --build -d

clean:
	cargo clean
	rm -rf frontend/node_modules frontend/dist
