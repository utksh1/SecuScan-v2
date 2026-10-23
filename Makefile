.PHONY: build test fmt clippy frontend frontend-test e2e docker clean

build: frontend
	cargo build --release --workspace

test:
	cargo test --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

frontend:
	cd frontend && npm ci && npm run build

frontend-test:
	cd frontend && npm ci && npm test

# Full local verification (mirrors CI + the Node E2E proof script)
verify: clippy test frontend-test frontend
	cargo run -q -p secuscan-cli -- plugins validate ./plugins
	node scripts/verify.mjs

docker:
	docker compose -f docker/docker-compose.yml up --build -d

clean:
	cargo clean
	rm -rf frontend/node_modules frontend/dist
