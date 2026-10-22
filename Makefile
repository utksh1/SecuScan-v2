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

# Full local verification (mirrors CI + the E2E smoke test)
verify: clippy test frontend-test frontend
	cargo run -q -p secuscan-cli -- plugins validate ./plugins
	bash scripts/e2e-smoke.sh

docker:
	docker compose -f docker/docker-compose.yml up --build -d

clean:
	cargo clean
	rm -rf frontend/node_modules frontend/dist
