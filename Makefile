# Developer entry points. Every target mirrors a CI gate.
# SQLX_OFFLINE uses the committed .sqlx query cache, so no database is needed.
export SQLX_OFFLINE := true

# Keep in sync with `rust-version` in Cargo.toml.
MSRV := 1.94

.PHONY: help build test test-db bench-db lint fmt fmt-check doc boundaries audit msrv check run

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST)

build: ## Build (debug)
	cargo build --locked

test: ## Run the full test suite (in-memory fakes, no Postgres/Redis needed)
	cargo test --locked --all-targets
	cargo test --locked --doc

test-db: ## Tests against a real PostgreSQL (set KORGAN_TEST_DATABASE_URL, see tests/real_db.rs)
	@test -n "$$KORGAN_TEST_DATABASE_URL" || { echo "set KORGAN_TEST_DATABASE_URL"; exit 1; }
	cargo test --locked --test real_db -- --ignored --skip bench_

bench-db: ## Audit-path benchmark on a real PostgreSQL (see docs/LOAD_TESTING.md)
	@test -n "$$KORGAN_TEST_DATABASE_URL" || { echo "set KORGAN_TEST_DATABASE_URL"; exit 1; }
	cargo test --release --test real_db bench_audit_paths -- --ignored --nocapture

lint: ## Clippy with warnings as errors
	cargo clippy --locked --all-targets --all-features -- -D warnings

fmt: ## Format the code
	cargo fmt --all

fmt-check: ## Check formatting
	cargo fmt --all -- --check

doc: ## Build rustdoc with warnings as errors
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps

boundaries: ## Hexagonal boundaries and zero-panic check
	python3 scripts/check_boundaries.py

audit: ## Advisory scan of Cargo.lock (needs cargo-audit)
	cargo audit

msrv: ## Check against the declared rust-version (needs that toolchain installed)
	cargo +$(MSRV) check --locked --all-targets

check: fmt-check lint boundaries doc test ## Everything CI runs, except audit and msrv

run: ## Run the server (configure via .env, see .env.example)
	cargo run --locked -- serve
