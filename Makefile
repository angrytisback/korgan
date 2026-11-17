# Developer entry points. Every target mirrors a CI gate.
# SQLX_OFFLINE uses the committed .sqlx query cache, so no database is needed.
export SQLX_OFFLINE := true

# Keep in sync with `rust-version` in Cargo.toml.
MSRV := 1.94

.PHONY: help build test lint fmt fmt-check doc boundaries audit msrv check run

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST)

build: ## Build (debug)
	cargo build --locked

test: ## Run the full test suite (in-memory fakes, no Postgres/Redis needed)
	cargo test --locked --all-targets
	cargo test --locked --doc

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
