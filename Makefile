# Developer entry points. Every target mirrors a CI gate.
# SQLX_OFFLINE uses the committed .sqlx query cache, so no database is needed.
export SQLX_OFFLINE := true

# Keep in sync with `rust-version` in Cargo.toml.
MSRV := 1.94

.PHONY: ci deny secrets workflows help build test test-arm64 build-arm64-musl test-db bench-db lint fmt fmt-check doc boundaries audit msrv check run

help: ## List targets
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST)

build: ## Build (debug)
	cargo build --locked

test: ## Run the full test suite (in-memory fakes, no Postgres/Redis needed)
	cargo test --locked --all-targets
	cargo test --locked --doc

test-arm64: ## Run the test suite for aarch64 under qemu-user via `cross` (needs Docker, see Cross.toml)
	cross test --locked --target aarch64-unknown-linux-gnu

build-arm64-musl: ## Static aarch64 musl release binary via `cross` (builds a target OpenSSL in the cross image, see Cross.toml)
	OPENSSL_DIR=/opt/openssl-arm64-musl OPENSSL_STATIC=1 cross build --locked --release --target aarch64-unknown-linux-musl

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

deny: ## Supply-chain bans, licenses and advisories (needs cargo-deny)
	cargo deny check

secrets: ## Secret scan of the full git history (needs gitleaks)
	gitleaks git . --config .gitleaks.toml --redact --no-banner

workflows: ## Lint GitHub Actions workflows (needs actionlint and zizmor)
	actionlint
	zizmor --no-progress .github/workflows

ci: check msrv audit deny secrets workflows ## Local equivalent of every CI and security gate

check: fmt-check lint boundaries doc test ## Everything CI runs, except audit and msrv

run: ## Run the server (configure via .env, see .env.example)
	cargo run --locked -- serve
