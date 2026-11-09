## Summary

<!-- What does this PR change and why? Link related issues: Closes #123 -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] Checked architectural boundaries (`python3 scripts/check_boundaries.py` passes; no `axum`/`sqlx`/I/O in `domain` or `application`)
- [ ] Added tests
- [ ] Ran `cargo clippy --all-targets -- -D warnings`
- [ ] Ran `cargo fmt --check` and `cargo test`
- [ ] Updated `.sqlx/` metadata and added a migration (if SQL changed)
- [ ] Updated documentation (if behavior or configuration changed)
- [ ] No `.unwrap()` / `.expect()` / `unsafe` in production code
- [ ] Commits follow Conventional Commits

## Notes for Reviewers

<!-- Design decisions, trade-offs, security implications. -->
