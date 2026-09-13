# `cargo-dupes` Agent Notes

This crate owns the Rust-only Cargo subcommand binary. Read the workspace-level `AGENTS.md` first, then use these crate-specific constraints when editing files under `cargo-dupes/`.

## Scope

- Keep this binary focused on CLI argument parsing and wiring `RustAnalyzer` into `dupes_core::cli::run_analysis`.
- Put shared command behavior, output formats, ignore-file commands, thresholds, and reporting logic in `dupes-core`.
- Do not add multi-language selection here; that belongs in `code-dupes`.

## Design Constraints

- Preserve Cargo subcommand expectations: users invoke this as `cargo dupes ...`.
- Keep flags aligned with shared `dupes_core::cli` types so `cargo-dupes` and `code-dupes` stay behaviorally consistent.
- Add or update fixtures under `tests/fixtures/` when CLI behavior depends on real Rust project layout, config files, ignored fingerprints, or test-code filtering.
- Treat `tests/fixtures/detector_coverage/` as frozen: its counts are pinned in `tests/detector_coverage/tests.rs`, so any fixture or detector change must update the pins in the same change. `tests/self_corpus/main.rs` gates the workspace's own code against re-grouping consolidated sites, using parsed Rust definitions to locate the protected spans.

## Testing

- Run `cargo test -p cargo-dupes --tests` for CLI changes.
- Run `cargo test -p dupes-rust --lib` if changes expose Rust analyzer assumptions.
- Run `cargo clippy --workspace --all-targets -- -D warnings` before handing off lint-sensitive CLI work.
