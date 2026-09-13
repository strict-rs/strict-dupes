# `dupes-rust` Agent Notes

This crate owns Rust parsing and Rust-specific normalization through `syn`. Read the workspace-level `AGENTS.md` first, then use these crate-specific constraints when editing files under `dupes-rust/`.

## Scope

- Keep `syn`-dependent logic in this crate. Do not move Rust parser assumptions into `dupes-core`.
- Use `parser.rs` for `CodeUnit` extraction and test-code tagging, and use `normalizer/` for `syn` AST to `NormalizedNode` conversion.
- Keep public analyzer behavior exposed through `RustAnalyzer`; shared CLI behavior belongs in `dupes-core::cli`.

## Design Constraints

- Preserve placeholder canonicalization across renamed identifiers and across sub-unit extraction.
- Keep signatures and bodies normalized separately so fingerprints remain stable for functions, methods, closures, impl blocks, and trait impl blocks.
- Method names are preserved as `Token` leaves in `MethodCall` normalization (method-name preservation, pinned by `method_call_fingerprint_pin`); changing that redefines fingerprints and requires the registry-migration procedure in `dupes-core/AGENTS.md`.
- Keep behavior shared between `CodeUnitExtractor` and `SubUnitExtractor` in the stamped macros (`with_test_context_method!`, `visit_item_mod_with_test_context!`) and the `ImplNaming`/`item_fn_is_test` helpers instead of duplicating method bodies across the two extractors.
- When adding syntax support, update both normalizer coverage and parser extraction tests if the construct affects line ranges, code-unit kind, or test-code detection.
- Adapt `syn` 3 at this boundary: match-arm guards reside in `Pat::Guard`, reference-receiver mutability belongs to `ReceiverKind::Reference`, closures expose `inputs_begin`, and trait-impl metadata carries `(Path, For)`. Preserve the detector's existing normalized child ordering when translating these parser shapes.

## Testing

- Run `cargo test -p dupes-rust --lib` for normalizer and parser unit tests.
- Run `cargo test -p dupes-rust --test core_with_syn_tests` for cross-core behavior backed by Rust fixtures.
- Run `cargo test -p cargo-dupes --tests` when Rust analyzer output changes CLI-visible behavior.
