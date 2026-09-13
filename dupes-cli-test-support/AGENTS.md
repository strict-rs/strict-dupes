# `dupes-cli-test-support` Agent Notes

This workspace-internal crate (`publish = false`) owns the shared integration-test support for the `cargo-dupes` and `code-dupes` binaries. Read the workspace-level `AGENTS.md` first, then use these crate-specific constraints when editing files under `dupes-cli-test-support/`.

## Scope

- Keep every helper binary-agnostic: assertions take a `CommandFactory` (`fn() -> Result<assert_cmd::Command, CliTestFailure>`) so the same test body runs against both binaries. Execution and assertion helpers return typed failures that retain native causes, command identity, captured output, and malformed report inputs; required JSON fields never silently become empty or zero values.
- Own command preparation and execution (`cargo_dupes`, `code_dupes`, `run_command`, `run_for_path`, `run_for_fixture`), fixture path resolution (`workspace_root`, `rust_fixture_path`, `code_fixture_path`), the stdout/JSON report helpers, and the `cli_support_tests!` macro that stamps the shared suite into both binaries' test crates. Pass filesystem arguments in their native encoding.
- Keep binary-specific behavior out: language detection lives in `code-dupes/tests/language.rs`, and the detector-coverage pins and self-corpus gate live in `cargo-dupes/tests/`.

## Design Constraints

- Shared cases are data: `StdoutCase` consts stamped into helper fns via `stdout_case_helpers!`. Register each case once in the appropriate named `cli_support_tests!` suite; both binaries instantiate that suite so membership stays aligned without duplicated lists or suppression markers.
- Fixture paths resolve from the workspace root: shared Rust fixtures live under `cargo-dupes/tests/fixtures/`, `code-dupes`-local fixtures under `code-dupes/tests/fixtures/`. Use `temp_copy_fixture` for ignore-file workflows so tests never write into the repo's own fixtures.
- Prefer the JSON helpers for structural assertions; `report_fingerprint` scrapes the text report only because the ignore workflow consumes the fingerprint a user would copy from that output.

## Testing

- Adjacent unit tests cover report decoding, query failures, and retained evidence. Both binaries' suites exercise command execution and fixture workflows. Run `cargo test -p dupes-cli-test-support`, `cargo test -p cargo-dupes --tests`, and `cargo test -p code-dupes --tests` after changes here.
