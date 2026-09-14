# `dupes-core` Agent Notes

This crate owns the language-agnostic duplicate-detection pipeline. Read the workspace-level `AGENTS.md` first, then use these crate-specific constraints when editing files under `dupes-core/`.

## Scope

- Keep `dupes-core` independent from parser implementations. Do not add dependencies on `syn`, `tree-sitter`, or language-specific analyzer crates.
- Put shared data types, grouping, similarity, filtering, config, scanning, ignore-file handling, and reporter behavior here.
- Keep language-specific parsing and normalization outside this crate behind the `LanguageAnalyzer` trait.

## Design Constraints

- Preserve deterministic fingerprints: normalize data before hashing, keep group ordering stable, and avoid source-order nondeterminism in public output.
- Preserve `NormalizedNode` invariants, especially placeholder indexing and `None` sentinel child positions used by similarity and sub-unit extraction.
- Treat `Config` and `AnalysisConfig` as the shared CLI/API contract; update both tests and reporters when adding fields that affect behavior.
- Prefer structured logic over output-only fixes. For example, fix stale ignore filtering or duplicate grouping at the data layer before touching reporters.
- Read the workspace-level `DETECTOR_REPORTABILITY.md` before changing `extractor`, `text_units`, ignore filtering, or duplicate-audit policy. The detector must remain ignore-blind: extract/group first, collect pre-ignore liveness, then filter `.dupes-ignore.toml` entries from the visible report.

## Fingerprint Stability Contract

Fingerprints are content identities, and ignore entries depend on these guarantees:

- Unit and exact-group fingerprints derive only from normalized content: they survive file moves, renames, line shifts, whitespace, and changes anywhere outside the unit. They change exactly when the unit's own content changes, which is intentional — edited duplicates must resurface for review.
- Exact-group fingerprints are membership-insensitive: members may join or leave a content group without changing its fingerprint. Never derive an exact group's fingerprint from its member set or locations.
- Near-group fingerprints are composites of member fingerprints and therefore membership-sensitive. Ignore entries compensate via `member_fingerprints`: an entry whose recorded members all still appear together in one group keeps matching and stays live across membership drift. Record member fingerprints when adding near-group entries.
- Changing how fingerprints are computed (normalization, hashing, or group-fingerprint derivation) invalidates every registered `.dupes-ignore.toml` entry at once, so it is only allowed for adjudicated correctness fixes and MUST land in the same commit as a full registry migration. Casual stability improvements stay additive (new matching semantics, new recorded fields), never redefinitions.
- Registry migration procedure: run the old and new binaries over one identical registry-free corpus copy with identical flags; pair each entry to its old-regime group by fingerprint (or recorded `member_fingerprints` subset), then pair that group to its new-regime successor by member file + line locations (small slack, ranked by matched members then total location drift, same dimension, same match kind first then crossed — an exact group may honestly degrade to near); rewrite `fingerprint`/`members`/`member_fingerprints` in place, preserve every `reason` and the file header; entries with no successor mean the duplication no longer exists under the new regime and are deleted. Verify with `cleanup --dry-run` reporting `No stale entries found.` before committing.
- `cleanup --dry-run` pairs stale entries with possible successor groups by member location overlap; keep entry `members` strings in the `name (path:start-end)` shape so that pairing keeps working.

## Detector Reportability Contract

Reportability predicates may suppress globally low-signal candidate shapes, but
they must never become project-local ignore policy:

- Keep detector logic ignore-blind. Do not consult `.dupes-ignore.toml` while extracting units, deciding candidate eligibility, grouping exact duplicates, or finding near duplicates.
- Apply ignore entries only after live groups exist. `AnalysisResult::all_fingerprints` and `AnalysisResult::all_member_fingerprint_sets` must describe pre-ignore groups so `cleanup --dry-run` can prove retained entries are still live.
- Suppress only standalone low-signal candidates. A trivial return, accessor, chain tail, or declaration scaffold can be rejected as its own finding, but a larger surrounding unit/window with behavior must remain detectable.
- `.dupes-ignore.toml` is an end-user facility: in repositories that maintain one, treat it as authoritative over stale audit artifacts — if a proposed source refactor or detector refinement would stale a retained-valid entry there, stop and reclassify or ask for user adjudication. This repository's own registry holds the entries adjudicated as valid and intentional; self-corpus findings outside those classes are resolved in code or left visible. Duplicated production or test-harness logic is consolidated at its owning source, never registered as fixture duplication.
- Preserve intentional fixture duplication, including embedded parser inputs, expected typed values, and test-only `NodeMapping` configurations. Register those findings with their regression purpose instead of changing fixtures to reduce the duplicate count. Validate the full-corpus registry through `cargo dupes cleanup --dry-run`; investigate stale allowances as detection regressions or explicit contract changes rather than deleting them automatically.
- Suppression is presentation policy, not extraction policy: units and groups are tagged against the rule registry in `suppression.rs` and partitioned at report time (`--show-suppressed` reveals them, `-v` attributes them per rule); nothing detectable is dropped at extraction.
- Add positive counter-tests for behavior-bearing variants whenever adding a skip. Examples: `return Some(x)` must survive the empty-default-return skip; `return f(a + b, c)` must survive the plumbing-dispatch return skip; assertion macros must survive a message-only macro skip; iterator chains with closures must survive value-plumbing skips; implementation signatures must survive declaration-prefix skips.

Run `cargo test -p cargo-dupes --test self_corpus --test detector_coverage` before accepting any detector refinement: `consolidated_sites_stay_consolidated` runs the pinned self-corpus command (`--exclude refactor --exclude cargo-dupes/tests/fixtures --exclude code-dupes/tests/fixtures --sub-function --format json report` at the workspace root) and proves consolidated sites never re-group, while the detector-coverage pins must be updated together with any behavior flip.

## Testing

- Run `cargo test -p dupes-core` for core-only changes.
- Run `cargo test -p dupes-rust --test core_with_syn_tests` when changing `fingerprint`, `similarity`, `grouper`, `extractor`, or `node` behavior that is easier to validate with realistic Rust AST fixtures.
- Run `cargo clippy --workspace --all-targets -- -D warnings` before handing off lint-sensitive changes.
