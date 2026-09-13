# Detector Reportability Policy

This document defines when `cargo-dupes` and `code-dupes` suppress a candidate duplicate and how suppression surfaces. Suppression is presentation policy, not extraction policy: every candidate unit and window is extracted, tagged against a rule registry, grouped, and kept; the default report hides tagged groups, `--show-suppressed` reveals them, and `-v` attributes them per rule. Nothing detectable is unrecoverable.

The policy applies to candidate units and windows, not to arbitrary code inside a larger unit. A low-signal shape may be suppressed as its own finding, but the surrounding function, branch, token window, or line window must remain eligible when it contains real duplicated behavior.

This policy is intentionally narrower than ignore policy: the detector stays ignore-blind, while `.dupes-ignore.toml` is a per-project end-user facility applied after detection (see Registry Framing).

## Pipeline Contract

```text
extract units and windows        (every candidate is emitted; nothing is dropped at extraction)
tag units against the registry   (dupes-core/src/suppression.rs; first matching enabled rule)
group exact and near duplicates  (over the full population, suppressed included)
partition groups                 (suppressed iff ALL members are tagged; mixed groups stay visible)
apply group-level rules as tags  (chain coverage, AST coverage, overlap containment); annotate coverers
collect pre-ignore liveness      (visible and suppressed populations)
apply `.dupes-ignore.toml`       (filters both populations; removals counted, never shown)
compute stats and render         (default body = visible groups; --show-suppressed adds tagged groups; -v adds per-rule attribution)
```

Guarantees this ordering preserves:

- Tagging never consults the ignore registry, so a detector refinement cannot silently hide a registry-protected duplicate and `cleanup --dry-run` can prove ignored entries still correspond to live detector output.
- Liveness means detected-not-visible: `AnalysisResult::all_fingerprints` and `all_member_fingerprint_sets` describe pre-ignore groups across both populations.
- A group is suppressed only when **all** members are tagged. Mixed groups stay visible with their tagged members marked `[suppressed: <rule>]`, so partial noise never hides a real cross-cutting duplicate.
- `total_code_units` and `total_lines` count the full extracted population (suppressed included); duplication percentages and `check` thresholds are computed from visible groups only.

## Suppression Rule Registry

Defined in `dupes-core/src/suppression.rs`. All rules are enabled by default. Toggling: config (`dupes.toml` or `[package.metadata.dupes]`) via `[suppress] disable = [...] / enable = [...]`, and repeatable CLI flags `--disable-rule <RULE_ID>` / `--enable-rule <RULE_ID>` (CLI enable overrides config disable). Unknown rule IDs warn into the report's warnings, never error. Under `-v`, stats attribute suppression per rule: unit-level rules count units, group-level rules count groups.

| Rule id | Level | Action | Dimensions | Shape |
|---|---|---|---|---|
| `ast.setter-returning-self` | Unit | Suppress | ast | builder setter: field assignment or simple mutation followed by `self` |
| `ast.forwarding-accessor` | Unit | Suppress | ast | single method call forwarding simple values |
| `ast.boolean-projection` | Unit | Suppress | ast | bare boolean combination of simple projections |
| `ast.comparator-adapter` | Unit | Suppress | ast | closure of `key(a).cmp(&key(b))` shape (closure kind only) |
| `sub.no-structure` | Unit | Suppress | sub_ast | sub-unit without bindings, control flow, calls, or arithmetic |
| `sub.trivial-predicate` | Unit | Suppress | sub_ast | comparison/boolean of simple values (currently unreachable, see note) |
| `sub.empty-default-return` | Unit | Suppress | sub_ast | guard returning an empty or default construction |
| `sub.message-only-macro` | Unit | Suppress | sub_ast | branch that only writes a message (print/println/eprint/eprintln/write/writeln) |
| `sub.value-plumbing` | Unit | Suppress | sub_ast | call or method chain that only shuttles simple values, including single-call dispatch returns |
| `sub.covered-by-chain` | Unit | Suppress | sub_ast | if-branch whose owning if-chain grouped as a whole |
| `token.import-scaffold` | Unit | Suppress | token_normalized, token_raw | import/module scaffolding windows |
| `token.chain-tail` | Unit | Suppress | token_normalized, token_raw | detached fluent-chain fragments |
| `token.signature-prefix` | Unit | Suppress | token_normalized, token_raw | doc/attr + unfinished multi-line signature prefixes |
| `token.declaration-scaffold` | Unit | Suppress | token_normalized, token_raw | type declaration scaffolding and field-like rows |
| `token.match-table-prefix` | Unit | Suppress | token_normalized, token_raw | windows cut part-way through simple match-arm tables |
| `token.low-signal` | Unit | Suppress | token_normalized, token_raw | the meaningful/unique/behavior scoring fall-through |
| `line.import-scaffold` | Unit | Suppress | line | import/module scaffolding windows |
| `line.chain-tail` | Unit | Suppress | line | detached fluent-chain fragments |
| `line.declaration-signature-prefix` | Unit | Suppress | line | declaration-side `fn` signature prefixes (terminating `;`) |
| `line.low-signal` | Unit | Suppress | line | the eligibility scoring fall-through |
| `line.declaration-stanza` | Unit | **Admit** | line | uniform doc/attr/field stanza windows admitted across blank-separated declaration blocks |
| `line.builder-chain-run` | Unit | **Admit** | line | windows made entirely of complete single-line builder steps |
| `group.covered-by-ast` | Group | Suppress | token_normalized, token_raw, line | token/line group fully covered by one AST/sub-AST group |
| `group.overlap-contained` | Group | Suppress | token_normalized, token_raw, line | window group contained (≥0.8) within a wider same-dimension group |

As-built notes:

- `sub.trivial-predicate` is currently unreachable with the present predicate set: a comparison whose children are all simple values has no reportable structure, so `sub.no-structure` fires first, and a structured comparison fails the all-children-simple test. The rule stays registered so the attribution surface is stable if the predicates ever diverge.
- Attribution shadowing: simple field comparators (`|a, b| a.f.cmp(&b.f)`) attribute to `ast.forwarding-accessor` because that check precedes the comparator shape; `ast.comparator-adapter` catches call-based adapters (`|a, b| key(a).cmp(&key(b))`). The suppression outcome is identical either way; only the attributed rule differs, and the detector-coverage harness pins it.

## Admission Rules

Admission rules are named carve-outs that turn an otherwise-suppressed window into a fully visible candidate. Disabling an admission rule reverts its windows to their base suppression (typically `line.low-signal` or `line.chain-tail`). Only suppressions appear in suppressed stats; admissions exist in the registry solely for toggling.

### `line.declaration-stanza`

Blank lines are hard concept boundaries for line windows, with one structural exception: adjacent blank-separated segments coalesce when the gap is exactly one blank line, both sides are declaration-stanza segments, and the first segment has not closed its declaration with a lone `}`. A declaration-stanza segment has the structural anatomy of a declaration block, evaluated in order: a comment/attribute prelude, at most one type-header row (`struct X {` and friends), uniform stanza rows, and at most one trailing lone `}`. Prelude-only segments (comment banners, bare attributes) and lone braces never qualify; `use`/`mod` rows and brace-only lines are never stanza rows. Documentation and attributes remain stanza rows when their text contains words such as `for`, `return`, or `fn`; executable rows still prevent coalescing.

Windows over a coalesced block are admitted when every line is stanza-shaped (doc comment, attribute, or structured `key: value` row), at least two lines are structured rows, and the window carries at least four unique terms. Windows containing the type header or the closing brace are not stanza-shaped and fall through to base classification, so coalescing adjacent blocks can never stitch windows across two types.

This is the recovery channel for cross-file clap-style CLI structs and blank-spread derive field tables — real copy-paste even though no line carries behavior.

### `line.builder-chain-run`

A window is admitted when **every** line is a complete single-line builder step: `.ident(args)` with balanced parens entirely on the line, optionally `,`/`;` terminated. Parentheses inside complete single- or double-quoted arguments are content; escaped quotes do not close those arguments. Detached tails and windows mixing receivers or other lines keep their `line.chain-tail` suppression.

### Comment Stripping Is Quote-Aware

Line normalization strips `/* ... */` spans with comment state tracked across lines, and marker detection is quote-aware: a `/*` or `*/` inside a quote span that closes on the same line is content, and a `//` or `#` line comment turns the rest of the line into prose. Without this, one quoted `"/*"` opens a phantom block comment that runs to the next stray `*/`, blinding the line dimension to everything in between — a single quoted marker can silently remove most of a file from line segmentation. Real block comments still strip to empty lines and stay concept boundaries. Known naive remainders, mirroring the token lexer's: quote spans pair only on a single line (a `/*` inside the body of a multi-line string still reads as a comment opener) and unclosed quotes stay punctuation. Pinned by `comment_marker_lines_do_not_blind_line_windows`, `strip_block_comments_tracks_comment_state_across_lines`, and `strip_block_comments_keeps_quoted_and_prose_markers`.

## Token Lexing Profiles

Token windows are anchored: each blank-line-separated segment yields exactly one window (the shortest prefix meeting the token and line minimums), a deterministic function of the segment content alone, so identical duplicated segments always produce identical windows and edits elsewhere in the file cannot re-cut them.

That stability holds only if segmentation itself is stable, which makes quote lexing load-bearing. The tokenizer selects a quote profile by file extension: the default pairs `"`, `'`, and `` ` `` naively; **Rust sources lex `'` as a quoted token only for char-literal shapes that close on the same line (`'X'`, `'\n'`, `'\u{10FFFF}'`) and treat every other tick — lifetimes, loop labels, prose apostrophes in comments — as punctuation.** Without the Rust profile, one unpaired apostrophe opens a phantom multi-line "string" running to the next apostrophe anywhere in the file, bridging blank lines and silently removing whole spans — easily an entire test module — from token segmentation, with the blindness re-dealt by every edit that changes tick parity. Pinned by `lifetime_ticks_do_not_blind_token_windows` and `comment_apostrophes_do_not_bridge_token_segments`.

Known naive remainders, accepted and documented rather than silently relied on: Rust raw strings (`r#"…"#`) pair at the first interior `"`; Python triple quotes lex as an empty string plus a quote-to-quote span (approximately right for apostrophe-free docstrings); comments are tokenized like code, so a doc-comment-led window can pair on comment shape alone (normalized comment words are uniform `IDENT`s).

## Valid Suppressions

These boundaries carry the per-rule positive/negative examples. When changing any of them, update the negative test, the positive counter-test, and the detector-coverage pins together.

### Trivial Guard Returns (`sub.empty-default-return`)

Suppress guard branches whose only work is returning an empty/default/projection value:

```rust
if items.is_empty() {
    return Vec::new();
}
```

```rust
if missing {
    return Config::default();
}
```

Do not suppress returns that wrap or compute meaningful values:

```rust
if !text.is_empty() {
    return Some(text);
}
```

```rust
if invalid {
    return Err(format!("bad field: {field}"));
}
```

### Dispatch Returns (`sub.value-plumbing`, Return arm)

Suppress branches whose body is one dispatch call forwarding plumbing arguments — exactly one `Call` child with a callee and at least two arguments, all value plumbing:

```rust
if mapping.if_kinds.contains(kind) {
    return normalize_if(node, source, mapping, ctx);
}
```

Do not suppress two-child calls (`return Some(x)`, `return NormalizedNode::leaf(kind)`) or calls with any computed argument (`return f(a + b, c)`); both stay reportable, pinned by `return_some_value_stays_reportable` and `return_with_computed_argument_stays_reportable`.

### Message-Only Macro Branches (`sub.message-only-macro`)

Suppress branches whose only effect is printing/writing a status message (`print`, `println`, `eprint`, `eprintln`, `write`, `writeln`). Do not suppress assertion, panic, or structured diagnostic macros (`assert_eq!`, `panic!`, `tracing::warn!`): they encode invariants and oracles.

### Value-Plumbing Call and Method Chains (`sub.value-plumbing`)

Suppress standalone sub-AST fragments that only shuttle simple values through calls, method calls, references, or value macros (`Box::new(RustAnalyzer::new())`, `files.push(path.to_path_buf())`). Do not suppress chains containing callback logic, closures, bindings, branching, or arithmetic — a pipeline with callback logic is a real refactorable shape. Do not broadly suppress call-rooted top-level functions.

### Builder Setters (`ast.setter-returning-self`)

Suppress whole top-level methods whose body is a builder-style mutation followed by `self` — **both** shapes:

```rust
pub fn with_resolver(mut self, resolver: Resolver) -> Self {
    self.resolver = Some(resolver);
    self
}
```

```rust
pub fn skip(mut self, kinds: &[&str]) -> Self {
    self.skip_kinds.extend(kinds.iter().map(ToString::to_string));
    self
}
```

Do not suppress setters that validate, transform, branch, fail, or carry closure-bearing arguments (`self.f.extend(items.iter().map(|x| x * 2)); self` stays reportable).

### Trivial-Body Size Cap

No top-level shape rule (`ast.*`) fires on a body at or above `TRIVIAL_BODY_MAX_NODES` normalized nodes. "Trivial" is bounded by size: a large boolean projection is a visible duplicate, not noise, while real setters and accessors sit well under the cap. Both sides are pinned end-to-end by the detector-coverage fixture (the large `ranges_overlap`/`spans_collide` pair stays visible; the small trivial shapes stay tagged).

### Simple Accessors and Forwarders (`ast.forwarding-accessor`)

Suppress whole top-level methods whose body is pure projection or simple forwarding (`self.percent_of(self.exact)`, `&self.name`). Do not suppress methods that compute policy, normalize data, cache, validate, branch, or call into callback-bearing chains.

### Boolean Projections (`ast.boolean-projection`) and No-Structure Blocks (`sub.no-structure`)

Suppress bare boolean combinations of simple projections (`first == '_' || first.is_ascii_alphabetic()`) below the size cap, and sub-AST candidates made only of placeholders/projections. Do not suppress branches with bindings, arithmetic, control flow, calls with callbacks, or computed returns.

### Comparator-Adapter Closures (`ast.comparator-adapter`)

Suppress standalone closure bodies that only adapt keys into comparisons (`|a, b| key(a).cmp(&key(b))`). Do not suppress closures with callback pipelines or internal logic. See the attribution-shadowing note above.

### Chain Coverage (`sub.covered-by-chain`) — release on no match

When consecutive `if` statements form a chain, the chain is emitted as one unit and each branch is emitted linked to its owning chain. Branch groups are tagged covered **only when every member's owning chain is itself a member of an exact IfChain group** — duplication of the branches is then fully explained by duplication of the whole chains. Branches of chains with no duplicate partner are released to full visibility, so cross-file branch-shape repetition (option-override clusters) stays detectable even when the chains differ as wholes. Because the condition quantifies over every member, a group mixing covered and released members stays wholly visible.

### Token/Line Scaffolding (`*.import-scaffold`, `*.chain-tail`, `*.signature-prefix`, `token.declaration-scaffold`, `token.match-table-prefix`, `*.low-signal`)

These shapes carry over the pre-registry detector's semantics: suppress import/module blocks, detached chain tails, doc/attr signature prefixes (line windows keep implementation-side prefixes whose lookahead opens a `{` body and suppress declaration-side prefixes terminating in `;`), type-declaration scaffolding token windows, cut match-table prefixes, and the scoring fall-throughs. Do not suppress implementation-side signature parity, complete callback-bearing chains in token windows, complete match tables, or windows with real body content.

`token.declaration-scaffold` recognizes private fields, `pub` fields, and restricted visibility such as `pub(crate)` or `pub(in crate::module)`. Its classification view omits `//` line-comment contents, including trailing field comments, so documentation words such as `for` or `fn` neither establish a type header nor count as executable behavior. Declaration recognition precedes signature-prefix classification so comment text cannot redirect a field table to the function-signature rule. Original comment tokens, window boundaries, and fingerprints remain unchanged in both token dimensions; disabling the rule exposes the same candidates. Executable code surrounding a declaration, computed field types, and incomplete visibility prefixes remain eligible. This refinement does not change block-comment or quoted-token lexing.

### Group Coverage (`group.covered-by-ast`) and Containment (`group.overlap-contained`)

A token/line group fully covered by one AST/sub-AST group is tagged rather than shown twice; the covering group is annotated (`also seen as: N <dimension> <kind> group(s)` under `--show-suppressed`). A window group contained (≥0.8) within a wider same-dimension group is tagged in favor of the widest representative — this is what keeps overlapping admitted stanza windows from multiplying in the visible report.

## Method-Name Preservation

`MethodCall` normalization preserves the method name as an opaque token while still erasing receiver and argument identifiers. Rationale: with names erased, bodies that differ only in which method they call (`is_ascii_alphabetic` vs `is_ascii_alphanumeric`) fingerprint as "exact duplicates"; name preservation kills the false-positive class at the root instead of hiding its instances. Discrimination is pinned by `different_method_names_get_different_fingerprints`; Python fingerprints are unaffected (`python_fingerprints_unchanged_by_method_name_preservation` — Python emits `Call` + `FieldAccess`, no `MethodCall`).

Fingerprint redefinitions like this one invalidate end-user ignore registries and require the migration procedure in `dupes-core/AGENTS.md`.

Deferred analogue: Python attribute-name preservation (see Future Work).

## Intentional And Visible

Two self-corpus classes are deliberately reported and must never be hidden by a global suppression rule. Registering them is per-project judgment, and the detector must keep reporting them on corpora that do not register them:

- **The sentinel-returns group** (`return NormalizedNode::leaf(NodeKind::Opaque)` at the distinct exits of `normalize_ts_node`): its normalized shape is the protected two-child-return class (`return Some(x)`), so any rule hiding it would corrupt this contract, and sentinel returns at distinct pipeline exits cannot be consolidated into one site.
- **The NodeMapping builder-chain parity groups** (`python_mapping()` in `dupes-python/src/lib.rs`, the test mappings in `dupes-treesitter/src/normalizer.rs`, `dupes-treesitter/tests/python_integration.rs`, and the `mapping.rs` builder test): each layer deliberately restates the chain so its expectations stay independent of the others.

## Registry Framing

The suppression rule registry (this document) is global detector policy. `.dupes-ignore.toml` is a per-project end-user facility: applied only after live groups exist, filtered from both populations, counted in stats (`Ignored (registry): N groups`), never shown, and never consulted during detection. The `ignore`/`ignored`/`cleanup` commands, drift-resilient entry matching, and the migration procedure are shipped product behavior, covered by fixture-local CLI tests.

This repository does not carry a `.dupes-ignore.toml` registry. Every self-corpus finding above the configured analysis floors must be resolved at its owning abstraction; no production or test duplicate is admitted by fingerprint.

## Shapes Not To Suppress Globally

Do not add broad rules for these without explicit user adjudication:

- Raw string contents, especially embedded fixture programs.
- Assertion macros; `panic!`, `todo!`, `unimplemented!` branches; logging/tracing macros with structured fields.
- Test fixture duplicates.
- Complete match tables and implementation-side function signatures.
- Call-rooted top-level wrappers and struct constructors.
- Iterator chains with closures.
- Branches with bindings, arithmetic, control flow, or computed returns.
- Two-child wrapped-value returns (`return Some(x)`).

Hiding these in the detector would turn a project-local judgment into a global blind spot.

## Future Rule Gate

Before adding a new rule, require all of the following:

1. The candidate is low-signal by itself (or, for admissions, real signal by itself), not merely inconvenient in the current report.
2. A registry row in `suppression.rs` with a stable id, declared level (Unit/Group), action (Suppress/Admit), and dimensions; the registry invariant tests must pass.
3. The rule applies to the smallest candidate unit/window only, and a larger surrounding duplicate remains detectable when it contains behavior.
4. Boundary tests in both directions: a negative test for the suppressed/admitted shape and a positive counter-test for the closest behavior-bearing variant. Name tests after the policy boundary, not the historical group that motivated the change.
5. The detector-coverage harness gains or flips pins in the same change, including the per-rule attribution map.
6. The self-corpus gate stays green: `consolidated_sites_stay_consolidated` plus a reviewed diff of the visible self-corpus report.

## Regression Coverage Map

- Registry invariants: `dupes-core/src/suppression.rs` tests (every id has exactly one row, ids round-trip, admit rules are exactly the two line admissions).
- Unit classifiers: `dupes-core/src/extractor.rs` tests (per-rule tagging and counter-tests, including the dispatch-return trio); the size cap is pinned end-to-end by the detector-coverage fixture.
- Window classifiers and the stanza coalescer: `dupes-core/src/text_units.rs` tests (segment anatomy positives/negatives, block coalescing, brace/import rejections, builder steps, admission carve-outs).
- Pipeline semantics: `dupes-core/src/lib.rs` tests (partition policy, mixed-group visibility, chain coverage release-on-no-match, liveness across both populations, ignore interplay with suppressed groups).
- Emission: `dupes-rust/src/parser.rs` tests prove every top-level unit and closure is emitted (no extraction gates), with dual chain emission linking branches to their owning chains.
- End-to-end pins: `cargo-dupes/tests/detector_coverage/tests.rs` over the frozen `tests/fixtures/detector_coverage/` project — stats totals, per-dimension visible groups, named membership, and the exact `suppressed_by_rule` map; every numeric value is a measured actual.
- Self-corpus gate: `cargo-dupes/tests/self_corpus/tests.rs` (`consolidated_sites_stay_consolidated`).

## Required Tests For Detector Changes

When changing `dupes-core/src/extractor.rs` classifiers:

```sh
cargo test -p dupes-core extractor
cargo test -p dupes-rust --test core_with_syn_tests
```

When changing `dupes-core/src/text_units.rs` eligibility, admission, or coalescing:

```sh
cargo test -p dupes-core text_units
```

Before accepting any detector refinement:

```sh
cargo test -p cargo-dupes --test detector_coverage --test self_corpus
cargo test --workspace --all-features --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Use a visible self-corpus report (`--sub-function --show-suppressed -v` with the pinned excludes) to confirm the intended shape moved between populations and nothing else did.

## Future Work

- Near-duplicate extension for the line/token_raw dimensions (deferred, no demonstrated loss; smallest slice if pursued: near-matching over merged line concept groups).
- Python attribute-name preservation, the analogue of method-name preservation (deferred; Python emits `Call` + `FieldAccess`, so the false-positive class does not currently reproduce there).
- Python quote profile: triple-quoted strings and a same-line rule for `'…'` literals (deferred; the naive pairing is approximately right for common Python and changing it churns Python window fingerprints without a demonstrated loss).
- Comment-aware token windows: skipping or down-weighting comment tokens would stop doc-comment-led windows from pairing on comment shape.
