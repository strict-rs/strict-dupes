## How It Works

`cargo-dupes` parses Rust source files into ASTs using [syn](https://github.com/dtolnay/syn), then normalizes each function, method, closure, and nested control-flow region into a canonical form where:

- **Identifiers are replaced** with positional placeholders (so `foo(x)` and `bar(y)` are identical) — except method names, which are preserved (`x.is_ascii_alphabetic()` never matches `x.is_ascii_alphanumeric()`)
- **Literal values are erased** but types preserved (`42` and `99` are both "integer literal")
- **Control flow structure is preserved** exactly
- **Macro invocations keep their names** with arguments normalized (`println!("a")` matches `println!("b")` but never `eprintln!`)

This normalized AST is hashed with deterministic `blake3`-based fingerprints for exact duplicate detection, and compared tree-by-tree using the Dice coefficient for near-duplicate detection. The same pipeline also runs generic token and line-window detection so macro-heavy, config-like, prose, and non-AST-friendly duplication can be found without a separate tool.

Detection dimensions:

- **AST** — whole functions, methods, trait impl methods, and closures.
- **Sub-AST** — nested `if` branches and chains, `match` arms, loop bodies, closure bodies, and significant blocks. This is opt-in via `--sub-function` or `sub_function = true`.
- **Normalized tokens** — identifier/literal-insensitive token windows.
- **Raw tokens** — whitespace-insensitive exact token windows.
- **Lines** — trimmed, whitespace-normalized line windows.

Low-signal shapes (trivial guard returns, message-only macro branches, builder setters, signature prefixes, declaration scaffolds, cut match-table prefixes, ...) are tagged by a global suppression-rule registry rather than dropped: the default report hides fully tagged groups, `--show-suppressed` reveals them, `-v` attributes them per rule, and `--disable-rule`/`--enable-rule` (or `[suppress]` in config) toggle individual rules. Suppression is separate from ignore policy: the detector extracts, tags, and groups candidates first, then the per-project `.dupes-ignore.toml` registry filters adjudicated intentional groups from the report. See [`DETECTOR_REPORTABILITY.md`](DETECTOR_REPORTABILITY.md) for the full contract, including the rule table and the guarantees that keep the detector ignore-blind.
