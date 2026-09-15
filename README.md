<!-- Do not edit; generated file. -->

# cargo-dupes

A cargo subcommand that detects duplicate and near-duplicate code blocks in Rust codebases. The workspace also ships `code-dupes`, a multi-language CLI that combines language-aware AST analysis with generic token and line duplicate detection for code and text files.

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

## Installation

```sh
cargo install --path cargo-dupes   # the cargo subcommand
cargo install --path code-dupes    # optional: the multi-language CLI
```

Or, to run directly from the workspace:

```sh
cargo run -p cargo-dupes -- report
```

When installed, it's available as a cargo subcommand:

```sh
cargo dupes report
```

## Usage

```
cargo dupes [OPTIONS] [COMMAND]

Commands:
  stats    Show duplication statistics only
  report   Show full duplication report (default)
  check    Check for duplicates and exit with non-zero if thresholds exceeded
  ignore   Add a fingerprint to the ignore list
  ignored  List all ignored fingerprints
  cleanup  Remove stale entries from the ignore list (--dry-run to list only)

Options:
  -p, --path <PATH>            Path to analyze (defaults to current directory)
      --min-nodes <MIN_NODES>  Minimum AST node count for analysis [default: 10]
      --min-lines <MIN_LINES>  Minimum source line count for analysis [default: 0 (disabled)]
      --threshold <THRESHOLD>  Similarity threshold for near-duplicates (0.0-1.0) [default: 0.8]
      --format <FORMAT>        Output format [default: text] [possible values: text, json]
      --exclude <EXCLUDE>      Exclude patterns (can be repeated)
      --exclude-tests          Exclude test code (#[test] functions and #[cfg(test)] modules)
  -s, --sub-function           Enable sub-function duplicate detection
      --no-sub-function        Disable sub-function duplicate detection when enabled by config
      --min-sub-nodes <N>      Minimum AST node count for sub-function units [default: 5]
      --show-suppressed        Include rule-suppressed duplicate groups in the report body
  -v, --verbose                Verbose statistics: per-rule suppression breakdown
      --disable-rule <RULE_ID> Disable a suppression/admission rule by id (can be repeated)
      --enable-rule <RULE_ID>  Enable a rule by id (can be repeated; overrides config disable)
      --dimension <D>          Enable only a dimension: ast, sub-ast, token-normalized, token-raw, line
      --disable-dimension <D>  Disable a dimension: ast, sub-ast, token-normalized, token-raw, line
      --token-min-tokens <N>   Minimum token count for token windows [default: 50]
      --token-min-lines <N>    Minimum source line span for token windows [default: 2]
      --token-threshold <T>    Similarity threshold for normalized token near-duplicates [default: 0.9]
      --line-min-lines <N>     Minimum line count for line windows [default: 5]
```

### `code-dupes`

`code-dupes` shares the same subcommands and options, adds `-l, --language <rust|python|generic>`, and is invoked directly (no cargo subcommand shim). Without `--language` it auto-detects from file extensions: a single known language runs directly, several known languages produce an error asking for `--language`, and directories with only generic text (Markdown, TOML, YAML, JSON, shell, ...) fall back to token/line detection.

```sh
$ code-dupes --path ./src --language python report
```

### Examples

**Full report:**

```sh
$ cargo dupes report
Duplication Statistics
=====================
Total code units analyzed: 4

Exact duplicates: 1 groups (2 code units)
Near duplicates:  0 groups (0 code units)

Duplicated lines (exact): 18
Duplicated lines (near):  0
Duplication: 50.0% exact, 0.0% near (of 36 total lines)

Exact Duplicates
================

Group 1 (fingerprint: 2a182da9e04e9428, 2 members):
  - sum_positive (function) at src/lib.rs:2-10
  - count_positive (function) at src/lib.rs:12-20
```

**Statistics only:**

```sh
$ cargo dupes stats
Duplication Statistics
=====================
Total code units analyzed: 4

Exact duplicates: 1 groups (2 code units)
Near duplicates:  0 groups (0 code units)

Duplicated lines (exact): 18
Duplicated lines (near):  0
Duplication: 50.0% exact, 0.0% near (of 36 total lines)
```

**JSON output:**

```sh
$ cargo dupes --format json stats
{
  "total_code_units": 4,
  "total_lines": 36,
  "exact_duplicate_groups": 1,
  "exact_duplicate_units": 2,
  "near_duplicate_groups": 0,
  "near_duplicate_units": 0,
  "exact_duplicate_lines": 18,
  "near_duplicate_lines": 0,
  "exact_duplicate_percent": 50.0,
  "near_duplicate_percent": 0.0,
  "suppressed_unit_count": 0,
  "suppressed_group_count": 0
}
```

`report --format json` emits one parseable JSON object:

```json
{
  "stats": {
    "total_code_units": 4,
    "exact_duplicate_groups": 1
  },
  "groups": [
    {
      "dimension": "ast",
      "match_kind": "exact",
      "fingerprint": "2a182da9e04e9428",
      "similarity": 1.0,
      "members": []
    }
  ],
  "warnings": []
}
```

**CI check (fail if any exact duplicates exist):**

```sh
$ cargo dupes check --max-exact 0
# Exits with code 1 if exact duplicate groups > 0
# Exits with code 0 if within thresholds
```

**CI check with percentage thresholds (fail if >5% of lines are exact duplicates):**

```sh
$ cargo dupes check --max-exact-percent 5.0
# Exits with code 1 if exact duplicate lines exceed 5% of total lines
```

**Exclude test code (inline `#[cfg(test)]` modules and `#[test]` functions):**

```sh
$ cargo dupes --exclude-tests report
```

**Exclude test directories by path:**

```sh
$ cargo dupes --exclude tests --exclude benches report
```

**Only report duplicates that are at least 10 lines long:**

```sh
$ cargo dupes --min-lines 10 report
```

**Lower the similarity threshold:**

```sh
$ cargo dupes --threshold 0.7 report
```

**Enable or disable a noisy dimension temporarily:**

```sh
$ cargo dupes --dimension ast report
$ cargo dupes --dimension line stats
$ cargo dupes --disable-dimension line report
$ cargo dupes --sub-function report
$ cargo dupes --no-sub-function report  # when sub_function = true is set in config
```

**Inspect or toggle suppressed findings:**

```sh
$ cargo dupes --sub-function --show-suppressed report  # render tagged groups in their own sections
$ cargo dupes -v stats                                 # per-rule suppression breakdown
$ cargo dupes --disable-rule line.chain-tail report    # make one rule's findings fully visible
```

## Configuration

Configuration can be provided in three ways (in order of precedence):

1. **CLI flags** (highest priority)
2. **`dupes.toml`** in the project root
3. **`Cargo.toml`** under `[package.metadata.dupes]`

### `dupes.toml`

```toml
min_nodes = 15
min_lines = 5
similarity_threshold = 0.85
exclude = ["tests", "benches"]
exclude_tests = true
max_exact_duplicates = 0
max_near_duplicates = 10
max_exact_percent = 5.0
max_near_percent = 10.0
sub_function = true
min_sub_nodes = 5

[dimensions]
ast = true
sub_ast = true
token_normalized = true
token_raw = true
line = true

[token]
min_tokens = 50
min_lines = 2
similarity_threshold = 0.9

[line]
min_lines = 5

[suppress]
disable = ["line.chain-tail"]
enable = []
```

### `Cargo.toml`

```toml
[package.metadata.dupes]
min_nodes = 15
similarity_threshold = 0.85
exclude = ["tests"]
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `min_nodes` | `10` | Minimum AST node count for a code unit to be analyzed. Increase to skip trivial functions. |
| `min_lines` | `0` | Minimum source line count for a code unit to be analyzed. `0` means disabled. |
| `similarity_threshold` | `0.8` | Minimum similarity score (0.0-1.0) for near-duplicate detection. |
| `exclude` | `[]` | Glob-like path patterns to exclude from scanning. |
| `exclude_tests` | `false` | Exclude `#[test]` functions and `#[cfg(test)]` modules from analysis. |
| `sub_function` | `false` | Enable nested sub-function duplicate detection. |
| `min_sub_nodes` | `5` | Minimum AST node count for sub-function units. |
| `[dimensions].ast` | `true` | Enable whole-unit AST duplicate detection. |
| `[dimensions].sub_ast` | `true` | Enable nested AST duplicate detection. |
| `[dimensions].token_normalized` | `true` | Enable normalized token-window duplicate detection. |
| `[dimensions].token_raw` | `true` | Enable raw token-window exact duplicate detection. |
| `[dimensions].line` | `true` | Enable normalized line-window exact duplicate detection. |
| `[token].min_tokens` | `50` | Minimum token count for token windows. |
| `[token].min_lines` | `2` | Minimum source line span for token windows. Use `1` to include dense one-line token matches. |
| `[token].similarity_threshold` | `0.9` | Minimum score for normalized token near-duplicates. |
| `[line].min_lines` | `5` | Minimum line count for line windows. |
| `[suppress].disable` | `[]` | Suppression/admission rule ids to disable (registry in [`DETECTOR_REPORTABILITY.md`](DETECTOR_REPORTABILITY.md)). Unknown ids warn, never error. |
| `[suppress].enable` | `[]` | Rule ids to re-enable; CLI `--enable-rule` overrides config disables. |
| `max_exact_duplicates` | `None` | For `check` subcommand: maximum allowed exact duplicate groups. |
| `max_near_duplicates` | `None` | For `check` subcommand: maximum allowed near-duplicate groups. |
| `max_exact_percent` | `None` | For `check` subcommand: maximum allowed exact duplicate line percentage. |
| `max_near_percent` | `None` | For `check` subcommand: maximum allowed near-duplicate line percentage. |

## Ignoring Duplicates

Some duplicates are intentional (e.g., test helpers, trait implementations). You can ignore them by fingerprint:

```sh
# Add a fingerprint to the ignore list
$ cargo dupes ignore 2a182da9e04e9428 --reason "Intentional test helpers"
Added 2a182da9e04e9428 to ignore list.

# List ignored fingerprints
$ cargo dupes ignored
Ignored fingerprints:
  2a182da9e04e9428 (reason: Intentional test helpers)

# Ignored groups are automatically filtered from reports and checks
$ cargo dupes report
# The ignored group will not appear
```

The ignore list is stored in `.dupes-ignore.toml` in the project root. Fingerprints are stable for the duplicate pattern: they include the detection dimension, match kind, and normalized content, but not file paths or line numbers. Moving a duplicated block should not make the ignore entry stale. When `ignore` matches a live group, the entry also records the member locations and their content fingerprints, so near-duplicate entries survive membership drift; `cleanup` (or `cleanup --dry-run`) removes or lists entries whose duplication no longer exists, suggesting possible successor groups.

`--exclude-tests` only removes code units that the active language analyzer tags as tests, such as Rust `#[test]` functions and `#[cfg(test)]` modules. It does not exclude generic text files like Markdown, TOML, shell scripts, or JSON; use `--exclude` for path-based filtering of those files.

## CI Integration

Use the `check` subcommand in CI pipelines:

```yaml
# GitHub Actions example
- name: Check for code duplication
  run: cargo dupes check --max-exact 0 --max-exact-percent 5.0
```

Exit codes:
- **0** — Check passed (within thresholds)
- **1** — Check failed (thresholds exceeded)
- **2** — Error (no source files, invalid path, etc.)

## What Gets Analyzed

| Code Unit | Description |
|-----------|-------------|
| **Functions** | Top-level `fn` items |
| **Methods** | `fn` items inside `impl` blocks |
| **Trait impls** | `fn` items inside `impl Trait for Type` blocks |
| **Closures** | Closure expressions (above the min node threshold) |
| **Sub-functions** | `if` branches and chains, `match` arms, loop bodies, closure bodies, and nested blocks |
| **Token windows** | Normalized and raw token windows in scanned code/text files |
| **Line windows** | Normalized line windows in scanned code/text files |

The scanner automatically:
- Skips `target/` directories
- Respects `.gitignore` / parent ignore files
- Skips hidden directories (starting with `.`)
- Respects glob-like exclude patterns
- Handles parse errors gracefully (skips unparseable files with a warning)

## Development

**Requirements:** Rust 1.96+ (edition 2024)

```sh
cargo build          # Build
cargo test           # Run all workspace tests
cargo clippy         # Lint check
cargo fmt --check    # Format check
```

Pre-commit hooks (via `cargo-husky`) run clippy and rustfmt automatically.

## License

This project is licensed under the [MIT License](LICENSE).
