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
