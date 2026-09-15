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
