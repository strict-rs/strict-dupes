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
