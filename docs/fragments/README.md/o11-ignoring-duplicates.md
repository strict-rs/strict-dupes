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
