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
