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
