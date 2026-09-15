<!-- Do not edit; generated file. -->

# Repo agent plugins

`.agents/plugins/` holds the repo-native agent plugins shared by every agent runtime that works in this repository. `marketplace.json` is the local marketplace catalog; each plugin lives in its own directory beside it.

## Plugin layout

Within a plugin directory (for example `rust-template-core/`):

- `plugin.json` — the single source-of-truth manifest.
- `.codex-plugin/plugin.json` and `.claude-plugin/plugin.json` — relative symlinks to `../plugin.json`, so each runtime reads the same manifest from the directory name it expects. Neither runtime owns the manifest.
- `skills/<name>/SKILL.md` — the bundled skills, shared by every runtime. `agents/openai.yaml` carries codex picker metadata and is ignored by runtimes that do not use it.

## Discovery

- **codex** reads `marketplace.json` and each plugin's `.codex-plugin/plugin.json`. Plugin `source` paths in `marketplace.json` are resolved from the repository root.
- **claude-code** loads each plugin in place as an `@skills-dir` plugin: a relative symlink at `.claude/skills/<plugin>` points back to the plugin directory here, and claude-code reads its `.claude-plugin/plugin.json`. No marketplace catalog or settings entry is required; launch claude-code from the repository root and accept the workspace-trust prompt.

## Editing

Edit `plugin.json`, `marketplace.json`, and `skills/**` here. The per-runtime manifest files and the `.claude/skills/<plugin>` entry are relative symlinks into this tree, so they track the source automatically and need no separate edits.
