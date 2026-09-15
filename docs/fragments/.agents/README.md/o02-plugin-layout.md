## Plugin layout

Within a plugin directory (for example `rust-template-core/`):

- `plugin.json` — the single source-of-truth manifest.
- `.codex-plugin/plugin.json` and `.claude-plugin/plugin.json` — relative symlinks to `../plugin.json`, so each runtime reads the same manifest from the directory name it expects. Neither runtime owns the manifest.
- `skills/<name>/SKILL.md` — the bundled skills, shared by every runtime. `agents/openai.yaml` carries codex picker metadata and is ignored by runtimes that do not use it.
