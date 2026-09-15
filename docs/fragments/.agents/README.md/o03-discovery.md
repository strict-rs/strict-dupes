## Discovery

- **codex** reads `marketplace.json` and each plugin's `.codex-plugin/plugin.json`. Plugin `source` paths in `marketplace.json` are resolved from the repository root.
- **claude-code** loads each plugin in place as an `@skills-dir` plugin: a relative symlink at `.claude/skills/<plugin>` points back to the plugin directory here, and claude-code reads its `.claude-plugin/plugin.json`. No marketplace catalog or settings entry is required; launch claude-code from the repository root and accept the workspace-trust prompt.
