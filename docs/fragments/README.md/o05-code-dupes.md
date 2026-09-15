### `code-dupes`

`code-dupes` shares the same subcommands and options, adds `-l, --language <rust|python|generic>`, and is invoked directly (no cargo subcommand shim). Without `--language` it auto-detects from file extensions: a single known language runs directly, several known languages produce an error asking for `--language`, and directories with only generic text (Markdown, TOML, YAML, JSON, shell, ...) fall back to token/line detection.

```sh
$ code-dupes --path ./src --language python report
```
