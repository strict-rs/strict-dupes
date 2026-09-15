### `dupes.toml`

```toml
min_nodes = 15
min_lines = 5
similarity_threshold = 0.85
exclude = ["tests", "benches"]
exclude_tests = true
max_exact_duplicates = 0
max_near_duplicates = 10
max_exact_percent = 5.0
max_near_percent = 10.0
sub_function = true
min_sub_nodes = 5

[dimensions]
ast = true
sub_ast = true
token_normalized = true
token_raw = true
line = true

[token]
min_tokens = 50
min_lines = 2
similarity_threshold = 0.9

[line]
min_lines = 5

[suppress]
disable = ["line.chain-tail"]
enable = []
```
