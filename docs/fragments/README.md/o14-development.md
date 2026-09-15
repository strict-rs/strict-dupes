## Development

**Requirements:** Rust 1.96+ (edition 2024)

```sh
cargo build          # Build
cargo test           # Run all workspace tests
cargo clippy         # Lint check
cargo fmt --check    # Format check
```

Pre-commit hooks (via `cargo-husky`) run clippy and rustfmt automatically.
