# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build --release          # Build all workspace crates
cargo test --workspace         # Run all tests
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint (warnings are errors)
cargo test -p ferriskey-cli-core context::tests  # Run a specific test module
```

## Architecture

This is a Cargo workspace with 4 crates:

- **`ferris-ctl`** (root) — Binary entry point. Parses CLI with `Cli::parse()`, passes to `ferriskey_cli_core::run()`.
- **`libs/ferriskey-commands`** — Clap derive structs only. Defines `Cli`, `Commands` enum, and per-command `*Command`/`*Args` structs. No logic.
- **`libs/ferriskey-cli-core`** — Command dispatch and execution. `run()` matches on `Commands` variants and delegates to module handlers (`context.rs`, `client.rs`). Owns config management.
- **`libs/ferriskey-client`** — `reqwest`-based HTTP client. `FerriskeyClient::new(base_url, prefix, token)` handles auth (Bearer token), request serialization, and response parsing.

### Data flow

```
CLI args → Cli::parse() → ferriskey_cli_core::run()
    → match Commands → handler (context/client)
        → FerriskeyClient → REST API
        → FileContextRepository → TOML config file
```

### Config storage

Contexts (URL, client_id, client_secret, optional realm) are stored as TOML at `$XDG_CONFIG_HOME/ferriskey/config.toml`. `FileContextRepository` does atomic writes (temp file + rename). `ContextStore` holds the map and tracks the active context.

### Output formatting

Root-level `--output` / `-o` flag accepts `table` (default), `json`, or `yaml`. Each handler has format-specific render functions.

### Unimplemented stubs

Realm and User commands are defined in `ferriskey-commands` but return `UnimplementedCommand` errors in `ferriskey-cli-core`. Client `get`/`delete` subcommands are also stubs.

### OAuth2 token exchange

`FerriskeyClient::exchange_client_credentials()` performs the client credentials flow before API calls that require authentication.
