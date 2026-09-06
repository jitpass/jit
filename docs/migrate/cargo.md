---
title: Migrating cargo registry tokens
description: crates.io and private-registry publish tokens move to the vault; cargo fetches them through its own credential-provider protocol, and cargo login keeps working.
---

# Cargo (`~/.cargo/credentials.toml`)

`cargo login` stores its registry token in `~/.cargo/credentials.toml` (and
older cargos used a bare `~/.cargo/credentials`, which is still honored) in
plaintext. This is a **publish** credential: with it an attacker ships a new
version of any crate the account owns, straight into other people's builds.
Same blast radius as the npm and PyPI tokens, and the same reason it rates
High in [`jit scan`](../audit/index.md).

`jit migrate ~/.cargo/credentials.toml` (category `cargo`) moves every
registry's token into the vault and wires cargo's own stable
credential-provider mechanism (cargo 1.74+) in its place - no intermediate
file at all:

- each token lands in a `cargo-<registry>` vault profile (crates.io uses
  cargo's own reserved name, `cargo-crates-io`);
- a `cargo-credential-jit` wrapper is written into `~/.cargo/`, invoking
  `jit cargo-credential` (the provider protocol over stdin/stdout);
- `~/.cargo/config.toml` gets
  `global-credential-providers = ["cargo:token", ".../cargo-credential-jit"]`
  under `[registry]` - jit last, because later entries take precedence;
- the token lines are stripped from the credentials file(s), including a
  stale copy in the legacy `~/.cargo/credentials`.

Cargo asks jit for the token exactly when an operation needs one
(`cargo publish`, `cargo yank`, `cargo owner`, a private registry's index
fetch), and the answer never touches disk.

## After migration

- **`cargo publish` and friends just work** - cargo invokes the provider,
  jit resolves the token from the vault (through the background service's
  unlocked session, or a Touch ID prompt).
- **`cargo login` keeps working, and lands in the vault.** jit's provider
  takes precedence, so a re-login (rotation) stores the new token in the
  vault instead of writing a fresh plaintext file. `cargo logout` removes it
  from the vault.
- **Unmigrated registries are untouched.** For a registry jit holds nothing
  for, the provider answers the protocol's not-found and cargo falls back to
  `cargo:token` (credentials.toml) exactly as if jit weren't installed.

## Notes

- **A pre-existing provider configuration is a hard stop.** If
  `global-credential-providers` is already set in `~/.cargo/config.toml`
  (say, `cargo:macos-keychain`), jit refuses rather than rewrite your own
  deliberate configuration, and the error says how to add jit's provider by
  hand (append it last - last wins).
- **Every protocol shape was verified empirically** against a live cargo,
  including precedence, fallback, and login/logout routing - see
  `spike/cargo-credential-provider/FINDINGS.md`.
- **Undo:** `jit migrate undo ~/.cargo/credentials.toml` restores the
  original file byte-for-byte from its encrypted backup (and
  `~/.cargo/config.toml` alongside it).
