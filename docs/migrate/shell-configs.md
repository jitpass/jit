---
title: Migrating shell configs
description: export KEY=value lines in ~/.zshrc move to the vault; an eval "$(jit export ...)" line takes their place.
---

# Shell configs

`export STRIPE_KEY=sk_live_...` in `~/.zshrc` is a secret readable by
anything running as your user, forever. `jit migrate ~/.zshrc` (category
`shell`) moves each such value into the vault and replaces the export lines
with one line:

```sh
eval "$(jit export --profile <name>)"
```

Every new shell resolves the profile from the vault at startup instead of
carrying plaintext in the config file. The merge announcement `jit export`
prints goes to stderr, so `eval` never swallows it - you can see what each
shell loaded.

## What to expect

- Opening a new shell needs the vault unlocked: with the
  [service](../service/index.md) installed that's at most one Touch ID prompt
  per session window, not per shell.
- A shell that's already running keeps the values it loaded at startup.
  After [rotating a value](../vault/index.md) or locking the vault, open a
  new shell (or re-run the `eval` line) to pick up changes.
- The original config file is backed up encrypted before rewriting;
  [`jit migrate undo`](./undo-and-remove.md) restores it byte-for-byte.

See also **[Shell exports](../run/export.md)** for how `jit export` picks
profiles and merges layers.
