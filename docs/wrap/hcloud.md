---
title: Wrap the Hetzner Cloud CLI (hcloud) with jit
description: Keep your Hetzner Cloud API token out of ~/.config/hcloud/cli.toml - injected as HCLOUD_TOKEN just-in-time.
---

# hcloud - Hetzner Cloud CLI

`hcloud context create` stores your API token in plaintext in
`~/.config/hcloud/cli.toml`. Wrapping moves it into the vault and injects
it as `HCLOUD_TOKEN` into each `hcloud` invocation only.

## Wrap it

```sh
jit wrap hcloud
```

jit reads the first context's token from `cli.toml` - the active one for
single-context setups, which is the common case - stores it at
`wrap-hcloud/HCLOUD_TOKEN`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/hcloud` shim plus the
`wrap-hcloud` profile.

## Verify

```sh
hcloud server list
```

## How it works

The shim injects `HCLOUD_TOKEN` from the vault into each `hcloud`
process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo hcloud
```

## Notes

- **Multiple contexts:** only the first context's token is auto-migrated.
  With several projects, vault each token yourself and switch by pointing
  [`jit wrap add`](./custom-tools.md)'s `HCLOUD_TOKEN` mapping at the
  right vault path.
