---
title: Wrap the DigitalOcean CLI (doctl) with jit
description: Keep your DigitalOcean API token out of doctl's config.yaml - injected as DIGITALOCEAN_ACCESS_TOKEN just-in-time.
---

# doctl - DigitalOcean CLI

`doctl auth init` stores your API token in plaintext in
`doctl/config.yaml` (under `~/Library/Application Support/` or
`~/.config/`). Wrapping moves it into the vault and injects it as
`DIGITALOCEAN_ACCESS_TOKEN` into each `doctl` invocation only.

## Wrap it

```sh
jit wrap doctl
```

jit checks both config locations, stores the token at
`wrap-doctl/DIGITALOCEAN_ACCESS_TOKEN`, scrubs the plaintext (original
backed up encrypted), and installs the `~/.jit/shims/doctl` shim plus the
`wrap-doctl` profile.

## Verify

```sh
doctl account get
```

## How it works

The shim injects `DIGITALOCEAN_ACCESS_TOKEN` from the vault into each
`doctl` process - the CLI's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo doctl
```

## Notes

- Multiple auth contexts: the catalog extracts the default
  `access-token`. For another context's token, use
  [`jit wrap add`](./custom-tools.md) pointed at a different vault path.
