---
title: Wrap the Snyk CLI with jit
description: Keep your Snyk API token out of ~/.config/configstore/snyk.json - injected as SNYK_TOKEN just-in-time.
---

# snyk - Snyk CLI

`snyk auth` stores your API token in plaintext in
`~/.config/configstore/snyk.json`, as the JSON field `api`. Wrapping moves it
into the vault and injects it as `SNYK_TOKEN` into each `snyk` invocation only.

## Wrap it

```sh
jit wrap snyk
```

jit reads the `api` field from `~/.config/configstore/snyk.json`, stores it at
`wrap-snyk/SNYK_TOKEN`, scrubs the plaintext (original backed up encrypted), and
installs the `~/.jit/shims/snyk` shim plus the `wrap-snyk` profile.

## Verify

```sh
snyk config get api
```

## How it works

The shim injects `SNYK_TOKEN` from the vault into each `snyk` process - the
CLI's documented env credential, which takes priority over the config file.
Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo snyk
```

## Notes

- The field is named `api`, not `token` - a quirk of the `configstore`
  library Snyk uses. jit reads the right key for you.
- No token stored yet? Set one first with
  `jit vault set wrap-snyk/SNYK_TOKEN`, then wrap.
