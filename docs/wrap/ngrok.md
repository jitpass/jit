---
title: Wrap ngrok with jit
description: Keep your ngrok authtoken out of ngrok.yml - injected as NGROK_AUTHTOKEN just-in-time.
---

# ngrok

`ngrok config add-authtoken` writes your authtoken in plaintext to
`ngrok.yml` - under `~/Library/Application Support/ngrok/` (or
`~/.config/ngrok/`), in the v3 `agent:` block or v2 top-level. Wrapping
moves it into the vault and injects it as `NGROK_AUTHTOKEN` into each
`ngrok` invocation only.

## Wrap it

```sh
jit wrap ngrok
```

jit checks both config locations and both layout versions, stores the
token at `wrap-ngrok/NGROK_AUTHTOKEN`, scrubs the plaintext (original
backed up encrypted), and installs the `~/.jit/shims/ngrok` shim plus the
`wrap-ngrok` profile.

## Verify

```sh
ngrok config check
```

## How it works

The shim injects `NGROK_AUTHTOKEN` from the vault into each `ngrok`
process - the ngrok agent's documented env-var credential. Details:
[how wrapping works](./index.md).

## Undo

```sh
jit wrap undo ngrok
```

## Notes

- Long-running tunnels hold the token for the tunnel's lifetime, like any
  process you inject into - the token still never returns to disk.
- Re-running `ngrok config add-authtoken` writes plaintext again - re-run
  `jit wrap ngrok` after rotating.
