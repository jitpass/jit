---
title: Wrap the Hugging Face CLI (hf) with jit
description: Keep your Hugging Face access token out of ~/.cache/huggingface/token - injected as HF_TOKEN just-in-time.
---

# hf - Hugging Face CLI

`hf auth login` stores your access token in plaintext in
`~/.cache/huggingface/token` - the file's entire contents are the token,
sitting in a cache directory that backups, syncs, and Docker `COPY`s pick
up without a second thought. Wrapping moves it into the vault and injects
it as `HF_TOKEN` into each `hf` invocation only. `HF_TOKEN` is the Hub's
documented env-var credential and takes priority over the token file.

## Wrap it

```sh
jit wrap hf
```

jit reads the token file whole, stores it at `wrap-hf/HF_TOKEN`, scrubs
the plaintext (original backed up encrypted), and installs the
`~/.jit/shims/hf` shim plus the `wrap-hf` profile.

## Verify

```sh
hf auth whoami
```

## How it works

The shim injects `HF_TOKEN` from the vault into each `hf` process.
Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo hf
```

## Notes

- **Vault a User Access Token, not a browser-login token.** The browser
  flow of `hf auth login` issues a short-lived token that Hugging Face
  refreshes in place on disk; once vaulted, it will eventually expire and
  `hf` starts returning 401s. Create a long-lived token at
  [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens)
  (`read` scope unless you publish) and log in by pasting it before
  wrapping - or store it directly with `jit vault set wrap-hf/HF_TOKEN`.
- `hf auth login` also records every named token in
  `~/.cache/huggingface/stored_tokens` (what `hf auth list` and
  `hf auth switch` read). jit scrubs the active token file only - if
  you've saved several tokens, `hf auth logout` clears the rest.
- The Python libraries (`huggingface_hub`, `transformers`, `datasets`)
  read the same `HF_TOKEN` variable, but the shim only covers `hf`
  invocations. After the file is scrubbed, run scripts through
  [`jit run`](../run/index.md):
  `jit run --profile wrap-hf -- python train.py`.
- Still invoking the legacy `huggingface-cli` binary? Point it at the
  same vault entry:
  [`jit wrap add huggingface-cli --env HF_TOKEN=wrap-hf/HF_TOKEN`](./custom-tools.md).
- If `HF_HOME` or `XDG_CACHE_HOME` is set, the token file lives at
  `$HF_HOME/token` instead and discovery won't find it - store the token
  with `jit vault set wrap-hf/HF_TOKEN`, re-run `jit wrap hf`, and delete
  the old file yourself.
- A re-`hf auth login` writes plaintext again - re-run `jit wrap hf`
  after.
