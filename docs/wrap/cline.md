---
title: Wrap the Cline CLI with jit
description: Keep your Anthropic API key out of ~/.cline/settings/providers.json - injected as ANTHROPIC_API_KEY just-in-time.
---

# cline - Cline CLI

`cline auth -p anthropic -k <key>` caches the key in plaintext JSON at
`~/.cline/settings/providers.json`. Wrapping moves it into the vault and
injects it as `ANTHROPIC_API_KEY` - which cline reads from the
environment - into each `cline` invocation only.

## Wrap it

```sh
jit wrap cline
```

jit reads the Anthropic `apiKey` from `providers.json`, stores it at
`wrap-cline/ANTHROPIC_API_KEY`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/cline` shim plus the
`wrap-cline` profile.

## Verify

```sh
cline -P anthropic "say hi"
```

## How it works

The shim injects `ANTHROPIC_API_KEY` from the vault into each `cline`
process. With the file's key scrubbed, cline picks the key up from the
environment. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo cline
```

## Notes

- **This wraps the Anthropic API-key setup** (`-P anthropic`). Cline's
  default hosted provider (`cline`) signs in with OAuth and stores no API
  key in `providers.json` - nothing to wrap there, and it's never touched.
  Other API-key providers (OpenRouter, etc.) keep their entries; only the
  Anthropic key is vaulted.
- **Cline runs commands as child processes**, and `ANTHROPIC_API_KEY` in
  its environment is inherited by them - the same tradeoff as `claude`.
  Unlike `codex` there is no scoped per-tool variable to prefer; the wrap
  still beats a key at rest in plaintext JSON.
- A re-`cline auth` with `-k` writes plaintext again - re-run
  `jit wrap cline` after.
