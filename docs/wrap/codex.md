---
title: Wrap the Codex CLI with jit
description: Keep your OpenAI API key out of ~/.codex/auth.json - injected as CODEX_API_KEY just-in-time.
---

# codex - Codex CLI

`codex login --with-api-key` caches the key in plaintext JSON at
`~/.codex/auth.json`, alongside whatever ChatGPT OAuth tokens a separate
login left there. Wrapping moves the API key into the vault and injects
it as `CODEX_API_KEY` - Codex's documented non-interactive auth variable
- into each `codex` invocation only.

## Wrap it

```sh
jit wrap codex
```

jit reads the `OPENAI_API_KEY` field from `auth.json`, stores it at
`wrap-codex/CODEX_API_KEY`, scrubs the plaintext (original backed up
encrypted), and installs the `~/.jit/shims/codex` shim plus the
`wrap-codex` profile.

## Verify

```sh
codex exec "say hi"
```

## How it works

The shim injects `CODEX_API_KEY` from the vault into each `codex`
process - deliberately not `OPENAI_API_KEY`. Codex runs the commands you
ask it to as child processes; putting the key in `OPENAI_API_KEY` would
hand it to every one of those children through inherited environment,
not just to Codex itself. `CODEX_API_KEY` is Codex's own scoped variable
for exactly this. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo codex
```

## Notes

- **A ChatGPT (subscription) login is left alone.** If `auth.json`'s
  `OPENAI_API_KEY` field is empty because you signed in with
  `codex login` (browser OAuth) instead of `--with-api-key`, there's
  nothing for `jit wrap codex` to find - it says so and installs the shim
  anyway, ready for `jit vault set wrap-codex/CODEX_API_KEY` if you add
  an API key later. Your OAuth session in the same file is never touched.
- A re-`codex login --with-api-key` writes plaintext again - re-run
  `jit wrap codex` after.
</content>
