---
title: Wrap OpenCode with jit
description: Keep your Anthropic API key out of ~/.local/share/opencode/auth.json - injected as ANTHROPIC_API_KEY just-in-time.
---

# opencode - OpenCode

OpenCode's `/connect` command stores provider API keys in plaintext JSON
at `~/.local/share/opencode/auth.json`. Wrapping moves the Anthropic key
into the vault and injects it as `ANTHROPIC_API_KEY` - which OpenCode
reads from the environment - into each `opencode` invocation only.

## Wrap it

```sh
jit wrap opencode
```

jit reads the Anthropic `key` from `auth.json`, stores it at
`wrap-opencode/ANTHROPIC_API_KEY`, scrubs the plaintext (original backed
up encrypted), and installs the `~/.jit/shims/opencode` shim plus the
`wrap-opencode` profile.

## Verify

```sh
opencode run "say hi"
```

## How it works

The shim injects `ANTHROPIC_API_KEY` from the vault into each `opencode`
process. With the file's key scrubbed, OpenCode picks the key up from the
environment. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo opencode
```

## Notes

- **Only the Anthropic API key is vaulted.** Other providers'
  credentials in the same `auth.json` - including OAuth logins, which
  store tokens rather than an API key - are left exactly as they were.
- **A Claude subscription (OAuth) login has no API key to wrap**; if
  that's how you connected Anthropic, there's nothing to find, and the
  wrap installs the shim anyway, ready for
  `jit vault set wrap-opencode/ANTHROPIC_API_KEY` if you switch to a key.
- A re-`/connect` with an API key writes plaintext again - re-run
  `jit wrap opencode` after.
