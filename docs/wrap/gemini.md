---
title: Wrap the Gemini CLI with jit
description: Keep your Gemini API key out of ~/.gemini/.env - injected as GEMINI_API_KEY just-in-time.
---

# gemini - Gemini CLI

The Gemini CLI's documented way to hold an API key on disk is a plain
`.env` file: `~/.gemini/.env` first, then a plain `~/.env` as a fallback
if the first isn't there. Both are ordinary dotenv `KEY=value` files -
easy to read, and easy to `cat` by accident into a terminal recording or
a support ticket. Wrapping moves the key into the vault and injects it as
`GEMINI_API_KEY` into each `gemini` invocation only.

## Wrap it

```sh
jit wrap gemini
```

jit reads `GEMINI_API_KEY` from `~/.gemini/.env` (or `~/.env`), stores it
at `wrap-gemini/GEMINI_API_KEY`, scrubs the plaintext line (original
backed up encrypted), and installs the `~/.jit/shims/gemini` shim plus
the `wrap-gemini` profile. Everything else in the file - any other
`KEY=value` line - is left untouched.

## Verify

```sh
gemini -p "hello"
```

## How it works

The shim injects `GEMINI_API_KEY` from the vault into each `gemini`
process. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo gemini
```

## Notes

- **If `jit migrate home` already protects this file, wrap it first.**
  `jit migrate home` independently discovers *any* `.env`-named file
  under your home directory (that's how it protects a stray `~/.env`
  used for other tools) and turns it into a live-mounted pipe. If that's
  already happened to `~/.gemini/.env` or `~/.env`, `jit wrap gemini`
  refuses with an error rather than reading the file - reading a jit
  mount doesn't fail or hang, it silently returns a decoy value, and
  vaulting that as the "real" key would be worse than doing nothing. Run
  `jit wrap gemini` **before** migrating that file, or read the key out of
  the vault (`jit vault get <path>`) and copy it into
  `jit vault set wrap-gemini/GEMINI_API_KEY` by hand.
- Only the *file* path is scrubbed. `GEMINI_API_KEY` set directly in your
  shell profile overrides both the vault injection and the `.env` file -
  `jit audit`/`jit migrate home --only shell` covers that case.
</content>
