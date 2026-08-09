---
title: Wrap the GitHub Copilot CLI with jit
description: Keep your Copilot PAT out of shell exports - injected as COPILOT_GITHUB_TOKEN just-in-time.
---

# copilot - GitHub Copilot CLI

Copilot CLI's programmatic auth is a fine-grained personal access token
(with the "Copilot Requests" permission), which GitHub's docs have you
`export` - landing a GitHub credential in a shell rc file and in every
process your shell starts. Wrapping stores the PAT in the vault and
injects it into each `copilot` invocation only.

## Wrap it

There is no standard file the PAT lives in (the interactive `/login`
stores an OAuth session, not your PAT), so vault the token first, then
wrap:

```sh
jit vault set wrap-copilot/COPILOT_GITHUB_TOKEN
jit wrap copilot
```

## Verify

```sh
copilot -p "say hi"
```

## How it works

The shim injects `COPILOT_GITHUB_TOKEN` from the vault - deliberately not
`GH_TOKEN` or `GITHUB_TOKEN`, although copilot reads all three. Copilot
runs the commands you ask it to as child processes; the generic variables
in that inherited environment would authenticate `gh` and every git
credential flow in every one of those children, not just Copilot itself.
`COPILOT_GITHUB_TOKEN` is Copilot CLI's own variable, and it takes
precedence over the other two. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo copilot
```

## Notes

- **An interactive `/login` session is left alone.** If you signed in
  through the browser flow, there's no PAT to wrap and no need for one -
  the wrap is for the PAT path (automation, or avoiding the OAuth grant).
- The PAT must be a **user-owned fine-grained token** with the
  **Copilot Requests** permission; organization-owned tokens can't carry
  that permission.
- If the token is already a plaintext `export` in `~/.zshrc`,
  `jit migrate ~/.zshrc` handles that copy.
