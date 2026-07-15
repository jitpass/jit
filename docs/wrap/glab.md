---
title: Wrap the GitLab CLI (glab) with jit
description: Keep your GitLab personal access token out of ~/.config/glab-cli/config.yml - injected as GITLAB_TOKEN just-in-time.
---

# glab - GitLab CLI

`glab auth login` stores a personal access token in plaintext in
`~/.config/glab-cli/config.yml`. Wrapping moves it into the vault and
injects it as `GITLAB_TOKEN` into each `glab` invocation only.

## Wrap it

```sh
jit wrap glab
```

jit reads the token from `config.yml` (the `gitlab.com` host entry),
stores it at `wrap-glab/GITLAB_TOKEN`, scrubs the plaintext line (original
backed up encrypted), and installs the `~/.jit/shims/glab` shim plus the
`wrap-glab` profile.

## Verify

```sh
glab auth status
```

## How it works

The shim injects `GITLAB_TOKEN` from the vault into each `glab` process -
glab's documented env-var credential. Scripts and subprocesses go through
the same shim. Details: [how wrapping works](./index.md).

## Undo

```sh
jit wrap undo glab
```

## Notes

- Self-hosted GitLab: the catalog extracts the `gitlab.com` token. For a
  self-hosted host's token, wrap by hand with
  [`jit wrap add`](./custom-tools.md) using the env var your setup reads.
- A re-`glab auth login` writes plaintext again - re-run `jit wrap glab`
  after.
