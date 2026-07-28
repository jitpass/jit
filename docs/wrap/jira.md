---
title: Wrap the Jira CLI with jit
description: Keep your Jira API token out of ~/.zshrc - injected as JIRA_API_TOKEN just-in-time.
---

# jira - Jira CLI

[`jira-cli`](https://github.com/ankitpokhrel/jira-cli) reads its Atlassian API
token from the `JIRA_API_TOKEN` environment variable. Its own docs tell you to
export that from your shell config, which is exactly how it ends up as a
plaintext line in `~/.zshrc` or `~/.bash_profile` that every process you run
can read.

Unlike most wrapped tools, there's nothing tool-specific to discover: the token
never lands in jira-cli's own config file, which holds only non-secret settings
(site URL, login email, default project and board).

## Wrap it

The token has no standard file to auto-migrate from, so vault it first:

```sh
jit vault set wrap-jira/JIRA_API_TOKEN
jit wrap jira
```

That installs the `~/.jit/shims/jira` shim and the `wrap-jira` profile. Keep
typing `jira` as normal.

## Already exported it in your shell config?

If the token is currently a plaintext `export JIRA_API_TOKEN=...` line, that's
[`jit migrate`](../migrate/shell-configs.md)'s territory:

```sh
jit migrate ~/.zshrc
```

That moves the value into the vault and rewrites the line, so every new shell
keeps working. Use migrate **or** wrap, not both - migrate makes the variable
available to every process in the shell, while wrap scopes it to `jira`
invocations only. Wrap is the tighter of the two.

## Verify

```sh
jira me
```

## Undo

```sh
jit wrap undo jira
```

## Notes

- **Atlassian API tokens are per-account, not per-project.** The same token
  reaches every Jira and Confluence site your account can, so its blast radius
  is wider than the project you're scripting against. Scope it with
  [Atlassian's scoped API tokens](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)
  where you can, and set an expiry.
- **`.netrc` users:** jira-cli also accepts credentials from `~/.netrc`. That
  file is covered by [`jit migrate`](../migrate/netrc.md) as the machine-global
  `netrc` credential instead - you don't need to wrap as well.
