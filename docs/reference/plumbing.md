---
title: Plumbing protocols
description: The commands other tools invoke - aws-credential-process, k8s-exec-credential, terraform-credentials, docker-credential, git-credential.
---

# Plumbing protocols

Seven commands exist to be invoked by *other tools' configuration* - or, in
the last case, by jit's own shell hook - rather than by hand. `jit --help`
groups them separately and shell tab-completion omits them entirely, for
exactly that reason.

The first six implement the consuming tool's documented credential-plugin
protocol, and each fetch requires the vault to be unlocked (the
[service](../service/index.md)'s session, or a Touch ID prompt). The
seventh, `jit guard check`, is the odd one out: it reads no secret, needs
no unlock, and exists only to answer a yes/no question for the shell hook.

## `jit aws-credential-process --profile <name>`

Implements AWS's [`credential_process`] contract: prints a JSON document
with the profile's access key, secret key, and session token to stdout.
Wired into `~/.aws/config` by [the AWS migration](../migrate/aws.md);
consulted by the CLI and every SDK that reads shared config.

## `jit k8s-exec-credential --profile <name>`

Implements client-go's exec credential plugin protocol: prints an
`ExecCredential` JSON document carrying the user's bearer token or client
cert/key pair. Wired into `~/.kube/config` by [the kubeconfig
migration](../migrate/kubernetes.md).

## `jit sops-age-key [--profile <name>]`

Implements sops's `SOPS_AGE_KEY_CMD` hook (sops v3.10+): prints the bare
age private key to stdout, nothing else - sops parses the output as key
material. Defaults to the `sops-age` profile [the SOPS
migration](../migrate/sops.md) creates; tools whose embedded sops
predates the hook read the migrated `keys.txt` live mount instead.

## `jit terraform-credentials <get|store|forget> <hostname>`

Implements Terraform's credentials-helper protocol: `get` prints the
host's token as JSON; `store` saves a new token into the vault (this is
what makes `terraform login` keep working); `forget` removes it
(`terraform logout`). Wired into `~/.terraformrc` by [the Terraform
migration](../migrate/terraform.md).

## `jit docker-credential <get|store|erase|list>`

Implements Docker's [credential-helper protocol], payloads on stdin:
`get` reads a registry address and prints the credential as JSON (or the
protocol's "credentials not found" sentinel, so anonymous pulls keep
working with no prompt); `store` saves a `docker login` into the vault;
`erase` handles `docker logout`; `list` prints an empty object (docker
resolves each registry through `get`, and a truthful list would need a
vault unlock inside headless docker calls). Invoked through the
`docker-credential-jit` script [the Docker migration](../migrate/docker.md)
writes, wired into `~/.docker/config.json`.

## `jit git-credential <get|store|erase>`

Implements git's [credential-helper protocol][git-cred], `key=value` attributes on
stdin (`protocol`, `host`, `path`, `username`, `password`): `get` reads a
host and prints the matching `username=`/`password=` pair (or nothing, so
git falls through to its next helper or prompt with no Touch ID); `store`
saves a login into the vault (a `git push` that authenticated with a
typed-in password afterward lands there, not back in plaintext); `erase`
removes it. Keys on host alone, matching git's default
(`credential.useHttpPath=false`). Invoked through the `git-credential-jit`
script [the git migration](../migrate/git.md) writes, with
`credential.helper` set to `jit` in your git config.

## `jit guard check`

Reads a shell command line on **stdin** and reports whether it carries a
value matching a known vendor credential format: exit 0 with the format
names on stdout, exit 1 and silence when it doesn't. It never prints the
value, stores nothing, and needs no vault - the whole job is a yes/no.

Invoked by the [`jit guard history`](../migrate/shell-history.md) hook
(`~/.jit/guard.zsh`) for each command line that passes the hook's own cheap
in-shell test, which settles ordinary commands in ~15µs without forking
anything (measured: 14% of lines on a real history reach this command, at
~33ms each). Stdin rather than an argument is the point, not a style choice: an
argument would put the credential into this process's `ps` output, readable
by every other process running as you, which is precisely the exposure the
guard exists to prevent.

Everything else about the guard IS audited: `jit guard history` and
`--remove` are recorded like any command, and when bare `jit migrate`
installs the guard as part of its plan, that lands in the trail too, as
`jit guard history (by jit migrate)` — so a hook you find in your `~/.zshrc`
can always be traced to the run that put it there.

`jit guard check` alone is excluded from the [application audit log](./commands/jit_audit.md),
alone among the plumbing commands - it runs at the interactive prompt, where
an audit append would be latency on your keystrokes, and a timestamped
record of *when* you typed credential-shaped commands is not what a trail of
secret access is for.

[`credential_process`]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
[credential-helper protocol]: https://docs.docker.com/reference/cli/docker/login/#credential-helper-protocol
[git-cred]: https://git-scm.com/docs/gitcredentials#_custom_helpers
