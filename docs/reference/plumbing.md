---
title: Plumbing protocols
description: The commands other tools invoke - aws-credential-process, k8s-exec-credential, terraform-credentials, docker-credential.
---

# Plumbing protocols

Five commands exist to be invoked by *other tools' configuration*, not by
hand - `jit --help` groups them separately and shell tab-completion omits
them entirely, for exactly that reason. Each
implements the consuming tool's documented credential-plugin protocol, and
each fetch requires the vault to be unlocked (the
[agent](../agent/index.md)'s session, or a Touch ID prompt).

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

[`credential_process`]: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
[credential-helper protocol]: https://docs.docker.com/reference/cli/docker/login/#credential-helper-protocol
