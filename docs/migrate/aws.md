---
title: Migrating AWS credentials
description: ~/.aws/credentials moves to the vault; credential_process serves the CLI and every SDK on demand.
---

# AWS credentials

`~/.aws/credentials` is the classic long-lived plaintext credential file.
`jit migrate` (category `aws`) moves each profile's access key, secret key,
session token, and expiration stamp (if a SAML/SSO tool minted the profile)
into the vault and wires a `credential_process` line into
`~/.aws/config` - after which **that file no longer holds the real value**:

```ini
[profile myprofile]
credential_process = jit aws-credential-process --profile aws-myprofile
```

`credential_process` is AWS's own extension point, and it's consulted by
everything that reads the shared config: the `aws` CLI, boto3, aws-sdk-go,
the Terraform AWS provider - every SDK. That's why this is a *native hook*
rather than a shim; nothing about how you invoke your tools changes.

## What to expect

- Each credential fetch needs the vault unlocked - the
  [service](../service/index.md)'s shared session, or a Touch ID prompt.
- SDKs cache the returned credentials per-process, so a long-running
  process doesn't re-prompt on every API call.
- `jit wrap aws` routes to this same migration - there's one AWS
  mechanism, whichever command you arrive through.

## What jit does not cover

jit protects the credential *you* stored. The AWS CLI also mints credentials
of its own, downstream of the one it just fetched, and those are not jit's:

- **`~/.aws/cli/cache`** holds the plaintext STS session the CLI receives
  after assuming a role. It expires on its own; deleting the directory clears
  it now.
- **`~/.aws/sso/cache`** holds the access token and role credentials
  `aws sso login` wrote. `aws sso logout` clears them.
- **`~/.aws/credentials-cache`** holds the temporary session credentials
  [clisso](https://github.com/allcloud-io/clisso) caches when its
  `cache-enable` option is on. They expire on their own; deleting the file
  clears them now.
- **A profile with an `aws_expiration` stamp** was minted by an SSO tool
  (clisso, aws-okta, onelogin-aws) that rewrites `~/.aws/credentials` on
  each login. Migrating it protects today's token - expiration included,
  served via `Expiration` so SDKs refresh on time - but the finding
  returns with tomorrow's login, and `jit scan` says so rather than
  reporting a clean machine that won't stay clean. The tool's own
  long-lived secret (for clisso: the OneLogin client-secret in
  `~/.clisso.yaml`) is reported separately as a manual finding.
- **Assume-role profiles are not migrated.** A profile that is just a
  `role_arn` plus a `source_profile` has no key of its own, so there is
  nothing for jit to move. Migrating the *source* profile still protects the
  long-lived key the role is assumed with, which is the credential that
  matters - but the session minted from it is cached by the CLI as above.

None of this is jit working around a problem; these files are how the CLI
works, and they will be rewritten the next time it runs. What changed is that
jit now says so: `jit scan` reports them under "Outside jit's scope, found
anyway" rather than walking silently past hex-named files in the directory it
has just tidied. A clean report that quietly omitted a live session token
would be the more dangerous output.

## Rotating keys

New access keys go into the vault, not into a file:
`jit vault set <path>` on the paths shown by
`jit status --secrets`. Everything picks the new values up on
its next fetch.

## Plumbing

`jit aws-credential-process` is the [plumbing
command](../reference/plumbing.md) the config invokes - you never run it by
hand. Reversing the migration: [`jit migrate
undo`](./undo-and-remove.md).
