---
title: Migrating GCP application-default credentials
description: The ADC refresh token (or service account key) leaves the JSON file for the vault; the file live-mounts from a template so Google SDKs keep working.
---

# GCP (application-default credentials)

`gcloud auth application-default login` writes a long-lived OAuth refresh
token to `~/.config/gcloud/application_default_credentials.json`, in
plaintext, next to non-secret fields like the client ID. Some setups put a
service account's private key there instead. Every Google client library
(and Terraform's google provider) reads that one path.

`jit migrate <path-to-ADC-json>` (category `gcp`) moves **just the secret
field**, the `refresh_token`, or a service account's `private_key`, into
the vault and
replaces the file with a [live mount](../run/mounts.md) serving a
template: every non-secret field passes through byte-for-byte, and the
secret slot fills from the vault when a read is authorized. With per-process
consent on (the default), that is the everyday way: run your tool and approve
the Touch ID prompt the first time it reads the file. `jit run --with gcp` is
the explicit alternative (a hard gate, and what you use for scripts and CI).
Either way the ADC is machine-wide, so a project's config can never grant it on
its own.

```sh
jit run --with gcp -- terraform apply     # scoped to this run, gone on exit
jit wrap add gcloud --grant gcp           # or: keep typing gcloud directly
```

## Why a mount and not a credential hook?

AWS has `credential_process`; kubectl has exec plugins; Terraform has
`credentials_helper`. GCP has no equivalent for these credential types.
Its only executable hook (`credential_source.executable`) belongs to
workload identity federation's `external_account` files: the executable
must return an OIDC/SAML subject token for an STS exchange against a real
workload identity pool, and every consuming process has to opt in with
`GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`. It cannot serve an
`authorized_user` refresh token or a `service_account` key at all, so
the live mount is what keeps SDKs working transparently with no secret on
disk. (An `external_account` file itself holds no secret; `jit migrate`
leaves it alone.)

## What to expect

- SDKs, `gcloud auth application-default print-access-token`, and
  Terraform read the mount like a normal file. With per-process consent on
  (the default), the first such read prompts a Touch ID that names the reader
  and returns real credentials on approval. `jit run --with gcp` (or a
  grant-wrapped `gcloud`) is the explicit grant, scoped to that run. If consent
  is off and no grant covers the read, they see placeholder values and fail fast
  with a local parse error; `jit service status` shows what the last reader was
  served.
- The file is machine-wide (one per user), so name it explicitly to
  convert it (a project directory walk never touches it).
- The gcloud CLI's *own* login (`gcloud auth login`) lives elsewhere
  (`~/.config/gcloud/credentials.db`) and isn't part of this migration.
- Re-running `gcloud auth application-default login` replaces the mount
  with a fresh plaintext file; run `jit migrate <path-to-ADC-json>` again
  to re-vault it.

Reversing: `jit unmount <path>` writes the file back plain, or
[`jit migrate undo`](./undo-and-remove.md) restores the original bytes.
