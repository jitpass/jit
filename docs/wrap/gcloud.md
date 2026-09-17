---
title: Wrap gcloud with jit
description: jit wrap gcloud runs every gcloud invocation inside jit run --with gcp, so the application-default credentials reach gcloud from the vault's live mount instead of a plaintext JSON file.
---

# gcloud - Google Cloud CLI (grant shim)

gcloud and every Google SDK read application-default credentials from
`~/.config/gcloud/application_default_credentials.json`.
[Migrating that file](../migrate/gcp.md) moves the refresh token (or
service-account key) into the vault and leaves the path as a live mount
that serves a decoy by default; the real credentials are served only to a
process that holds a grant on it.

`jit wrap gcloud` is the shim that takes the grant for you:

```sh
jit migrate ~/.config/gcloud/application_default_credentials.json  # once
jit wrap gcloud                 # shim: `gcloud` now runs jit run --with gcp
gcloud storage ls               # as before; the shim grants the real ADC
```

Each invocation runs `jit run --with gcp -- gcloud ...`: the mount is
granted to that one process under a disclosed Touch ID naming the
credential, and the grant ends with the process. Anything else reading
the JSON file gets a decoy the Google APIs reject.

The wrap injects no environment variables. Terraform's Google provider
and SDK-based programs are not covered by this shim: run those inside
`jit run --with gcp` (or wrap them the same way with
`jit wrap add <tool> --grant gcp`).

## Verify

```sh
gcloud auth application-default print-access-token
```

Through the wrapped gcloud this prints a token; through `cat` the file
still shows the decoy.

## Undo

`jit wrap undo gcloud` removes the shim; `jit run --with gcp -- gcloud ...`
still works and the mount keeps serving decoys by default. To put the
plaintext file back, use [`jit migrate undo`](../migrate/undo-and-remove.md).
