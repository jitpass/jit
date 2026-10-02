---
title: Wrap gsutil with jit
description: gsutil reads the Google Cloud CLI's login from legacy_credentials, so jit wrap gcloud shims it too and unseals the store for each gsutil run.
---

# gsutil - Cloud Storage CLI (store)

`gsutil` reads the Google Cloud CLI's login from
`~/.config/gcloud/legacy_credentials/<account>/.boto`, a second plaintext
copy of the refresh token. The wrap seals that folder with the rest of the
store and shims `gsutil`, so each run unseals it:

```sh
jit wrap gcloud      # or jit wrap gsutil: either wraps the whole family
gsutil ls gs://my-bucket
```

Without the shim, a sealed store makes `gsutil` run anonymously and fail
with `401 Anonymous caller`. See the [gcloud page](./gcloud.md) for how
the store is unsealed.

## Verify

```sh
gsutil version -l
```

## Undo

`jit wrap undo gsutil` undoes the whole family, as `jit wrap undo gcloud`
does.
