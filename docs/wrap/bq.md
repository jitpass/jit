---
title: Wrap bq with jit
description: bq reads the Google Cloud CLI's login store, so jit wrap gcloud shims it too and unseals the store for each bq run.
---

# bq - BigQuery CLI (store)

`bq` signs in with the Google Cloud CLI's login, read from
`~/.config/gcloud`. Once that store is sealed in the vault, `bq` needs the
same per-run unsealing as `gcloud`, so the wrap shims it too:

```sh
jit wrap gcloud      # or jit wrap bq: either wraps the whole family
bq ls
```

Everything on the [gcloud page](./gcloud.md) applies: one Touch ID to
unseal, a private folder per run, nothing left on disk afterwards.

## Verify

```sh
bq version
```

## Undo

`jit wrap undo bq` undoes the whole family, as `jit wrap undo gcloud`
does: the login goes back to `~/.config/gcloud` and every shim is removed.
