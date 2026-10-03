---
title: Wrap git-credential-gcloud with jit
description: git's credential helper for Google source repositories reads the Google Cloud CLI's login, so jit wrap gcloud shims it and unseals the store for each request.
---

# git-credential-gcloud - git helper for Google source repositories (store)

When git is configured with `credential.helper=gcloud` (Cloud Source
Repositories), git runs `git-credential-gcloud` by name, and it reads the
Google Cloud CLI's login itself.

The wrap shims it, so each credential request unseals the store for that
one call:

```sh
jit wrap gcloud
git fetch
```

See the [gcloud page](./gcloud.md) for how the store is unsealed.

## Verify

```sh
git fetch    # in a repository on source.developers.google.com
```

## Undo

`jit wrap undo git-credential-gcloud` undoes the whole family, as
`jit wrap undo gcloud` does.
