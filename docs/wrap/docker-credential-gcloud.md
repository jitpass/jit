---
title: Wrap docker-credential-gcloud with jit
description: Docker's credential helper for Google registries reads the Google Cloud CLI's login, so jit wrap gcloud shims it and unseals the store for each pull or push.
---

# docker-credential-gcloud - Docker helper for Google registries (store)

`gcloud auth configure-docker` registers `docker-credential-gcloud` in
`~/.docker/config.json`. Docker runs it by name for every pull or push to
Artifact Registry or Container Registry, and it reads the Google Cloud
CLI's login itself, without going through `gcloud`.

So the wrap shims it too. Docker finds the shim on your PATH, and each
credential request unseals the store for that one call:

```sh
jit wrap gcloud
docker pull us-docker.pkg.dev/my-project/repo/image
```

Without the shim, a sealed store leaves the helper with no account and
the pull fails with an authentication error. See the
[gcloud page](./gcloud.md).

## Verify

```sh
echo https://us-docker.pkg.dev | docker-credential-gcloud get
```

That prints an access token, so run it only where that is fine to show.

## Undo

`jit wrap undo docker-credential-gcloud` undoes the whole family, as
`jit wrap undo gcloud` does.
