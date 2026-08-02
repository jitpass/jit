---
title: Wrap kubectl with jit
description: jit wrap kubectl runs every kubectl invocation inside a jit run grant, so migrated Secret manifests apply with real values while everything else sees rejectable decoys.
---

# kubectl - Kubernetes CLI (run-grant shim)

kubectl touches jit twice, and the two are independent:

- **Authentication** is already covered by
  [migrating your kubeconfig](../migrate/kubernetes.md): kubectl fetches its
  token or client certificate through the standard exec credential plugin.
  No wrap involved, nothing to install.
- **Secret manifests** are covered by
  [migrating the manifest itself](../migrate/kubernetes-secret-manifests.md):
  `jit migrate secret.yaml` moves the `data:` values into the vault and
  leaves the file as a live mount that serves decoys by default. Real
  values are served only to a process tree launched through `jit run`.

`jit wrap kubectl` closes the last gap in the second story: typing
`kubectl apply -f secret.yaml` without remembering `jit run --`.

```sh
jit wrap kubectl
```

installs a PATH shim that re-execs every kubectl invocation as
`jit run --grant-only -- kubectl ...`. Inside that grant, a migrated
Secret manifest serves kubectl its real content; outside it (another
terminal without the shim, a script, an exfiltration attempt) the mount
serves decoy `data:` values that are never valid base64, so an apply
fails loudly at the API server instead of writing decoys into a cluster.

The wrap changes nothing else about kubectl: it injects no environment
variables, and in a directory with no migrated manifests the grant simply
has nothing to grant. `kubectl get pods` behaves identically wrapped or
not.

## Verify

```sh
kubectl apply --dry-run=client -f <your migrated secret.yaml>
```

Through the wrapped kubectl this parses the real manifest; through
`cat secret.yaml` you still see decoys.

## Undo

`jit wrap undo kubectl` removes the shim. The manifest mount keeps
serving (decoys by default) - unwrapping kubectl changes how you launch
it, not how the Secret is protected. To put the plaintext manifest back,
use [`jit migrate undo`](../migrate/undo-and-remove.md).
