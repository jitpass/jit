---
title: Migrating Kubernetes Secret manifests
description: jit migrate turns a plaintext secret.yaml into a live mount serving rejectable decoys - kubectl applies real values only through a jit run grant.
---

# Kubernetes Secret manifests

A `secret.yaml` on a laptop is plaintext with extra steps: the Kubernetes
docs themselves note that base64 "obscures but does not provide any useful
level of confidentiality". Anyone (or any process) that can read the file
can decode every value. `jit scan` flags these manifests; `jit migrate`
(category `k8s-secret`) is the fix:

```sh
jit migrate k8s/secret.yaml
```

Every `data:` and `stringData:` value moves into the vault, and the file
becomes a live mount serving the manifest with placeholders filled in per
reader:

- **Through jit** - `jit run -- kubectl apply -f k8s/secret.yaml`, or a
  [wrapped kubectl](../wrap/kubectl.md) - the manifest renders with its
  real values. kubectl behaves exactly as before.
- **Any other reader** - `cat`, an exfiltrating script, kubectl launched
  outside jit - gets decoy values like `jit-hidden-SECRET_DB_CREDS_PASSWORD`.
  Decoys are deliberately **never valid base64** (Kubernetes requires valid
  base64 in `data:`), so `kubectl apply` on a decoy manifest fails loudly at
  the API server. A decoy can never be silently written into a cluster.

Nothing in the cluster changes: Secrets already applied stay as they are,
and pods consume them by reference. The migration protects the at-rest
copy on your machine.

## stringData is converted to data

`stringData:` accepts any plaintext string, which means a decoy under
`stringData:` would be silently accepted by a real cluster - the opposite
of failing loudly. Migration therefore rewrites `stringData:` keys into
the `data:` section (the plan says so before you confirm). The applied
Secret object is byte-identical - Kubernetes folds `stringData` into
`data` at apply time anyway - and it sidesteps the documented caveat that
"the stringData field does not work well with server-side apply".

## What migrate refuses

The migration only rewrites what it can prove right; anything else is
reported and left untouched (and `jit scan` keeps flagging it):

- multi-line block-scalar values (`cert: |` blocks)
- one document using both `data:` and `stringData:` (unify them first)
- flow-style sections (`stringData: {token: x}`)
- a value that appears more than once in the file

## What to expect

- Each real render needs the vault unlocked - the
  [service](../service/index.md)'s shared session, or a Touch ID prompt.
- Multi-document files work: only `kind: Secret` documents are touched,
  and a ConfigMap or Deployment in the same file passes through verbatim.
  SealedSecrets and SOPS-encrypted values are recognized as already
  protected and skipped.
- Retrieval by hand: `jit status --secrets` shows the vault paths;
  `jit vault get <profile>/SECRET_<NAME>_<KEY>` prints one value (the
  base64 string, exactly as the manifest carried it).
- kustomize `secretGenerator` source files (`.env.secret`,
  `username.txt`) are plain files, not manifests - migrate them with the
  [loose-secret category](./index.md) instead.

Reversing: [`jit migrate undo`](./undo-and-remove.md) restores the
original manifest byte-for-byte, stringData layout included.
