---
title: Migrating kubeconfig credentials
description: Bearer tokens and client key pairs leave ~/.kube/config; an exec credential plugin serves kubectl on demand.
---

# Kubernetes (kubeconfig)

`~/.kube/config` routinely carries bearer tokens or client certificate/key
pairs in plaintext. `jit migrate` (category `kube`) moves the user's
credential into the vault and replaces it with an `exec` block - client-go's
standard credential-plugin protocol:

```yaml
users:
  - name: my-user
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: jit
        args: ["k8s-exec-credential", "--profile", "kube-my-user"]
```

`kubectl` and every client-go-based tool call it on demand and get a
standard `ExecCredential` response; nothing about your workflow changes.

## What to expect

- Each credential fetch needs the vault unlocked - the
  [service](../service/index.md)'s shared session, or a Touch ID prompt.
- Rotating: update the vault paths shown by `jit status --secrets`; the
  next fetch serves the new credential.
- The `exec` block records jit's absolute path. If an upgrade moves the
  binary, `jit doctor` flags the stale line and `jit migrate ~/.kube/config`
  (or `--only kube`) [refreshes
  it](./index.md#a-recorded-jit-path-that-went-stale).

## OIDC logins (kubelogin)

[kubelogin](https://github.com/int128/kubelogin) (`kubectl oidc-login`)
keeps each login's refresh token in `~/.kube/cache/oidc-login` in
plaintext by default. It can keep them in the keychain instead, and
`jit migrate ~/.kube/config` switches it there: each user whose exec runs
kubelogin gets `--token-cache-storage=keyring`, and the plaintext cache is
removed (backed up first, so undo brings it back).

The next `kubectl` call for each cluster signs in once more, then keeps its
token in the keychain. Every file in the default cache goes, so a login a
*different* kubeconfig keeps on disk also signs in again on its next use.

`jit k8s-exec-credential` is the [plumbing
command](../reference/plumbing.md) the kubeconfig invokes - you never run
it by hand. Reversing the migration: [`jit migrate
undo`](./undo-and-remove.md).
