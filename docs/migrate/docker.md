---
title: Migrating Docker registry logins
description: Plaintext auths in ~/.docker/config.json move to the vault; a credential helper keeps docker login/logout working.
---

# Docker registry logins

`docker login` without a configured credential store writes your registry
username and password (or token) into `~/.docker/config.json`,
base64-encoded under `auths`. Base64 is encoding, not encryption - anyone
who can read the file can decode every registry login on the machine.
Docker Desktop users usually have a keychain-backed store configured;
CLI-only setups (colima, a homebrew docker client, CI-style installs)
usually don't, and that's where the plaintext accumulates.

`jit migrate` (category `docker`) moves each registry's credential into
the vault and wires Docker's own pluggable mechanism, a [credential
helper](https://docs.docker.com/reference/cli/docker/login/#credential-helpers),
into `~/.docker/config.json`:

```json
{
  "auths": { "registry.example.com": {} },
  "credHelpers": { "registry.example.com": "jit" }
}
```

The empty `auths` entry is docker's own marker shape for "a store holds
this"; the `credHelpers` entry routes that registry to the
`docker-credential-jit` helper (a two-line script in `~/.jit/shims`,
which jit keeps on `PATH`). Docker then asks jit for the credential on
demand (`get`), and - the part a shim could never cover - **`docker
login` and `logout` keep working**: a re-login lands directly in the
vault (`store`) instead of back in base64, and `logout` removes it
(`erase`).

## The default store

Per-registry `credHelpers` entries win over the default `credsStore`, so
jit **never replaces an existing credential store** (Docker Desktop's
`desktop`, `osxkeychain`). When the config has *no* store at all - the
plaintext situation - jit also claims the default:

```json
{ "credsStore": "jit" }
```

so a future `docker login` to any brand-new registry lands in the vault
too, instead of writing base64 again. A registry already routed to a
different helper is left alone entirely (audit still reports its stale
plaintext; `docker logout <registry>` clears it).

## What to expect

- Each credential fetch needs the vault unlocked - the
  [service](../service/index.md)'s shared session, or a Touch ID prompt.
  Anonymous pulls of public images never prompt: an unknown registry gets
  the protocol's "credentials not found" answer before any vault access.
- **Rotating a credential is just `docker login` again.** Prefer a scoped
  [access token](https://docs.docker.com/security/access-tokens/) over
  your account password when logging in to Docker Hub; whatever you log
  in with is what the vault stores.
- The helper resolves via `PATH` (`~/.jit/shims`), so docker invoked from
  a shell, script, or Makefile finds it. Open a new shell after the first
  migration if jit just added the `PATH` line.
- `jit wrap docker` routes to this same migration.

## Docker Compose

- **Image pulls**: `docker compose pull`/`up` reads the same
  `~/.docker/config.json` and invokes the same helper - covered
  automatically.
- **`.env` files and `env_file:`**: compose interpolation is the [.env
  migration](./env-files.md)'s territory. For `${VAR}` interpolation in
  `compose.yml`, shell environment wins over `.env` in compose's precedence,
  so `jit run -- docker compose up` injects the real values over the masked
  mount. For an `env_file:` that compose reads *from disk* into containers,
  `jit run` auto-detects the `docker`/`docker-compose`/`podman` command and
  keeps the live file serving real values to that run (the same as
  [`--live`](../run/index.md#reading-the-file-itself-during-a-run)); a
  compose-only project can pin `read_as_file: true` in `.jit/config.yaml`.
- **`secrets:` with a `file:` source**: compose mounts that file into the
  container at `/run/secrets/<name>`. Point the `file:` at a jit-managed
  path (an [.env-style mount](./env-files.md) or any vaulted file) and run
  `up` through `jit run --live`; jit doesn't auto-migrate arbitrary compose
  files.

Swarm's `docker secret create` is cluster-side state on managers, not a
local plaintext file - out of jit's scope.

`jit docker-credential <get|store|erase|list>` is the [plumbing
command](../reference/plumbing.md) docker invokes - you never run it by
hand. Reversing the migration: [`jit migrate undo`](./undo-and-remove.md).
