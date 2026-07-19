# Global File-Delivered Mount Grants — Design Plan

Status: proposed (post-v0.17.0). Owner: TBD. This is a spec, not shipped code.

## Context

v0.17.0 added run-scoped reveal: under `jit run`, a migrated `.env` mount is
made compatible with the command for that run only — swapped for an inert
file by default, or kept live and granted to the run's process tree with
`--live`. That work deliberately covered only **dotenv (`.env`-family)
mounts**. This plan extends the same run engine to the credentials that are
delivered as a **file a tool reads at a fixed path**, with the security
constraints that global credentials require.

## 1. Delivery models (why this is scoped the way it is)

Every jit credential type is one of three shapes:

- **Call-out** — the tool asks jit on demand: `aws` (`credential_process`),
  `kubectl` (exec plugin), `terraform` **Cloud/registry token**
  (`credentials_helper`), `docker` (credential-helper protocol), modern
  `sops` (`SOPS_AGE_KEY_CMD`). Solved; no mount, no grant, not in scope here.
- **Env-delivered** — jit injects a variable: `.env`, shell configs, `tfvars`
  (`TF_VAR_*`), `mcp` (server launched via `jit run`). The compatibility
  swap covers these; not in scope here.
- **File-delivered** — a tool reads the file at a path. These are the
  template mounts, and they are this plan's subject.

The file-delivered mounts today:

| Mount | Path | Escape hatch | Scope |
|---|---|---|---|
| **gcp ADC** | `~/.config/gcloud/application_default_credentials.json` (+ `$GOOGLE_APPLICATION_CREDENTIALS`) | **none** (verified vs Google AIP-4117: the only executable hook is Workload Identity Federation's `credential_source.executable`, which returns an OIDC/SAML subject token, needs `GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1`, and cannot serve an `authorized_user` refresh token or `service_account` key) | global |
| **sops** | `~/.config/sops/age/keys.txt` (+ `$SOPS_AGE_KEY_FILE`) | `SOPS_AGE_KEY_CMD` call-out, `SOPS_AGE_KEY` env | global |
| **npmrc** | project `.npmrc` **or** global `~/.npmrc` | `NPM_TOKEN` env (but the file also holds non-secret registry config, so jit mounts it) | project **or** global |

The hard, irreducible case is **gcp** — no call-out, no env substitute, must
be a file mount. sops and npmrc have escapes but are mounted for
compatibility. The general category this plan solves is **global
file-delivered mounts**: `{ gcp ADC, global sops keys, global ~/.npmrc }`.

Project-local file-delivered mounts (a project `.npmrc`) are the safe subset:
they belong to the run's project and fold into the run engine's existing
project scope like `.env` does, with no global-credential concern.

## 2. The security invariant (the constraint everything else serves)

> **Project-local configuration may reconfigure the project's own secrets,
> but it must never authorize access to a machine-global credential. Every
> global-mount grant is triggered by explicit user intent and disclosed in
> its own challenge that names the credential.**

Why this exists: a project's `.jit/config.yaml` is untrusted input (a cloned
repo, a malicious PR). A naive `grants: [gcp]` declaration in that file would
let any `jit run` in the directory hand the run's tree your global gcloud
credentials — silently, riding the Touch ID you approved for the *project*.
The unlock authorizes *the session*, not *the scope*; the attacker-controlled
file must not get to widen the scope. So:

- A global-mount grant is never driven by a project-local file.
- A global-mount grant always forces a **fresh** challenge (even if the
  session is already unlocked) whose wording names the global credential, so
  it can never happen silently on the back of a project unlock. This is the
  same doctrine `jit agent reveal <path>` already follows.

This also explains why `read_as_file: true` (v0.17.0) is safe as a
project-local setting: it only changes how the project's **own** mount is
served (swap vs live), never reaching a global credential.

## 3. How a grant works (reuses the v0.17.0 engine)

The run engine (`internal/cli/mountruns.go`) already serves real content to a
run's process tree, decided per read by process ancestry, torn down on the
run's exit (`NOTE_EXIT`), lock, pid-recycle, or hard cap. A global-mount
grant is that same grant applied to a global mount path. Its laziness is what
makes it safe:

- Real content flows only if the run's tree actually **opens** the file.
- It flows only to that tree; every other process on the machine gets decoys
  the whole time.

This is **strictly narrower than the reveal window** the mount uses today,
which serves real values to *every* process for 60 seconds. Granting a global
mount to a run is a security improvement, not a regression.

## 4. Triggers — explicit intent only, no guessing

Global-mount grants come from exactly two user-driven signals. **There is no
consumer auto-detection for global mounts** (see §9 for why).

1. **`jit run --with <name> <command>`** — one-off intent, repeatable:
   `--with gcp`, `--with sops`, `--with npm`. The flag is the intent; an
   attacker cannot type it for you. (`--` before the command is optional; jit
   stops reading its own flags at the first non-flag argument. Use `--` only
   when the command's own leading flags would be mistaken for jit's.)
2. **A grant-wrap** (a new mode of `jit wrap`, permanent) — for a tool you
   run by its native name (see §4a). Explicit permanent intent, still gated by
   the disclosed challenge.

Rejected: a project-local `grants:` declaration (violates §2).

## 4a. Native-tool use: grant-wraps (the primary answer for "just type gcloud")

The chosen solution for using a file-delivered tool by its native name
(`gcloud storage ls`, not `jit run … gcloud …`) is a **grant-mode extension
of `jit wrap`**, reusing the existing wrap machinery whole. `jit wrap` today
has exactly one mode; add a second:

- **env-wrap** (today): the shim runs `jit run --profile wrap-<tool> <tool>`
  → injects a token. For `gh`, `aws`, `stripe`.
- **grant-wrap** (new): the shim runs `jit run --with <mount> <tool>`
  → grants a file-delivered mount. For `gcloud`, `terraform`-against-gcp,
  SDK-using scripts.

```
jit wrap gcloud        # one-time: installs a grant-shim for the gcp mount
gcloud storage ls      # native from here; the shim transparently grants the ADC
```

Everything else is unchanged: the `~/.jit/shims` PATH entry, real-binary
resolution beyond the shim, and `jit wrap list`/`doctor`/`undo`. The only new
concept is "a wrapped tool may grant a mount instead of injecting an env var,"
a small branch in the wrap install path. `jit wrap` thereby becomes the single
"use a tool by its native name" answer for env- and file-delivered tools alike.

Security: the shim runs `jit run --with <mount>`, i.e. the disclosed-challenge
grant. The user gets **one disclosed unlock per session** ("grant `gcloud` your
global gcloud credentials?"), cached for the session thereafter; each grant is
scoped to that tool's process tree and ends on exit — never a broad window.

Full usage story for a native file-delivered tool:

| Want | Do | Security |
|---|---|---|
| Native, all the time | `jit wrap gcloud` once, then `gcloud …` | scoped grant, one disclosed unlock/session |
| Occasional, no setup | `jit agent reveal <path>`, then `gcloud …` | broad window, manual |
| Scripted / one-off | `jit run --with gcp gcloud …` | scoped grant, per-run |

Bare `gcloud` with no wrap, no window, and no `jit run` gets decoys and fails
fast — by design (decoy-by-default requires *something* to authorize a real
read; there is no un-mediated real read).

## 5. The disclosed challenge

Every global-mount grant forces a fresh challenge, worded to name the
credential and the requester:

> *"`terraform apply` (this run) is requesting your global **gcloud**
> credentials. Approve? [Touch ID]"*

- Fires from both triggers in §4 (and the first grant under a future
  machine-level allow, §11).
- Implemented as a disclosed variant of `OpRevealPID` (or a new
  `OpGrantGlobal`): always runs `ensureUnlockedNotify` with a caller-supplied,
  credential-naming reason — reusing the fresh-challenge path
  `jit agent reveal` already has, even when the session is unlocked.
- **Session caching:** after approval, the grant may ride the agent session
  for subsequent runs naming the *same* credential via the *same* trigger,
  bounded by a short TTL, so the user is not prompted per invocation. A grant
  never rides a session it was not disclosed-and-approved for. Tunable;
  default: cache per-credential for the session.

## 6. Per-mount mode (the one real protocol change)

Today a run is all-swap or all-grant — one mode for every mount
(`OpRevealPID` carries a single `Swap` bool). A single run now needs three
buckets at once:

- **swap** — project `.env` (default, guard-compatible),
- **local grant** — project `.npmrc` (rides the session; it's the project's
  own secret, no disclosure needed),
- **global grant** — gcp / global sops / global npmrc (disclosed challenge).

So the run→agent request becomes a list of `{mountPath, mode}` (or three
lists). `resolveInjectionProfile` starts including the project's template
mounts (it filters them out today at `internal/cli/envlayers.go:93`), and
`--with` adds the global ones. The engine already supports grant mode; this
is plumbing, not new gating.

## 7. Resolving `<name>` → a mount

A single table of known global mount kinds, the one place a new global mount
is registered:

| `<name>` | path(s) | migrate category |
|---|---|---|
| `gcp` | `~/.config/gcloud/application_default_credentials.json`, `$GOOGLE_APPLICATION_CREDENTIALS` | gcpadc |
| `sops` | `~/.config/sops/age/keys.txt`, `$SOPS_AGE_KEY_FILE` | sopsage |
| `npm` | `~/.npmrc` | npmrc (global) |

`--with gcp` resolves to the registered mount for that kind; if it isn't
migrated, jit says so plainly.

## 8. Optional hardening — short-lived token broker

For tools that honor an access-token env var (gcloud's
`CLOUDSDK_AUTH_ACCESS_TOKEN`, some SDKs' `GOOGLE_OAUTH_ACCESS_TOKEN`),
`jit run` can mint a short-lived access token from the vaulted refresh token
and inject *that* instead of granting the refresh-token mount — the long-lived
credential never leaves the vault and the token self-expires. Partial (SDK
env-var support is inconsistent), so it layers on top of the mount grant,
which stays the universal fallback. Requires implementing the Google OAuth
refresh call. Defer to the last stage.

## 9. Why there is no consumer auto-detection for global mounts

We considered auto-detecting the tool (`gcloud` → grant gcp, like the docker
`env_file` → live auto-detect in v0.17.0) and rejected it:

- **The disclosed challenge fires either way.** Auto-detect would save the
  user typing `--with gcp`, not the interaction — a tiny win.
- **Wrong stakes.** The docker auto-detect decides swap-vs-live on the
  *project's own* `.env` (low stakes; a wrong guess fails loudly with "use
  `--live`"). A global-credential grant is machine-wide; the correct default
  is "don't grant unless asked."
- **Forgetting `--with` fails safely and loudly.** Without it, the tool reads
  the mount, gets decoys, and fails fast with a local parse error (already
  documented for gcp). The user adds `--with` once. No silent exposure.
- **The permanence need is better served explicitly** by a grant-shim (§4.2)
  than by an implicit guess.

Note this is only about **global** mounts. The v0.17.0 docker→live
auto-detect for a project's own `.env` stays — different, lower-stakes
decision.

## 10. Two distinct "terraform" credentials (a clarification)

- **Terraform's own token** (Terraform Cloud / private registry) → already
  handled by the `terraform-credentials` call-out. Not in scope here.
- **Terraform reading gcp ADC** (a run with the Google provider) → terraform
  is a *consumer* of the gcp mount, nothing jit provides a credential to.

Terraform is **not** an auto-detect trigger for gcp — it is multi-cloud
(Google/AWS/Azure/none), so its use of gcp is not inferable from the command.
It uses explicit `jit run --with gcp terraform apply`. Only unambiguous
single-purpose tools would ever be candidates for detection, and per §9 we
don't detect for global mounts at all.

## 11. Tool support

**At launch:**
- **gcp ADC** (`authorized_user` and `service_account`) — mount grant +
  disclosed challenge; `--with gcp`; optional token broker for gcloud/SDKs.
- **global sops** — prefer the existing `SOPS_AGE_KEY_CMD` call-out; mount
  grant as fallback for sops < 3.10; `--with sops`.
- **global `~/.npmrc`** — mount grant, or `NPM_TOKEN` env injection where the
  file has no non-secret config; `--with npm`.

**Future (add a row to §7):**
- **`~/.pgpass`** (Postgres/libpq) — already a k8s-protection candidate.
- **`~/.netrc`** (curl/git).
- Any new global file-delivered credential jit learns to migrate.

**Deliberately out of scope:**
- **SSH / GPG / PEM private keys** — the right model is an agent
  (ssh-agent/gpg-agent), i.e. call-out, not a file-mount grant. `jit audit`
  flags them; migration stays out.
- **Anything callable** (aws, kubectl, terraform-cloud, docker, modern sops)
  — already solved by credential helpers.
- **Project-local `grants:` declarations** — rejected (§2).

## 12. Build stages

Status: stages 1-3 plus the §12a guidance are BUILT and code-reviewed on
branch `per-mount-mode` (unmerged). Stages 4-5 below remain, both conditional.

1. **[DONE] Per-mount mode** in the run→agent protocol + include project
   template mounts in run resolution. Unblocks everything; also gives project
   `.npmrc` grants for free.
2. **[DONE] `--with <name>` + the known-mount-kinds table + the disclosed
   challenge** (disclosed `OpRevealPID`). The minimum that makes gcp work
   safely under `jit run`.
3. **[DONE] Grant-wraps** (§4a) — the grant-mode of `jit wrap` for
   native-tool use. The primary answer for `gcloud`/`terraform`/SDK scripts.
   Plus **[DONE] §12a guidance** at migrate + doctor time.
4. **Machine-level `jit trust`** (direnv-style approval stored outside the
   repo), only if declare-once ergonomics prove wanted. NOT started —
   deliberately deferred: it relaxes the disclosed challenge, so it should
   wait until per-run-prompt friction is actually demonstrated.
5. **Short-lived token broker** for gcloud (hardening), last. NOT started.

## 12a. Guidance at migrate / doctor time (discoverability)

A mount the user can't figure out how to *use* is a papercut even when the
migration succeeds — the same lesson as the compatibility swap. So a
file-delivered global mount must ship with its usage guidance, at the two
moments the user is already looking:

- **`jit migrate` summary.** After migrating a file-delivered global mount,
  the per-category output names the consuming tools and the command:
  > `gcp` migrated → `~/.config/gcloud/application_default_credentials.json`
  > is now a live mount. Tools that read it (`gcloud`, `terraform`, Google
  > SDKs) get real credentials when you run them with
  > `jit run --with gcp <command>`.
  This replaces the generic reveal-hook line for these mounts, since the
  hook path (direnv/npm) does not apply to gcloud/sops/global-npmrc.
- **`jit doctor`.** For an already-migrated file-delivered global mount,
  doctor carries the same one-line reminder, so the `--with` usage is
  discoverable long after the migration scrolled off screen.

Note this is guidance about the mount `jit migrate` created — it is NOT a
suggestion to `jit wrap` the tool. gcloud is handled by the mount; the
`jit wrap`-style grant-shim (§4.2) is an optional convenience the guidance
may mention as "for a tool you run constantly," never as the primary fix.

## 13. Verification

- **Unit:** `--with` resolves each kind; a project-local `grants:`
  declaration grants **nothing** (regression test for §2); the disclosed
  challenge fires even when the session is unlocked; per-mount mode
  round-trips (swap + local-grant + global-grant in one run).
- **E2E (real agent + Touch ID):** `jit run --with gcp cat <ADC>` inside the
  tree gets real content, a sibling process reads decoys, the grant dies on
  exit; a `.jit/config.yaml` with `grants: [gcp]` grants nothing.
- **Security:** add the §2 invariant to `docs/security/architecture.md`.

## 14. Rejected alternatives (so they aren't reproposed)

- **Project-local `grants: [...]`** — untrusted config authorizing a global
  credential; the core vulnerability this design exists to prevent.
- **Consumer auto-detection for global mounts** — see §9.
- **Materializing plaintext at a path** — jit never writes a secret to disk.
- **Treating gcp's WIF `credential_source.executable` as a call-out** — it
  cannot serve `authorized_user`/`service_account` credentials (§1, AIP-4117).
