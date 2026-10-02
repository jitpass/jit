# Spike Findings: a sealed gcloud credential store, materialized per run

**Question:** gcloud keeps a refresh token with no fixed expiry in plaintext
(`credentials.db`, a SQLite file it writes itself), and has no keychain
option. A FIFO mount cannot serve SQLite, and a decoy would just log gcloud
out. Can the store instead live sealed in the vault and be materialized into
a private `CLOUDSDK_CONFIG` only while a gcloud-family command runs? Concretely:

1. Does gcloud work from a temp `CLOUDSDK_CONFIG` whose settings are symlinks
   into the real `~/.config/gcloud` and whose secrets are copies?
2. Which commands rewrite the secret files, so how often must jit reseal?
3. What happens when the provider rotates the refresh token, and when
   several commands share one materialized dir?
4. Which other programs read the store, and do they go through a `gcloud`
   shim on PATH?

**Environment:** macOS (Darwin 27.0.0, arm64), Google Cloud SDK 587.0.0
from `brew install --cask gcloud-cli`, components `gke-gcloud-auth-plugin`,
`kubectl`, `bq`; bundled Python 3.14.7. **No Google account:**
`fake_token_server.py` stands in for `oauth2.googleapis.com/token`, wired in
through gcloud's own `auth/token_host` property (`core/credentials/creds.py`
honours it when explicitly set). It answers every grant with
`ya29.FAKE-ACCESS-<n>`, optionally rotating the refresh token, and logs each
request. All work happens in a scratch dir; the real `~/.config/gcloud` is
never touched. Reproduce with `./run.sh` (or `./run.sh e4` for one).

## Result 1 — one login writes the refresh token to three files, and sometimes a log (E1)

| File | Holds | Mode |
|---|---|---|
| `credentials.db` | `refresh_token` in a JSON blob, plus gcloud's public client id/secret | 0600 |
| `legacy_credentials/<account>/adc.json` | the same refresh token | 0600 |
| `legacy_credentials/<account>/.boto` | the same refresh token (`gs_oauth2_refresh_token`) | 0600 |
| `access_tokens.db` | the current ~1h access token | 0600 |

So the secret set is exactly `credentials.db`, `access_tokens.db` and
`legacy_credentials/`. Everything else in the dir is settings
(`configurations/`, `active_config`, `default_configs.db` — which holds only
`client_arch` and a format flag — `gce`, `logs/`, update-check stamps).

**Side finding:** `logs/` records every command's arguments.
`gcloud auth activate-refresh-token ACCOUNT TOKEN` therefore writes the
refresh token into a log file in plaintext. Access tokens never appeared in
logs, including from `print-access-token`. jit's scan should sweep
`~/.config/gcloud/logs` for tokens; `gcloud auth login` (the browser flow)
puts no token on its command line.

## Result 2 — a symlinked-settings temp dir works, writes included (E2)

With `CLOUDSDK_CONFIG=<temp>`, the settings symlinked to the real dir and the
three secrets copied in:

- `auth list`, `config get-value project` read correctly.
- `config set compute/region` wrote **through** the symlink into the real
  `configurations/config_default`; the symlink survived.
- `config configurations create` and `activate` landed in the real dir; the
  temp `active_config` stayed a symlink.
- gcloud created nothing else in the temp dir: the only non-symlinks there
  afterwards were the three secrets jit put there.

**Settings never need resealing; only secrets do.**

## Result 3 — in normal use only `access_tokens.db` changes (E3, E4)

| Command | Refreshes | Rewrote |
|---|---|---|
| `auth list`, `config config-helper`, `print-access-token` (token valid) | 0 | nothing |
| `config list` | 1 | `access_tokens.db` |
| `print-access-token` (token expired) | 1 | `access_tokens.db` |
| `projects list` (token expired) | 2 | `access_tokens.db` |

**E4: gcloud does not persist a rotated refresh token** during a normal
refresh. With the fake endpoint returning a new `refresh_token`, gcloud used
the new access token but left `credentials.db`, `adc.json` and `.boto` on the
old refresh token. (At *activation*, the first spike run showed the rotated
token was stored — the store is written at login/activate, not on refresh.)

So `credentials.db` and `legacy_credentials/` are **write-once per login**:
they change on `gcloud auth login`, `auth activate-*`, `auth revoke`, and
nothing else seen here. That makes resealing simple and cheap:

- after any run, reseal `access_tokens.db` only if its content changed;
- reseal `credentials.db`/`legacy_credentials/` only after an `auth` command
  (or whenever their content hash changed — the cheaper rule to get right).

Whether real Google ever rotates a gcloud refresh token is **not verified**
here; if it did, gcloud itself would drop the new one, so jit would be no
worse than gcloud.

## Result 4 — concurrent runs can share one materialized dir (E5)

8 parallel `print-access-token` on one temp dir with an expired access token
and rotation on: **0 failures, 1–2 refreshes** across runs (the rest found
the fresh access token another process had just cached), stored refresh token unchanged. A refcounted shared
materialization (one dir per user while any gcloud-family process lives) is
safe; per-process dirs are not needed.

## Result 5 — who reads the store, and whether a `gcloud` shim catches them (E6–E8)

| Reader | How it gets credentials | Through a `gcloud` shim? |
|---|---|---|
| `gcloud` | the store | yes |
| `gke-gcloud-auth-plugin` (kubectl exec plugin) | runs `gcloud config config-helper --format=json`, found with `LookPath` | **yes** — the spy on PATH saw the call |
| `bq` | gcloud's store via the gcloud wrapper; works **without** `legacy_credentials/` | it is its own entry point: needs its own shim |
| `gsutil` | `legacy_credentials/<account>/.boto`; **Anonymous caller** without it | its own entry point: needs its own shim |
| `docker-credential-gcloud` | execs Python on gcloud's lib directly, reads `CLOUDSDK_CONFIG` itself | **no** — docker launches it by name from PATH, so it needs its own shim. Launched as docker would, without the env var, it reported no active account |
| `git-credential-gcloud` | same as the docker helper | **no** — needs its own shim |

So the wrap set is **five names**: `gcloud`, `bq`, `gsutil`,
`docker-credential-gcloud`, `git-credential-gcloud`. The GKE plugin is
covered by the `gcloud` shim. All five are what the cask links onto PATH
(plus `gke-gcloud-auth-plugin` in the SDK `bin/`), so a PATH shim dir sees
every normal launch. Absolute-path callers (IDE plugins) bypass it and see
"no active account" — loud, not a silent leak.

Terraform and client libraries use ADC (`application_default_credentials.json`),
not this store, and jit already migrates ADC.

## Result 6 — cost (E9)

Materialize + reseal with shell `cp`, no crypto: **46 ms**; one
`gcloud config get-value` alone: **273 ms**. jit in-process (Go, vault
decrypt of three small blobs) will be well under the shell figure. Not on the
critical path.

## Implication for the design

Buildable from existing pieces, with one new one:

1. **`jit migrate` for the gcloud store**: vault `credentials.db`,
   `access_tokens.db` and `legacy_credentials/` (whole-file blobs; the
   SQLite files are 12 KB), remove them from `~/.config/gcloud`, leave the
   settings, back up first like every migrate.
2. **Five shims** (the list above) that run the tool with
   `CLOUDSDK_CONFIG=<materialized dir>`.
3. **The new piece — a service-owned lease.** A shim `exec`s the tool, so
   nothing of jit survives to reseal. The service must own the dir:
   materialize on first request (consent as today), refcount by pid, watch
   exit with kqueue `EVFILT_PROC`/`NOTE_EXIT`, reseal changed secrets and
   erase when the count hits zero, force-reseal on screen lock/sleep, and
   sweep stale dirs at startup.
4. **Login is a capture**: `gcloud auth login` runs inside the materialized
   dir like any command; the reseal-on-change rule vaults the new store.
5. **Scan**: report `~/.config/gcloud/logs` lines carrying tokens (Result 1).

Open, not spike-shaped: what the dir's path is (per-user, `0700`, under
`$TMPDIR`), how `jit status`/doctor report a lease, and undo
(`jit migrate undo` puts the three secrets back).

## Cleanup

Everything ran under the scratch `WORK` dir; the fake token server is killed
on exit. The real `~/.config/gcloud` was created by the cask install's own
post-processing and holds no credentials. This directory holds source only.
