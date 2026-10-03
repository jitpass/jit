# Spike Findings: AWS SSO without a plaintext token cache

**Question:** `aws sso login` leaves an IAM Identity Center token in
`~/.aws/sso/cache` in plaintext. With an `sso_session` config the token
carries a `refreshToken`, so a copy of the file mints role credentials for
**every account and role the user is assigned** until the Identity Center
session ends (8 h by default, up to 90 days). Every credential fetch also
writes the role credentials to `~/.aws/cli/cache` (up to 12 h). Can jit keep
both caches off disk while every SSO profile keeps working, without speaking
SSO or STS itself?

The candidate (`design/minting-broker.md` B1's "exec the vendor" shape):
rewrite each SSO profile to `credential_process = jit aws-sso <profile>`; jit
unseals the token cache into a private temp `HOME` and runs AWS's own
`aws configure export-credentials` against the original profile, so AWS's
code does the refresh, the rotation and `GetRoleCredentials`; jit seals the
cache again if the run changed it.

**Environment:** macOS (Darwin 27.0.0, arm64), AWS CLI 2.37.7
(`brew install awscli`, bundled Python 3.14.8), boto3 in a venv for E7.
**No AWS account:** `fake_sso_server.py` stands in for the SSO OIDC and SSO
portal APIs (RegisterClient, StartDeviceAuthorization, CreateToken for the
device-code and refresh grants, GetRoleCredentials), wired in with the CLI's
own `AWS_ENDPOINT_URL_SSO_OIDC` / `AWS_ENDPOINT_URL_SSO`. `jit_sso_process.sh`
is the stand-in for the jit command. All work happens under a scratch dir;
the real `~/.aws` is never touched. Reproduce with `./run.sh` (or
`./run.sh e4`).

## Result 1 — what lands on disk today (E1)

| File | Holds | Written by |
|---|---|---|
| `~/.aws/sso/cache/<sha1(session)>.json` | `accessToken`, `refreshToken`, `clientId`, `clientSecret`, `expiresAt`, `registrationExpiresAt` | `aws sso login`, every refresh |
| `~/.aws/sso/cache/<sha1(...)>.json` | the client registration (`clientId`, `clientSecret`, `scopes`) | `aws sso login` |
| `~/.aws/cli/cache/<sha1>.json` | role credentials (`ProviderType: sso`) | every CLI credential fetch for an SSO profile, including `export-credentials` |
| `~/.aws/cli/cache/session.db` | the CLI's telemetry session id (SQLite) | any CLI run; no secret |

Both cache paths come from `os.path.expanduser("~/.aws/...")`, evaluated at
import, so `HOME` set before the CLI starts redirects them entirely.

Also noticed: CLI 2.37 has a `~/.aws/login/cache` (the `aws login`
console-credentials flow). Not in scope here; a store for the scan to learn.

## Result 2 — the rewrite works, and nothing is left in plaintext (E2, E7, E9, E11)

The rewritten profile:

```ini
[profile dev]
sso_session = corp                 # kept: `aws sso login --profile dev` needs it
credential_process = jit aws-sso dev
region = us-east-1
```

It works because of one line in botocore's `SSOProvider._load_sso_config`:
the SSO credential provider applies only when the profile has
`sso_account_id` or `sso_role_name` ("Role name & Account ID indicate the
cred provider should be used"). Without them it returns None and the chain
falls through to `custom-process`. The original definitions (with account
and role) live in a jit-owned config passed to the inner run as
`AWS_CONFIG_FILE`.

- `aws configure export-credentials --profile dev` (E2), `aws s3 ls
  --profile dev` (E11) and **boto3** (E7) all get credentials through it.
- The real `~/.aws` holds **no** `sso/cache` and **no** `cli/cache` file
  afterwards: the CLI does not disk-cache credential_process output (E11),
  and whatever the inner run writes (role credentials, telemetry) lives and
  dies in its temp `HOME`.
- The legacy shape (`sso_start_url` in the profile, no `sso-session`) works
  the same way (E9).

**One trap, found the hard way (E2):** `aws configure export-credentials`
guards against loops with `_AWS_CLI_PROFILE_CHAIN`. An outer `aws configure
export-credentials --profile dev` sets it to `dev`, and the inner run,
resolving `dev` against the sealed config, refused with "profile cycle: dev
-> dev". It is not a cycle (the inner `dev` is the SSO profile), so jit must
clear that variable for the inner run.

## Result 3 — logging in keeps working, and is captured (E3)

`aws sso login --profile dev` on the rewritten profile succeeds (the token
provider needs only `sso_session`), and writes the new token to the real
cache in plaintext. The next credential fetch moves it into the vault and
leaves the real cache empty. The plaintext window is from login to the
first use, which is usually seconds, since a person logs in to use it.

## Result 4 — refresh is AWS's own, and the rotation must be resealed (E4)

With the access token expired, the inner run sends `CreateToken`
(refresh_token grant) with the **sealed** refresh token, then
`GetRoleCredentials`. Unlike gcloud, botocore **stores the rotated refresh
token** (`tokens.py`, `_attempt_create_token`), so the cache changes on
every refresh: the vault must take it back, or the next run presents a
refresh token Identity Center has already rotated away. A fetch with a fresh
token changes nothing and reseals nothing.

## Result 5 — concurrent fetches need a lock (E5)

Six fetches at once with an expired token, rotation on:

| | refreshes | distinct refresh tokens presented | failures |
|---|---|---|---|
| no lock | **6** | 1 | 0 (the fake accepts reuse) |
| exclusive lock around unseal, run, reseal | **1** | 1 | 0 |

Without a lock every run refreshes with the same token; real Identity
Center may reject a rotated-out one, and the last writer wins. With the
lock, one run refreshes and the others read its result. (Harness note:
perl's flock descriptor is close-on-exec, so the lock must be held across
`system`, not `exec`.)

## Result 6 — cost (E6)

| | ms per credential fetch |
|---|---|
| native SSO profile | 196 |
| rewritten profile (outer CLI → helper → inner CLI) | 458 |

About 260 ms per process that resolves credentials, almost all of it the
inner CLI's Python start. Long-lived SDK processes resolve once per hour.
A short-lived `aws` command pays it every time; caching the role
credentials in the agent's memory (never on disk) would remove it, and is a
follow-up, not a precondition.

## Result 7 — failure and sign-out (E8, E10, E12)

- No login (or an expired session): the inner CLI says `Error loading SSO
  Token: Token for corp does not exist`, exit 253, and the outer CLI
  surfaces it. jit should say instead which `aws sso login` to run.
- `aws sso logout` on the rewritten config does nothing: the real cache is
  empty, so it neither calls the server nor touches the vault (E10). Run
  under the temp `HOME` on the sealed cache, it calls the server-side Logout
  and deletes the token file (E12); resealing that leaves the vault with no
  login. So jit needs its own sign-out (`jit aws-sso logout`).

## Implication for the design

Buildable without SSO, OIDC or SigV4 code in jit: AWS's CLI does every
network call. The pieces:

1. **Migration** (`jit migrate ~/.aws/config` or a dedicated command): for
   each SSO profile, copy its definition into a jit-owned sealed config,
   drop `sso_account_id`/`sso_role_name`, add `credential_process`; vault
   the token cache (one canonical blob, like the gcloud store, backed up
   first); delete `~/.aws/cli/cache` SSO entries. Undo restores the profile
   lines and the token files.
2. **`jit aws-sso <profile>`** (credential_process): capture a fresh login
   from the real cache, unseal into a 0700 run dir in jit's root (not
   `$TMPDIR`), run `aws configure export-credentials` with `HOME`,
   `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE=/dev/null` and
   `_AWS_CLI_PROFILE_CHAIN` cleared, reseal on change under an exclusive
   lock, print the JSON, translate "no token" into the login command.
3. **`jit aws-sso logout`**: the inner `aws sso logout`, then reseal.
4. **Scan**: the SSO cache finding points at the fix; `~/.aws/login/cache`
   joins the inventory.

The sealed config is not secret (start URLs, account ids, role names), but
it is the only copy of the original definitions once the user's config is
rewritten, so it lives in jit's root and is restored by undo and
`uninstall --restore`.

## Not verified

- Real Identity Center's behaviour on a reused, rotated-out refresh token
  (the fake accepts it; the lock makes the question moot for jit).
- Whether real Identity Center returns a refresh token to the legacy
  (no `sso-session`) flow; the fake always does.
- Other SDKs (aws-sdk-go-v2 in Terraform, the JS SDK): they read
  `credential_process` by the same documented contract, but were not run.
