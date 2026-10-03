# Spec: AWS SSO logins, sealed in the vault

Status: built 2026-10-02 (spike #212; build #213, #215, #217; QA fixes for
2.4.0, see D7 and D12)
Scope: IAM Identity Center logins the AWS CLI caches in
`~/.aws/sso/cache`, the role credentials it caches in `~/.aws/cli/cache`,
and the `~/.aws/config` profiles that use them.
Non-goals: minting in jit (no SSO, OIDC or SigV4 code, `minting-broker.md`
Part C stays rejected).

Extended 2026-10-02 to `aws login` console sessions (`~/.aws/login/cache`),
D11 below; evidence `spike/aws-login-process/FINDINGS.md`.

Evidence: `spike/aws-sso-process/FINDINGS.md` (E1–E12, AWS CLI 2.37.7,
boto3). Companion: `design/gcloud-sealed-store.md`, whose run-dir and
reseal machinery this reuses.

## Problem

`aws sso login` writes an IAM Identity Center token to
`~/.aws/sso/cache/<sha1>.json` in plaintext. With an `sso_session` config it
carries a refresh token: a copy mints role credentials for every account
and role the user is assigned until the Identity Center session ends (8 h
by default, up to 90 days). Every credential fetch then writes those role
credentials to `~/.aws/cli/cache` (up to 12 h). jit reported both as
advisories it could not act on.

## The mechanism

```
~/.aws/config, rewritten                  <jit root>/aws-sso/config (sealed copy, 0600)
[profile dev]                             [profile dev]
sso_session = corp                        sso_session = corp
credential_process = jit aws-sso          sso_account_id = 111122223333
  --profile dev                           sso_role_name = Developer
region = us-east-1                        [sso-session corp] …
[sso-session corp] …
                                          vault: aws-sso/cache (tar of ~/.aws/sso/cache)
aws s3 ls --profile dev
  → credential_process → jit aws-sso --profile dev
      1. capture: a login `aws sso login` just left in ~/.aws/sso/cache joins the vault copy
      2. lock; unseal the cache into <jit root>/aws-sso-run/<id>/.aws/sso/cache
      3. HOME=<run dir> AWS_CONFIG_FILE=<sealed config> AWS_SHARED_CREDENTIALS_FILE=/dev/null
         aws configure export-credentials --profile dev --format process
         (AWS's own code: refresh, rotation, GetRoleCredentials)
      4. reseal the cache if it changed; remove the run dir; unlock
      5. print the JSON
```

### Decisions

**D1. The profile keeps `sso_session`, loses account and role.** botocore's
SSO credential provider applies only when a profile has `sso_account_id` or
`sso_role_name` (spike Result 2), so the chain falls through to
`credential_process`; `aws sso login --profile dev` keeps working because
login needs only `sso_session`. The legacy shape (`sso_start_url` in the
profile) is rewritten the same way and keeps its start URL and region.

**D2. The original definitions live in a sealed config in jit's root.** Not
secret (start URLs, account ids, role names), but after the rewrite it is
the only copy, so it is a file jit owns (`<root>/aws-sso/config`, 0600),
written at migration, merged on a later migration, and passed to the inner
run as `AWS_CONFIG_FILE`. Undo restores the original `~/.aws/config` from
its backup, so the sealed copy is never needed to put things back.

**D3. One vault value for the whole token cache, class `aws`.** The cache
directory is packed as one canonical tar (`sealstore`), one decrypt per
fetch, so one consent prompt naming the `aws` credential.

**D4. Reseal on change, under a lock.** botocore rotates the refresh token
on every refresh and stores the new one (spike Result 4), so the cache
changes about hourly while in use; the vault must take it back. The read
that started the run unlocked the session, so the write rides the same
session. An exclusive `flock` around unseal–run–reseal turns concurrent
refreshes into one (Result 5): without it, every run presents the same
refresh token and the last writer wins.

**D5. A native login is captured, not intercepted.** `aws sso login` keeps
writing to the real cache; the next fetch (seconds later, as a rule) moves
it into the vault. No `aws` shim. The plaintext window is login-to-first-use.

**D6. The inner run is isolated.** `HOME` is the run dir (both caches
resolve under it: `expanduser`, Result 1), `AWS_SHARED_CREDENTIALS_FILE` is
`/dev/null`, and `_AWS_CLI_PROFILE_CHAIN` is cleared: export-credentials'
loop guard would otherwise refuse `dev` inside an outer `export-credentials
--profile dev` (Result 2). Role credentials the inner CLI caches die with
the run dir; the outer CLI never caches credential_process output (E11).

**D7. Role credentials are cached in the service's memory.** Each fetch
that runs the inner CLI costs about 260 ms (Result 6), and the role
credentials it returns live an hour. The service keeps them, by profile,
and `jit aws-sso` asks it first (`internal/agent/awscache.go`, ops
`aws_cache_get`, `aws_cache_put`, `aws_cache_clear`). Rules:

- Memory only, dropped on every re-lock with the consent cache; served only
  while more than 15 minutes remain (botocore refreshes inside that).
- A read passes the same consent gate an aws unwrap does, naming the
  caller, and needs a live session; a miss prompts nothing.
- A write is accepted only from a process that completed a consented unwrap
  of an aws-class secret in this session, within 5 minutes, anchored to its
  fork time. The threat is a filler that lies: a socket client planting
  credentials for an account it controls, so the user's next upload goes
  there. Such a client has read nothing and is refused; a process that has
  read the sealed login already held more than a cache entry is worth.
- A new login (captured) and a sign-out clear it; a login waiting in the
  real cache bypasses it, so a real fetch seals that login promptly.
- An older service answers "unknown op", which the CLI reads as a miss: no
  protocol bump.

**D8. Signing out is `jit aws-sso logout`.** Plain `aws sso logout` finds
an empty real cache and does nothing (E10). jit's runs AWS's logout on the
unsealed cache (server-side Logout, token file deleted) and reseals.

**D9. Part of the `aws` migrate category.** `~/.aws/credentials` keys and
`~/.aws/config` SSO profiles are both "AWS": `jit migrate ~/.aws/config`,
`--only aws`, `jit wrap aws` and bare `jit migrate` (from the scan finding)
all include it.

**D10. Undo and Remove JitPass give back a live login.** Per-file backups
of the token cache are taken at sealing only (a backup per hourly reseal
would pile up); restoring from them would hand back a refresh token
Identity Center has since rotated away. So both undo and `uninstall
--restore` write the cache back from the vault's current copy.

**D11. `aws login` sessions share the store, not the login path.** The
vault value holds `~/.aws`'s `sso/` and `login/` (one tar, the layout
relative to `~/.aws`), so one unseal and one prompt serve both kinds. An
`aws login` profile is claimed by botocore's login provider iff it has
`login_session`, so sealing removes that key (the sealed config keeps it)
and adds the same `credential_process`. Three differences from SSO:

- **Per-profile sessions.** A session's file is `sha256(login_session)`,
  so sealing takes exactly the sealed profiles' sessions
  (`sealstore.MergeFiles`). Another profile's session stays on disk,
  where that profile reads it.
- **No capture.** `aws login` refuses a profile with `credential_process`
  (spike Result 2), so a session that appears in `~/.aws/login/cache` is
  an unsealed profile's and is left alone.
- **Re-login is `jit aws-sso login`.** It runs AWS's own `aws login` (or
  `aws sso login` for an SSO profile) against the sealed config, with the
  run dir as HOME, under the run lock, then reseals. The browser flow is
  AWS's; the new session never touches `~/.aws`. The rewritten profile
  carries a comment that says so, because the CLI's refusal tells the user
  to delete the `credential_process` line.

`jit aws-sso logout` also runs `aws logout --all` when the sealed store
holds a session. That is local only, as it is in the AWS CLI; a password
change is what ends a session (botocore `LoginRefreshPasswordChanged`).
`AWS_LOGIN_CACHE_DIRECTORY` is dropped from the inner environment, so the
cache resolves into the run dir.

**D12. The cache proof is the sign-in's own class (2.4.0 QA).** The fill
proof was first "a consented unwrap of an aws-class secret". Release QA
found two ways around it: the grant path recorded a proof on the caller's
unverified class claim, so any process under a grant (a grant-wrapped
npm's postinstall) could earn one; and `jit run --profile <aws keys>`
reads aws-class keys and then execs the user's program, which keeps the
pid and fork time the proof is anchored to. So the sealed sign-in has its
own class, `aws_signin` (vault.ClassAWSSignIn): the proof is a read of
THAT class, AEAD-verified on the normal unwrap path, and never recorded
on the grant path. The cache read is gated on the same class, so a fetch
asks one consent question. Fills, refused fills and clears are audited
(a refused fill collapsed on its op, since any client can trigger it).

## Limits

- While a fetch runs, the run dir holds the token in plaintext (owner-only,
  jit's root, removed after; a killed run's dir is swept by the next run and
  at service start).
- Between `aws sso login` and the first fetch, the login is in plaintext.
- A program that reads `~/.aws/sso/cache` itself rather than going through
  the profile's credential_process (a hand-rolled SSO client) sees no login.
- A native `aws sso login` is captured only for a start URL the sealed
  profiles sign in to (2.4.1); a profile sharing that start URL but not
  sealed still loses its token to the vault, until
  `jit migrate ~/.aws/config` seals it too.
