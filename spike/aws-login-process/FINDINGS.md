# Spike Findings: `aws login` sessions without a plaintext cache

**Question:** `aws login` (AWS CLI 2.32+, console credentials) leaves a
session in `~/.aws/login/cache/<sha256(session)>.json`: a refresh token next
to the DPoP private key meant to bind it to this machine, so a copy of the
file works anywhere. Can the AWS SSO mechanism (`spike/aws-sso-process`,
`design/aws-sso-sealed.md`) seal it too?

**Environment:** AWS CLI 2.37.7 (bundled botocore). `fake_signin.py` stands
in for the Sign-In service's `CreateOAuth2Token` (`POST /v1/token`,
rest-json, the body is the TokenInput itself), wired in with the CLI's own
`AWS_ENDPOINT_URL_SIGNIN`. The cache entry is hand-built with a real P-256
key (`openssl ecparam -name prime256v1 -genkey`), its access token expired.

## Result 1: the credential half works exactly like SSO

- botocore's `LoginProvider` claims a profile iff it has `login_session`
  (credentials.py, `LoginProvider.load`), so a profile that loses
  `login_session` and gains `credential_process` falls through to the
  process, as SSO profiles do.
- The inner run (`HOME` = a temp dir holding the unsealed cache,
  `AWS_CONFIG_FILE` = the sealed config with `login_session`,
  `_AWS_CLI_PROFILE_CHAIN` cleared) refreshed the expired session: one
  `CreateOAuth2Token`, refresh grant, **signed with the sealed DPoP key**
  (the DPoP header was present), and printed credentials.
- botocore **saved the rotated refresh token** to the cache
  (`rt-original` → `rt-rotated-1`): the vault must take it back, under a
  lock, as for SSO.
- A second fetch with the token fresh made **no** request.
- A rewritten profile in a fresh home, through a stand-in helper, returned
  the credentials and left **zero** files in that home.

## Result 2: logging in again is not like SSO

`aws login --profile dev` on the rewritten profile refuses:

```
Profile 'dev' is already configured with Credential Process credentials.
```

(`ensure_profile_does_not_have_existing_credentials`, login.py). It never
writes anything. So re-login must go through jit: run AWS's own `aws login`
with `AWS_CONFIG_FILE` = the sealed config (where `login_session` lives and
where the CLI writes the new one) and `HOME` = a run dir (where it caches
the new session), then seal the result. The browser flow is AWS's,
unchanged.

## Result 3: credentials are short

The session's credentials last 15 minutes (`expiresIn` 900 in the refresh
response botocore expects), so the service's role-credential cache, which
serves nothing with under 15 minutes left, rarely helps here. Speed, not
correctness.

## Implication

Buildable on the SSO machinery, generalised over "which cache, which
profile key": `login_session` instead of the SSO role keys,
`~/.aws/login/cache` instead of `~/.aws/sso/cache`. Plus a jit login
command, since `aws login` refuses the rewritten profile, and a comment in
the rewritten profile saying so.

Built (design/aws-sso-sealed.md D11). `TestAWSLoginE2E` drives the real
CLI's cross-device sign-in (`aws login --remote`, its code pasted back)
against the fake, natively and through `jit aws-sso login`. Not verified:
a sign-in against AWS itself; the login half runs AWS's code unchanged,
under a different `HOME` and config file.
