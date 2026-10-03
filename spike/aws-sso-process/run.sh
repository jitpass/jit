#!/usr/bin/env bash
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# Spike: can an AWS SSO login stay sealed (no ~/.aws/sso/cache or
# ~/.aws/cli/cache plaintext) while every SSO profile keeps working, by
# rewriting each profile to credential_process and letting AWS's own CLI do
# the refresh against a sealed cache under a temporary HOME? See FINDINGS.md.
#
# Needs the AWS CLI v2 (brew install awscli). No AWS account: a local fake
# of IAM Identity Center's SSO and SSO OIDC APIs (fake_sso_server.py) answers,
# wired in with AWS_ENDPOINT_URL_SSO / AWS_ENDPOINT_URL_SSO_OIDC. Everything
# happens under $WORK; the real ~/.aws is never touched.
#
#   ./run.sh        # all experiments
#   ./run.sh e4     # one
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-${TMPDIR:-/tmp}/aws-sso-process}"
PORT="${PORT:-8780}"
export AWS_ENDPOINT_URL_SSO="http://127.0.0.1:$PORT"
export AWS_ENDPOINT_URL_SSO_OIDC="http://127.0.0.1:$PORT"
export AWS_PAGER="" AWS_CLI_AUTO_PROMPT=off

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }
ms()   { python3 -c 'import time;print(int(time.time()*1000))'; }

start_server() { # ROTATE TTL
  stop_server
  : >"$WORK/req.jsonl"
  PORT=$PORT LOG="$WORK/req.jsonl" ROTATE="$1" TTL="$2" python3 "$HERE/fake_sso_server.py" >/dev/null 2>&1 &
  echo $! >"$WORK/server.pid"; disown
  for _ in $(seq 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && return; sleep 0.1; done
  echo "fake SSO server did not start" >&2; exit 1
}
stop_server() { [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null; rm -f "$WORK/server.pid"; }
ops() { python3 -c "import json,sys;print(' '.join(json.loads(l)['op']+('('+json.loads(l).get('grant','').split(':')[-1]+')' if json.loads(l).get('grant') else '') for l in open('$WORK/req.jsonl')))"; }
count() { grep -c "\"$1\"" "$WORK/req.jsonl" | tr -d ' '; }

SSO_SESSION='[sso-session corp]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access'

# The user's config as it is before jit: one SSO profile.
original_config() {
  cat <<EOF
[profile dev]
sso_session = corp
sso_account_id = 111122223333
sso_role_name = Developer
region = us-east-1

$SSO_SESSION
EOF
}

# The same config after the rewrite: the profile keeps sso_session (so
# `aws sso login --profile dev` still works) but loses account and role,
# which is what makes botocore's SSO credential provider stand down, and
# gains credential_process.
rewritten_config() {
  cat <<EOF
[profile dev]
sso_session = corp
credential_process = $HERE/jit_sso_process.sh dev
region = us-east-1

$SSO_SESSION
EOF
}

# A fresh user home with a native login in it.
fresh_login() {
  rm -rf "$WORK/home" "$WORK/vault" "$WORK"/run.* "$WORK"/*.log
  mkdir -p "$WORK/home/.aws" "$WORK/vault/sso-cache"
  original_config >"$WORK/home/.aws/config"
  HOME="$WORK/home" aws sso login --use-device-code --no-browser --sso-session corp >/dev/null 2>&1
}

# The migration the feature would do: token files into the vault, the
# original profile definitions into the sealed config, the user's config
# rewritten, the CLI's role-credential cache deleted.
seal() {
  mv "$WORK/home/.aws/sso/cache"/*.json "$WORK/vault/sso-cache/"
  original_config >"$WORK/vault/config.sealed"
  rewritten_config >"$WORK/home/.aws/config"
  rm -rf "$WORK/home/.aws/cli/cache"
}

as_user() { HOME="$WORK/home" REAL_HOME="$WORK/home" VAULT="$WORK/vault" "$@"; }
plaintext() { find "$WORK/home/.aws" -type f \( -path '*/sso/cache/*' -o -path '*/cli/cache/*.json' \) | sed "s|$WORK/home/||" | tr '\n' ' '; }
expire_vault_token() {
  python3 - "$WORK/vault/sso-cache" <<'EOF'
import json, glob, sys
for f in glob.glob(sys.argv[1] + "/*.json"):
    d = json.load(open(f))
    if "accessToken" in d:
        d["expiresAt"] = "2000-01-01T00:00:00Z"
        json.dump(d, open(f, "w"))
EOF
}
vault_refresh_token() { python3 -c "import json,glob;print([json.load(open(f)).get('refreshToken') for f in glob.glob('$WORK/vault/sso-cache/*.json') if 'accessToken' in json.load(open(f))][0])"; }

# ---------------------------------------------------------------------------

e1() {
  say "E1  what a native login and one credential fetch leave on disk"
  start_server 1 3600; fresh_login
  note "after aws sso login:  $(plaintext)"
  HOME="$WORK/home" aws configure export-credentials --profile dev --format process >/dev/null 2>&1
  note "after a credential fetch:  $(plaintext)"
  note "token file keys: $(python3 -c "import json,glob;print([sorted(json.load(open(f))) for f in glob.glob('$WORK/home/.aws/sso/cache/*.json') if 'accessToken' in json.load(open(f))][0])")"
  note "requests: $(ops)"
}

e2() {
  say "E2  the rewritten profile: credentials through the sealed cache"
  start_server 1 3600; fresh_login; seal
  : >"$WORK/req.jsonl"
  local out; out=$(as_user aws configure export-credentials --profile dev --format process 2>&1)
  note "outer fetch: $(echo "$out" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("AccessKeyId",d["AccessKeyId"],"Expiration",d.get("Expiration"))' 2>&1)"
  note "requests: $(ops)"
  note "plaintext in the real ~/.aws afterwards: [$(plaintext)]"
  note "files the inner run wrote in its temp HOME: $(sort -u "$WORK/tmpfiles.log" | tr '\n' ' ')"
  note "reseals: $(cat "$WORK/reseals.log" 2>/dev/null | wc -l | tr -d ' ')"
}

e3() {
  say "E3  aws sso login --profile dev still works on the rewritten profile, and is captured"
  start_server 1 3600; fresh_login; seal
  local login; login=$(as_user aws sso login --use-device-code --no-browser --profile dev 2>&1 | tail -1)
  note "login: $login"
  note "plaintext right after login: [$(plaintext)]"
  as_user aws configure export-credentials --profile dev --format process >/dev/null 2>&1
  note "plaintext after the next credential fetch: [$(plaintext)]"
  note "vault holds the new login's refresh token: $(vault_refresh_token)"
}

e4() {
  say "E4  an expired access token: AWS's own refresh, rotation sealed back"
  start_server 1 3600; fresh_login; seal
  local before; before=$(vault_refresh_token); expire_vault_token
  : >"$WORK/req.jsonl"; rm -f "$WORK/reseals.log"
  as_user aws configure export-credentials --profile dev --format process >/dev/null 2>&1
  note "requests: $(ops)"
  note "refresh token presented: $(python3 -c "import json;print([json.loads(l).get('refreshToken') for l in open('$WORK/req.jsonl') if json.loads(l)['op']=='CreateToken'])") (vault had $before)"
  note "vault refresh token now: $(vault_refresh_token); reseals: $(cat "$WORK/reseals.log" 2>/dev/null | wc -l | tr -d ' ')"
  note "plaintext in the real ~/.aws: [$(plaintext)]"
  : >"$WORK/req.jsonl"; rm -f "$WORK/reseals.log"
  as_user aws configure export-credentials --profile dev --format process >/dev/null 2>&1
  note "a second fetch, token fresh: requests $(ops); reseals $(cat "$WORK/reseals.log" 2>/dev/null | wc -l | tr -d ' ')"
}

e5() {
  say "E5  concurrent fetches with an expired token and rotation, without and with a lock"
  for lock in 0 1; do
    start_server 1 3600; fresh_login; seal; expire_vault_token
    : >"$WORK/req.jsonl"
    local fails=0 i
    for i in $(seq 6); do
      (LOCK=$lock as_user aws configure export-credentials --profile dev --format process >/dev/null 2>&1 || echo x >>"$WORK/fails") &
    done; wait
    fails=$(cat "$WORK/fails" 2>/dev/null | wc -l | tr -d ' '); rm -f "$WORK/fails"
    note "LOCK=$lock: 6 fetches, failures ${fails:-0}, refreshes $(count CreateToken), distinct refresh tokens presented: $(python3 -c "import json;print(len({json.loads(l).get('refreshToken') for l in open('$WORK/req.jsonl') if json.loads(l)['op']=='CreateToken'}))")"
  done
}

e6() {
  say "E6  cost of the extra hop"
  start_server 1 3600; fresh_login
  local a b
  a=$(ms); for _ in 1 2 3; do HOME="$WORK/home" aws configure export-credentials --profile dev --format process >/dev/null 2>&1; done; b=$(ms)
  note "native SSO profile fetch: $(( (b-a)/3 )) ms"
  seal
  a=$(ms); for _ in 1 2 3; do as_user aws configure export-credentials --profile dev --format process >/dev/null 2>&1; done; b=$(ms)
  note "rewritten profile fetch (outer CLI + helper + inner CLI): $(( (b-a)/3 )) ms"
}

e7() {
  say "E7  boto3 on the rewritten profile"
  if [ ! -x "$WORK/venv/bin/python" ]; then python3 -m venv "$WORK/venv" >/dev/null && "$WORK/venv/bin/pip" -q install boto3 >/dev/null 2>&1; fi
  start_server 1 3600; fresh_login; seal
  local out
  out=$(as_user "$WORK/venv/bin/python" -c 'import boto3;c=boto3.Session(profile_name="dev").get_credentials().get_frozen_credentials();print(c.access_key)' 2>&1 | tail -1)
  note "boto3 credentials: $out"
  note "plaintext in the real ~/.aws: [$(plaintext)]"
}

e8() {
  say "E8  no login yet / login expired: what the caller sees"
  start_server 1 3600; fresh_login; seal
  rm -f "$WORK/vault/sso-cache"/*.json
  local out code
  out=$(as_user aws configure export-credentials --profile dev --format process 2>&1); code=$?
  note "exit $code: $(echo "$out" | grep -v '^$' | tail -2 | tr '\n' ' ' | cut -c1-240)"
}

e9() {
  say "E9  the legacy (no sso-session) profile shape"
  start_server 1 3600
  rm -rf "$WORK/home" "$WORK/vault" "$WORK"/*.log; mkdir -p "$WORK/home/.aws" "$WORK/vault/sso-cache"
  printf '[profile old]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\nsso_account_id = 111122223333\nsso_role_name = Developer\n' >"$WORK/home/.aws/config"
  HOME="$WORK/home" aws sso login --use-device-code --no-browser --profile old >/dev/null 2>&1
  note "legacy token file keys: $(python3 -c "import json,glob;print([sorted(json.load(open(f))) for f in glob.glob('$WORK/home/.aws/sso/cache/*.json')])")"
  mv "$WORK/home/.aws/sso/cache"/*.json "$WORK/vault/sso-cache/"
  cp "$WORK/home/.aws/config" "$WORK/vault/config.sealed"
  printf '[profile old]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\ncredential_process = %s old\n' "$HERE/jit_sso_process.sh" >"$WORK/home/.aws/config"
  rm -rf "$WORK/home/.aws/cli/cache"
  local out; out=$(as_user aws configure export-credentials --profile old --format process 2>&1 | tr -d '\n' | cut -c1-80)
  note "rewritten legacy profile: $out"
  note "plaintext in the real ~/.aws: [$(plaintext)]"
}

e10() {
  say "E10 aws sso logout on the rewritten config"
  start_server 1 3600; fresh_login; seal
  : >"$WORK/req.jsonl"
  local out; out=$(as_user aws sso logout 2>&1 | tail -1)
  note "logout said: [${out}] requests: [$(ops)]; vault token files left: $(ls "$WORK/vault/sso-cache" | wc -l | tr -d ' ')"
}

e11() {
  say "E11 an ordinary aws command on the rewritten profile: does the CLI cache the result?"
  start_server 1 3600; fresh_login; seal
  : >"$WORK/req.jsonl"
  as_user aws s3 ls --profile dev --endpoint-url http://127.0.0.1:1 --cli-connect-timeout 1 >/dev/null 2>&1
  note "requests: $(ops) (credentials were resolved before the S3 call failed)"
  note "plaintext in the real ~/.aws: [$(plaintext)]"
}

e12() {
  say "E12 signing out: aws sso logout run on the sealed cache, under the temp HOME"
  start_server 1 3600; fresh_login; seal
  : >"$WORK/req.jsonl"
  local tmp; tmp=$(mktemp -d "$WORK/run.XXXXXX"); mkdir -p "$tmp/.aws/sso/cache"; cp "$WORK/vault/sso-cache"/*.json "$tmp/.aws/sso/cache/"
  HOME="$tmp" AWS_CONFIG_FILE="$WORK/vault/config.sealed" aws sso logout >/dev/null 2>&1
  note "requests: $(ops) (the CLI's server-side Logout call; the fake answers 404)"
  note "token files left in the temp HOME: $(ls "$tmp/.aws/sso/cache" | wc -l | tr -d ' ') (reseal that: the vault then holds no login)"
  rm -rf "$tmp"
}

mkdir -p "$WORK"; trap stop_server EXIT
if [ $# -eq 0 ]; then set -- e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12; fi
for x in "$@"; do "$x"; done
