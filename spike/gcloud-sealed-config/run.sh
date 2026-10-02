#!/usr/bin/env bash
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# Spike: can gcloud's credential store live sealed (in a vault) and be
# materialized into a private CLOUDSDK_CONFIG only while a gcloud-family
# command runs? See FINDINGS.md for the questions and the results.
#
# Needs gcloud (brew install --cask gcloud-cli) with the components
# gke-gcloud-auth-plugin and bq. No Google account: a local fake token
# endpoint (fake_token_server.py) answers every refresh, wired in through
# gcloud's own auth/token_host property. Everything happens under $WORK;
# the real ~/.config/gcloud is never touched.
#
#   ./run.sh            # all experiments
#   ./run.sh e3         # one experiment
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-${TMPDIR:-/tmp}/gcloud-sealed-config}"
PORT="${PORT:-8765}"
SDKBIN="$(dirname "$(readlink -f "$(command -v gcloud)")")"
ACCOUNT="spike-user@example.com"
RT0="1//FAKE-REFRESH-TOKEN-abc123"

# The secret part of a gcloud config dir. Everything else is settings.
SECRETS=(credentials.db access_tokens.db legacy_credentials)

export CLOUDSDK_CORE_DISABLE_PROMPTS=1
export CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK=1

say()  { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }

start_server() { # ROTATE TTL
  stop_server
  : >"$WORK/req.jsonl"
  PORT=$PORT LOG="$WORK/req.jsonl" ROTATE="$1" TTL="$2" \
    python3 "$HERE/fake_token_server.py" >/dev/null 2>&1 &
  echo $! >"$WORK/server.pid"; disown
  for _ in $(seq 50); do nc -z 127.0.0.1 "$PORT" 2>/dev/null && return; sleep 0.1; done
  echo "fake token server did not start" >&2; exit 1
}
stop_server() { [ -f "$WORK/server.pid" ] && kill "$(cat "$WORK/server.pid")" 2>/dev/null; rm -f "$WORK/server.pid"; }
tmo() { perl -e 'alarm shift; exec @ARGV' "$@"; }   # macOS has no timeout(1)
refreshes() { wc -l <"$WORK/req.jsonl" | tr -d ' '; }

# A logged-in config dir, the way a user's ~/.config/gcloud looks.
make_real() {
  rm -rf "$WORK/real"; mkdir -p "$WORK/real"
  CLOUDSDK_CONFIG="$WORK/real" gcloud config set auth/token_host "http://127.0.0.1:$PORT/token" >/dev/null 2>&1
  CLOUDSDK_CONFIG="$WORK/real" gcloud config set project spike-proj >/dev/null 2>&1
  CLOUDSDK_CONFIG="$WORK/real" gcloud auth activate-refresh-token "$ACCOUNT" "$RT0" >/dev/null 2>&1
}

# "Migrate": move the secrets out of real/ into vault/ (a stand-in for the
# jit vault; here just a directory).
seal_real() {
  local s; rm -rf "$WORK/vault"; mkdir -p "$WORK/vault"
  for s in "${SECRETS[@]}"; do [ -e "$WORK/real/$s" ] && mv "$WORK/real/$s" "$WORK/vault/"; done
}

# Materialize: a private dir whose settings are symlinks into real/ and
# whose secrets are copies out of the vault.
materialize() { # DIR
  local t="$1" e s; rm -rf "$t"; mkdir -m 700 -p "$t"
  for e in "$WORK/real"/* "$WORK/real"/.[!.]*; do
    [ -e "$e" ] || continue
    ln -s "$e" "$t/$(basename "$e")"
  done
  for s in "${SECRETS[@]}"; do [ -e "$WORK/vault/$s" ] && cp -Rp "$WORK/vault/$s" "$t/"; done
}

# Fingerprint the secret files of a dir (content only, sorted).
fp() { (cd "$1" && find "${SECRETS[@]}" -type f 2>/dev/null | sort | while read -r f; do
  case "$f" in
    *.db) printf '%s %s\n' "$(sqlite3 "$f" .dump | shasum | cut -c1-12)" "$f" ;;
    *)    printf '%s %s\n' "$(shasum <"$f" | cut -c1-12)" "$f" ;;
  esac; done); }
changed() { diff <(echo "$1") <(echo "$2") | grep '^>' | awk '{print $3}' | tr '\n' ' '; }
stored_rt() { sqlite3 "$1/credentials.db" "select json_extract(value,'\$.refresh_token') from credentials"; }
expire_access() { sqlite3 "$1/access_tokens.db" "update access_tokens set token_expiry='2000-01-01 00:00:00'"; }

# ---------------------------------------------------------------------------

e1() {
  say "E1  where a login puts the refresh token, and what gcloud logs"
  start_server 0 3600; make_real
  note "files holding the refresh token:"
  grep -rl --exclude-dir=logs "$RT0" "$WORK/real" | sed "s|$WORK/real/|     |"
  local n; n=$(grep -rl "$RT0" "$WORK/real/logs" | wc -l | tr -d ' ')
  note "log files holding it: $n  (activate-refresh-token logs its TOKEN argument)"
  note "modes: $(stat -f '%Sp %N' "$WORK/real/credentials.db" "$WORK/real/access_tokens.db" | sed "s|$WORK/real/||g" | tr '\n' ' ')"
}

e2() {
  say "E2  a symlinked-settings temp CLOUDSDK_CONFIG: reads and settings writes"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t2"; materialize "$t"
  note "auth list:   $(CLOUDSDK_CONFIG=$t gcloud auth list --format='value(account)' 2>&1 | tr '\n' ' ')"
  note "project:     $(CLOUDSDK_CONFIG=$t gcloud config get-value project 2>/dev/null)"
  CLOUDSDK_CONFIG=$t gcloud config set compute/region us-east1 >/dev/null 2>&1
  note "set region through temp -> real config_default has: $(grep -c 'region = us-east1' "$WORK/real/configurations/config_default")"
  note "configurations/ still a symlink: $([ -L "$t/configurations" ] && echo yes || echo NO)"
  CLOUDSDK_CONFIG=$t gcloud config configurations create spike2 --no-activate >/dev/null 2>&1
  note "new configuration landed in real/: $([ -f "$WORK/real/configurations/config_spike2" ] && echo yes || echo NO)"
  CLOUDSDK_CONFIG=$t gcloud config configurations activate spike2 >/dev/null 2>&1
  note "activate -> real active_config: $(cat "$WORK/real/active_config"); temp active_config symlink: $([ -L "$t/active_config" ] && echo yes || echo 'NO (replaced by a file)')"
  CLOUDSDK_CONFIG=$t gcloud config configurations activate default >/dev/null 2>&1
  note "secrets left in real/: $(ls "$WORK/real" | grep -E 'credentials|access_tokens' | tr '\n' ' ')"
  note "new files gcloud created in temp (not symlinks):"
  find "$t" -maxdepth 1 -not -type l -not -path "$t" | sed "s|$t/|     |"
}

e3() {
  say "E3  which commands rewrite the secret files"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t3"; materialize "$t"
  run() { local before after r0; before=$(fp "$t"); r0=$(refreshes)
    CLOUDSDK_CONFIG=$t "$@" >/dev/null 2>&1
    after=$(fp "$t"); note "$(printf '%-44s' "$*") refreshes:+$(( $(refreshes) - r0 ))  rewrote: $(changed "$before" "$after")"; }
  run gcloud auth list
  run gcloud config list
  run gcloud auth print-access-token
  run gcloud auth print-access-token
  expire_access "$t"
  run gcloud auth print-access-token
  expire_access "$t"
  run gcloud projects list --limit 1
  run gcloud config config-helper --format=json
}

e4() {
  say "E4  a refresh that ROTATES the refresh token: where the new one is stored"
  start_server 0 3600; make_real; seal_real          # log in WITHOUT rotation
  local t="$WORK/t4"; materialize "$t"; expire_access "$t"
  start_server 1 3600                                 # now the provider rotates
  CLOUDSDK_CONFIG=$t gcloud auth print-access-token >/dev/null 2>&1
  note "refreshes: $(refreshes)  (server hands out 1//FAKE-ROTATED-<n>)"
  note "credentials.db now: $(stored_rt "$t")"
  note "adc.json now:       $(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['refresh_token'])" "$t/legacy_credentials/$ACCOUNT/adc.json")"
  note ".boto now:          $(grep refresh_token "$t/legacy_credentials/$ACCOUNT/.boto" | awk '{print $3}')"
  note "vault (not resealed): $(stored_rt "$WORK/vault")  <- a reseal that skips this loses the rotated token"
}

e5() {
  say "E5  concurrent commands sharing one materialized dir (rotation on)"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t5"; materialize "$t"; expire_access "$t"
  start_server 1 3600
  for i in $(seq 8); do (CLOUDSDK_CONFIG=$t gcloud auth print-access-token >/dev/null 2>"$WORK/c$i.err" || echo fail >"$WORK/c$i.fail") & done; wait
  note "8 parallel print-access-token: failures $(ls "$WORK"/c*.fail 2>/dev/null | wc -l | tr -d ' '), refreshes $(refreshes)"
  note "refresh token presented per request: $(python3 -c "import json;print([json.loads(l)['refresh_token'][-12:] for l in open('$WORK/req.jsonl')])")"
  note "stored afterwards: $(stored_rt "$t")"
  rm -f "$WORK"/c*.err "$WORK"/c*.fail
}

e6() {
  say "E6  gke-gcloud-auth-plugin: does it run gcloud from PATH?"
  local spy="$WORK/spybin"; rm -rf "$spy"; mkdir -p "$spy"
  cat >"$spy/gcloud" <<EOF
#!/bin/sh
echo "\$0 \$*" >>"$WORK/spy.log"
exec "$SDKBIN/gcloud" "\$@"
EOF
  chmod +x "$spy/gcloud"; : >"$WORK/spy.log"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t6"; materialize "$t"
  local out; out=$(PATH="$spy:$SDKBIN:$PATH" CLOUDSDK_CONFIG=$t "$SDKBIN/gke-gcloud-auth-plugin" 2>&1)
  note "plugin printed a token: $(echo "$out" | grep -o 'ya29[^"]*' | head -1)"
  note "gcloud calls seen through PATH: $(wc -l <"$WORK/spy.log" | tr -d ' ')"
  sed 's/^/     /' "$WORK/spy.log"
  note "plugin binary mentions: $(strings "$SDKBIN/gke-gcloud-auth-plugin" | grep -oE 'config config-helper|CLOUDSDK_CONFIG|LookPath' | sort -u | tr '\n' ' ')"
}

e7() {
  say "E7  bq and gsutil: which credential files do they need?"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t7"; materialize "$t"
  for tool in bq gsutil; do
    case $tool in bq) args=(ls --project_id=spike-proj);; gsutil) args=(ls gs://spike-bucket);; esac
    note "$tool, full dir:              $(CLOUDSDK_CONFIG=$t tmo 60 "$SDKBIN/$tool" "${args[@]}" 2>&1 | grep -m1 -E 'rror|nvalid|401|nonymous' | cut -c1-100)"
    mv "$t/legacy_credentials" "$t/legacy_credentials.off"
    note "$tool, no legacy_credentials/: $(CLOUDSDK_CONFIG=$t tmo 60 "$SDKBIN/$tool" "${args[@]}" 2>&1 | grep -m1 -E 'rror|nvalid|401|nonymous' | cut -c1-100)"
    mv "$t/legacy_credentials.off" "$t/legacy_credentials"
  done
  note "(Invalid Credentials = a fake token reached Google, i.e. credentials WERE found;"
  note " Anonymous caller = no credentials found at all)"
}

e8() {
  say "E8  docker-credential-gcloud and git-credential-gcloud (the cask links both onto PATH)"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t8"; materialize "$t"
  note "docker helper, materialized dir: $(echo https://gcr.io | CLOUDSDK_CONFIG=$t "$SDKBIN/docker-credential-gcloud" get 2>&1 | grep -o 'ya29[^"]*')"
  note "docker helper as docker runs it: $(echo https://gcr.io | env -u CLOUDSDK_CONFIG HOME="$WORK/emptyhome" "$SDKBIN/docker-credential-gcloud" get 2>&1 | grep -m1 -o 'You do not currently have an active account selected')"
  note "git helper, materialized dir:    $(printf 'protocol=https\nhost=source.developers.google.com\n\n' | CLOUDSDK_CONFIG=$t "$SDKBIN/git-credential-gcloud.sh" get 2>&1 | grep -c '^password=') password line(s)"
  note "both exec python on gcloud's lib directly; they never run 'gcloud' from PATH:"
  note "  $(grep -c 'CLOUDSDK_ROOT_DIR\|bootstrapping' "$SDKBIN/docker-credential-gcloud") bootstrapping refs in docker helper"
}

now_ms() { python3 -c 'import time;print(int(time.time()*1000))'; }
e9() {
  say "E9  materialize + reseal cost (cp only, no crypto)"
  start_server 0 3600; make_real; seal_real
  local t="$WORK/t9" a b x i
  a=$(now_ms)
  for i in $(seq 20); do materialize "$t"; for x in "${SECRETS[@]}"; do rm -rf "$WORK/vault.tmp"; cp -Rp "$t/$x" "$WORK/vault.tmp"; done; rm -rf "$t"; done
  b=$(now_ms); note "materialize+reseal: $(( (b-a)/20 )) ms each (shell cp; Go in-process will be lower)"
  a=$(now_ms); for i in $(seq 5); do CLOUDSDK_CONFIG="$WORK/real" gcloud config get-value project >/dev/null 2>&1; done
  b=$(now_ms); note "for scale, one 'gcloud config get-value': $(( (b-a)/5 )) ms"
}

mkdir -p "$WORK"; trap stop_server EXIT
if [ $# -eq 0 ]; then set -- e1 e2 e3 e4 e5 e6 e7 e8 e9; fi
for x in "$@"; do "$x"; done
