#!/usr/bin/env bash
# pre-release-live-test.sh — jit end-to-end live smoke test, run before cutting a release.
#
# WHY THIS EXISTS
#   `go test ./...` proves the units. This proves the SHIPPED binary actually
#   protects secrets on a real Mac: real keychain, real Touch ID, real FIFO
#   mounts, real credential_process, real docker/git helpers. Run it against
#   the release-candidate binary before `git tag` + publish.
#
# SAFETY MODEL (read before running)
#   jit has ONE machine-global vault (no data-dir override) and no auth-bypass,
#   so this test necessarily runs against your REAL vault and is ATTENDED — you
#   approve Touch ID prompts as they come. It stays safe by:
#     • Namespacing every test secret under "jit-e2e" and removing each on exit.
#     • Snapshotting your real vault count at start and ASSERTING it returns to
#       that baseline at the end (proof nothing of yours was touched).
#     • Backing up ~/.aws, ~/.docker, ~/.gitconfig before the phases that write
#       them and restoring them in teardown (trap-protected, even on failure).
#     • Keeping `vault delete` behind --destructive (export-first), never default.
#
# USAGE
#   scripts/pre-release-live-test.sh [options]
#     --phase LIST     run only these phases, comma-separated (e.g. --phase 3,4)
#     --os-creds       also run phase 7 (docker/git helpers — writes real
#                      ~/.docker & ~/.gitconfig, backed up + restored)
#     --destructive    also run phase 9 (vault delete → init → import restore)
#     --keep           skip teardown (leave artifacts for debugging)
#   The full pre-release gate is:  scripts/pre-release-live-test.sh --os-creds --destructive
#     -h, --help       this help
#   Env:
#     JIT_BIN=/path/to/jit   test a specific binary (default: `jit` on PATH)
#
# EXIT: 0 = all checks passed, 1 = one or more failed, 2 = harness/setup error.
set -uo pipefail

# ---------------------------------------------------------------- presentation
if [ -t 1 ]; then
  RST=$'\e[0m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; BLD=$'\e[1m'
else
  RST=''; RED=''; GRN=''; YEL=''; BLU=''; BLD=''
fi
section(){ printf "\n${BLD}${BLU}━━ %s ━━${RST}\n" "$1"; }
info(){ printf "  ${BLU}·${RST} %s\n" "$1"; }
gesture(){ printf "  ${YEL}⤷ Touch ID incoming: %s${RST}\n" "$1"; }
PASS=0; FAIL=0; declare -a FAILED=()
pass(){ PASS=$((PASS+1)); printf "  ${GRN}✓${RST} %s\n" "$1"; }
fail(){ FAIL=$((FAIL+1)); FAILED+=("$1"); printf "  ${RED}✗ %s${RST}\n" "$1"; }

# ------------------------------------------------------------------- assertions
expect_contains(){ case "$2" in *"$3"*) pass "$1";; *) fail "$1 — expected to contain: $3";; esac; }
expect_missing(){  case "$2" in *"$3"*) fail "$1 — should NOT contain: $3";; *) pass "$1";; esac; }
expect_exit(){ if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 — exit $3, wanted $2"; fi; }
expect_file(){ if [ -f "$2" ]; then pass "$1"; else fail "$1 — no regular file at $2"; fi; }
expect_fifo(){ if [ -p "$2" ]; then pass "$1"; else fail "$1 — not a FIFO at $2"; fi; }
expect_eq(){ if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 — got '$2', wanted '$3'"; fi; }

# ---------------------------------------------------------------------- globals
JIT="${JIT_BIN:-jit}"
NS="jit-e2e"                 # every test secret path contains this
PROJ_NAME="jit-e2e-proj"    # migrate derives the profile name from the dir base
CLISSO_APP="jit-e2e-aws"    # → profile aws-jit-e2e-aws
WRAP_TOOL="jit-e2e-tool"    # → profile wrap-jit-e2e-tool
WORK=""; BASELINE=""; CLEANED=0
KEEP=0; DESTRUCTIVE=0; OS_CREDS=0; PHASES="0,c,1,2,3,4,5,6,8"
EXPORT_PASS="e2e-export-passphrase"

die(){ printf "${RED}harness error: %s${RST}\n" "$1" >&2; exit 2; }

# real files the OS-integration phases overwrite; saved here, restored in teardown
declare -a SAVED=()
save_real(){ # save_real <path>
  local p=$1 b
  [ -e "$p" ] || { SAVED+=("$p::MISSING"); return; }
  b="$WORK/realbak/$(echo "$p" | tr '/' '_')"
  mkdir -p "$WORK/realbak"
  cp -a "$p" "$b" && SAVED+=("$p::$b")
}
restore_real(){
  local entry p b
  for entry in "${SAVED[@]:-}"; do
    [ -n "$entry" ] || continue
    p=${entry%%::*}; b=${entry##*::}
    rm -rf "$p"
    if [ "$b" != "MISSING" ] && [ -e "$b" ]; then
      mkdir -p "$(dirname "$p")"; cp -a "$b" "$p"
    fi
  done
  SAVED=()
}

# ------------------------------------------------------------- vault bookkeeping
# Only real secret-path lines (e.g. "netrc/PW"); drops the human summary footer
# and blank lines that `vault list` prints, which would otherwise be miscounted.
vault_paths(){ "$JIT" vault list --all 2>/dev/null | grep -E '^[A-Za-z0-9._-]+/'; }
# LIVE secrets NOT under our namespace — must be identical before and after the run.
# Excludes _backups: migrate-undo backups are cruft, not the invariant we assert.
real_secret_count(){ vault_paths | grep -vE '^_backups' | grep -vE "${NS}|${CLISSO_APP}|${WRAP_TOOL}|${PROJ_NAME}" | grep -cE '.'; }
list_test_secrets(){ vault_paths | grep -vE '^_backups' | grep -E "${NS}|${CLISSO_APP}|${WRAP_TOOL}|${PROJ_NAME}"; }

# One unlock covers the whole run. Only `jit vault <sub>` commands force their
# own gesture (they never ride the session, by design); migrate/clisso/run/
# export/unmount/docker/git all ride an unlocked session — so pre-unlocking with
# a generous TTL turns dozens of would-be prompts into zero.
SAVED_TTL=""
session_setup(){
  SAVED_TTL=$("$JIT" service ttl 2>/dev/null | grep -oE '[0-9]+[hms]([0-9]+[ms])*' | head -1)
  "$JIT" service ttl 45m >/dev/null 2>&1
  gesture "one unlock — covers every session-backed op for the whole run"
  "$JIT" unlock >/dev/null 2>&1
}
session_restore(){ [ -n "$SAVED_TTL" ] && "$JIT" service ttl "$SAVED_TTL" >/dev/null 2>&1; }

# Walk the ENTIRE command tree straight from the binary so no command,
# subcommand, or flag can be silently missing/broken. Prompt-free: it only
# reads --help and probes an unknown flag. Behavioral flag coverage lives in the
# other phases; this proves the surface is wired and parses.
CMD_N=0
walk_cmd(){
  local path="$*"
  # </dev/null on every probe: the credential-helper plumbing (docker-credential,
  # git-credential, …) reads its protocol from stdin, and an unknown flag can
  # drop it into that read — EOF makes it exit instead of hanging the sweep.
  local help rc; help=$("$JIT" $path --help </dev/null 2>&1); rc=$?
  CMD_N=$((CMD_N+1))
  expect_exit "cmdtree: 'jit ${path:-<root>} --help' exits 0" "0" "$rc"
  expect_contains "cmdtree: 'jit ${path:-<root>} --help' shows Usage" "$help" "Usage:"
  # an unknown flag must fail cleanly — never a Go panic
  local bad; bad=$("$JIT" $path --jit-e2e-nope-flag </dev/null 2>&1)
  expect_missing "cmdtree: 'jit ${path:-<root>}' no panic on unknown flag" "$bad" "panic:"
  # Enumerate REAL subcommands only. At the root, __complete lists the top-level
  # commands (root takes no args, so completions are commands). Below the root,
  # parse the "Available Commands:" section of --help — a leaf like `vault get`
  # has no such section (its completion returns secret PATHS, which must NOT be
  # walked as commands), so recursion stops exactly at the leaves.
  local subs
  if [ -z "$path" ]; then
    subs=$("$JIT" __complete "" 2>/dev/null | grep -v '^:' | awk -F'\t' '{print $1}')
  else
    subs=$(printf '%s' "$help" | awk '
      /^Available Commands:/{f=1;next}
      /^(Flags|Global Flags|Additional help topics):/{f=0}
      f && /^  [a-z]/{print $1}')
  fi
  local s
  for s in $subs; do
    case "$s" in help|completion|"") continue;; esac  # cobra built-ins
    walk_cmd "$path $s"
  done
}
phasecmd(){
  section "Phase C · Command-tree completeness (every command/subcommand/flag)"
  CMD_N=0
  walk_cmd ""
  # hidden plumbing commands (invoked by other tools) — completion omits them,
  # but their --help must still render; sweep them explicitly.
  local pc
  for pc in aws-credential-process clisso-capture docker-credential git-credential \
            k8s-exec-credential sops-age-key terraform-credentials; do
    walk_cmd "$pc"
  done
  info "$CMD_N command node(s) swept (help renders + unknown flag rejected cleanly)"
}

# ------------------------------------------------------------------- fixture gen
make_fixtures(){
  local d="$WORK/$PROJ_NAME"; mkdir -p "$d"
  # a realistic .env: production indicator + real-shaped vendor secrets
  cat > "$d/.env" <<EOF
APP_ENV=production
DATABASE_URL=postgres://admin:s3cr3t-prod-pw@db.prod.example.com:5432/main
STRIPE_SECRET_KEY=sk_live_51QjitE2Eabcdef0123456789ABCDEFghij
AWS_SECRET_ACCESS_KEY=$(rand_b64 40)
EOF
  cat > "$d/.env.local" <<EOF
DATABASE_URL=postgres://admin:local-pw@localhost:5432/dev
EOF
  # bare loose secrets (name-gate would miss these on a dir walk; explicit scan catches them)
  printf 'ghp_%s' "$(rand_alnum 36)" > "$d/token.txt"
  printf 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqaXQtZTJlIn0.%s' "$(rand_alnum 32)" > "$d/jwt.txt"
  printf 'AKIA%s' "$(rand_upnum 16)" > "$d/awskey.txt"
  # tfvars + npmrc for --only / category coverage. tfvars sits at the project
  # root on purpose: migrate names the group after the parent dir, so this keeps
  # it "$PROJ_NAME-tfvars" (namespaced) instead of leaking an "infra-tfvars".
  cat > "$d/terraform.tfvars" <<EOF
region        = "us-east-1"
db_password   = "tf-prod-$(rand_alnum 12)"
api_token     = "$(rand_alnum 32)"
EOF
  printf '//registry.npmjs.org/:_authToken=npm_%s\n' "$(rand_alnum 36)" > "$d/.npmrc"
  echo "$d"
}
rand_alnum(){ LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$1"; }
rand_upnum(){ LC_ALL=C tr -dc 'A-Z0-9'     < /dev/urandom | head -c "$1"; }
rand_b64(){   LC_ALL=C tr -dc 'A-Za-z0-9+/' < /dev/urandom | head -c "$1"; }

# ============================================================= PHASE 0: preflight
phase0(){
  section "Phase 0 · Preflight & version"
  local ver svc
  ver=$("$JIT" version 2>&1); expect_contains "jit binary runs" "$ver" "jit version"
  info "$ver"
  svc=$("$JIT" service status 2>&1)
  expect_contains "service is running" "$svc" "running"
  # service and CLI should be on the same build (a stale service is the #1 release-day trap)
  local cliv svcv
  cliv=$(printf '%s' "$svc" | grep -oE 'CLI [0-9.]+' | awk '{print $2}')
  svcv=$(printf '%s' "$svc" | grep -oE 'service [0-9.]+' | awk '{print $2}')
  expect_eq "service build == CLI build ($svcv vs $cliv)" "$svcv" "$cliv"
  local doc; doc=$("$JIT" doctor 2>&1); expect_contains "doctor resolves references" "$doc" "resolve cleanly"
  BASELINE=$(real_secret_count)
  info "vault baseline: $BASELINE non-test secret(s) recorded"
}

# ============================================================ PHASE 1: vault CRUD
AWS_VAL=""
phase1(){
  section "Phase 1 · Vault CRUD (set/get/list/history/restore)"
  AWS_VAL=$(rand_b64 40)
  gesture "2 × vault set"
  printf '%s' "$AWS_VAL" | "$JIT" vault set "$NS/aws-key" --stdin -y >/dev/null 2>&1
  printf 'db-pw-v1'      | "$JIT" vault set "$NS/db-pw"   --stdin -y >/dev/null 2>&1
  expect_contains "list shows both secrets" "$("$JIT" vault list 2>&1)" "$NS/aws-key"
  gesture "get round-trip"
  expect_eq "get aws-key round-trips" "$("$JIT" vault get "$NS/aws-key" 2>/dev/null)" "$AWS_VAL"
  # overwrite → history → restore, all on db-pw
  gesture "overwrite + restore db-pw"
  printf 'db-pw-v2' | "$JIT" vault set "$NS/db-pw" --stdin -y >/dev/null 2>&1
  expect_eq "overwrite took effect" "$("$JIT" vault get "$NS/db-pw" 2>/dev/null)" "db-pw-v2"
  expect_contains "history shows an archived version" "$("$JIT" vault history "$NS/db-pw" 2>&1)" "archived"
  "$JIT" vault restore "$NS/db-pw" >/dev/null 2>&1
  expect_eq "restore reverted to v1" "$("$JIT" vault get "$NS/db-pw" 2>/dev/null)" "db-pw-v1"
}

# =============================================================== PHASE 2: rekey
phase2(){
  section "Phase 2 · Vault rekey"
  gesture "vault rekey"
  local out; out=$("$JIT" vault rekey -y 2>&1)
  expect_contains "rekey re-wrapped envelopes" "$out" "re-wrapped"
  gesture "get after rekey"
  expect_eq "aws-key still decrypts under new key" "$("$JIT" vault get "$NS/aws-key" 2>/dev/null)" "$AWS_VAL"
}

# ================================================================ PHASE 3: scan
FIX=""
phase3(){
  section "Phase 3 · Scan (read-only) + flags"
  FIX=$(make_fixtures)
  local dir; dir=$("$JIT" scan "$FIX" 2>&1)
  expect_contains "dir scan flags CRITICAL (prod indicator)" "$dir" "CRITICAL"
  expect_contains "dir scan finds the .env" "$dir" ".env"
  # explicit-file content sweep catches bare secrets a name-gated dir walk misses
  local tok jwt awsk
  tok=$("$JIT" scan "$FIX/token.txt" 2>&1)
  expect_contains "explicit ghp_ token → HIGH" "$tok" "HIGH"
  jwt=$("$JIT" scan "$FIX/jwt.txt" 2>&1)
  expect_contains "explicit JWT → exposed secret" "$jwt" "Exposed Secrets        1"
  awsk=$("$JIT" scan "$FIX/awskey.txt" 2>&1)
  expect_contains "explicit AKIA key → HIGH" "$awsk" "HIGH"
  # placeholder filtering: the canonical EXAMPLE key must be judged clean
  local exf; exf="$FIX/example.txt"; printf 'AKIAIOSFODNN7EXAMPLE' > "$exf"
  expect_contains "EXAMPLE placeholder filtered to CLEAN" "$("$JIT" scan "$exf" 2>&1)" "CLEAN"
  # flags
  expect_contains "--score prints a score line" "$("$JIT" scan "$FIX" --score 2>&1)" "/100"
  "$JIT" scan "$FIX" --fail-on high --score >/dev/null 2>&1
  expect_exit "--fail-on high trips exit 2" "2" "$?"
  local clean; clean="$WORK/cleandir"; mkdir -p "$clean"; echo "nothing" > "$clean/readme.md"
  "$JIT" scan "$clean" --fail-on any --score >/dev/null 2>&1
  expect_exit "--fail-on any on clean dir exits 0" "0" "$?"
  local nd; nd=$("$JIT" scan "$FIX" --format ndjson 2>&1 | head -1)
  expect_contains "ndjson output is JSON" "$nd" '{'
}

# ================================================ PHASE 4: migrate / mounts / run
phase4(){
  section "Phase 4 · Migrate, mounts, profiles, run/export"
  [ -n "$FIX" ] || FIX=$(make_fixtures)
  local proj="$FIX"
  # dry-run changes nothing
  local dry; dry=$("$JIT" migrate "$proj/.env" --dry-run 2>&1)
  expect_contains "migrate --dry-run shows a plan" "$dry" "DRY RUN"
  expect_file ".env untouched by dry-run" "$proj/.env"
  expect_contains "dry-run really changed nothing" "$(head -1 "$proj/.env")" "APP_ENV=production"
  # real migrate → FIFO mount + pointers + vault group + profile
  "$JIT" migrate "$proj/.env" -y >/dev/null 2>&1
  expect_fifo ".env became a live FIFO mount" "$proj/.env"
  expect_file ".pointers companion written" "$proj/.env.pointers"
  expect_contains ".pointers holds vault paths only" "$(cat "$proj/.env.pointers")" "jit://vault/"
  expect_file "profile manifest created (project-local)" "$proj/.jit/profiles/${PROJ_NAME}.yaml"
  expect_contains "vault holds migrated group" "$("$JIT" vault list 2>&1)" "$PROJ_NAME/"
  # jit run injects the REAL values; ambient stays empty
  expect_eq "ambient shell has no secret" "${STRIPE_SECRET_KEY:-empty}" "empty"
  local runout; runout=$(cd "$proj" && "$JIT" run -- sh -c 'echo S=$STRIPE_SECRET_KEY' 2>/dev/null)
  expect_contains "jit run injected the live value" "$runout" "S=sk_live_51QjitE2E"
  local exp; exp=$(cd "$proj" && "$JIT" export 2>/dev/null)
  expect_contains "jit export prints shell statements" "$exp" "export STRIPE_SECRET_KEY="
  # unmount reverses back to plaintext
  "$JIT" unmount "$proj/.env" -y >/dev/null 2>&1
  expect_file ".env reverted to a regular file" "$proj/.env"
  expect_contains ".env has real values again" "$(cat "$proj/.env")" "sk_live_51QjitE2E"
  # --only scoping: only tfvars touched
  "$JIT" migrate "$proj" --only tfvars -y >/dev/null 2>&1
  expect_contains "--only tfvars migrated the tfvars" "$("$JIT" vault list 2>&1)" "$PROJ_NAME"
  expect_file ".env NOT swept by --only tfvars (still a file)" "$proj/.env"
}

# ================================================================ PHASE 5: wrap
phase5(){
  section "Phase 5 · Wrap (shim injection)"
  local realbin="$WORK/realbin"; mkdir -p "$realbin"
  cat > "$realbin/$WRAP_TOOL" <<EOF
#!/bin/sh
echo "TOKEN=\${JIT_E2E_TOKEN:-empty}"
EOF
  chmod +x "$realbin/$WRAP_TOOL"
  local secret; secret="wrap-value-$(rand_alnum 8)"
  gesture "vault set wrap secret"
  printf '%s' "$secret" | "$JIT" vault set "wrap-$WRAP_TOOL/JIT_E2E_TOKEN" --stdin -y >/dev/null 2>&1
  "$JIT" wrap add "$WRAP_TOOL" --env "JIT_E2E_TOKEN=wrap-$WRAP_TOOL/JIT_E2E_TOKEN" >/dev/null 2>&1
  expect_file "shim installed on PATH" "$HOME/.jit/shims/$WRAP_TOOL"
  expect_contains "wrap list shows the tool" "$("$JIT" wrap list 2>&1)" "$WRAP_TOOL"
  local got; got=$(PATH="$HOME/.jit/shims:$realbin:$PATH" "$WRAP_TOOL" 2>/dev/null | tail -1)
  expect_eq "shim injected the token JIT" "$got" "TOKEN=$secret"
  "$JIT" wrap undo "$WRAP_TOOL" >/dev/null 2>&1
  expect_missing "wrap undo removed the shim" "$("$JIT" wrap list 2>&1)" "$WRAP_TOOL"
}

# ==================================================== PHASE 6: aws / terraform
phase6(){
  section "Phase 6 · AWS credential_process + terraform"
  command -v aws >/dev/null 2>&1 || { info "aws CLI not installed — skipping phase 6"; return; }
  save_real "$HOME/.aws"; rm -rf "$HOME/.aws"
  local realbin="$WORK/realbin"; mkdir -p "$realbin"
  # fake clisso: emits a credential_process JSON line the capturer grabs
  cat > "$realbin/clisso" <<'EOF'
#!/bin/sh
[ "$1" = "get" ] || { echo "fake clisso: $*" >&2; exit 0; }
echo "Fetching credentials for '$2'..."
echo '{"Version":1,"AccessKeyId":"ASIAE2ETESTKEYID0000","SecretAccessKey":"e2eFAKEsecretaccesskeyABCDEF0123456789xy","SessionToken":"E2ETOKEN==","Expiration":"2030-01-01T00:00:00Z"}'
EOF
  chmod +x "$realbin/clisso"
  local cap; cap=$("$JIT" clisso-capture --real "$realbin/clisso" -- get "$CLISSO_APP" 2>&1)
  expect_contains "capture reports storing creds" "$cap" "captured temporary AWS credentials"
  expect_missing "credential JSON NOT echoed to stdout" "$cap" "SecretAccessKey"
  expect_contains "vault holds aws-<app> group" "$("$JIT" vault list 2>&1)" "aws-$CLISSO_APP/"
  expect_file "~/.aws/config wired" "$HOME/.aws/config"
  local cl; cl=$(AWS_PROFILE="$CLISSO_APP" aws configure list 2>&1)
  expect_contains "aws CLI reports custom-process source" "$cl" "custom-process"
  # dummy terraform → real aws sts: creds must reach AWS (auth error proves delivery)
  if [ "${E2E_NET:-1}" = "1" ]; then
    local sts; sts=$(AWS_PROFILE="$CLISSO_APP" aws sts get-caller-identity 2>&1)
    expect_contains "creds reached AWS end-to-end (InvalidClientTokenId)" "$sts" "InvalidClientTokenId"
  else
    info "E2E_NET=0 — skipping the live aws sts call"
  fi
}

# ==================================================== PHASE 7: docker / git creds
phase7(){
  section "Phase 7 · Docker & git credential helpers"
  # --- docker ---
  save_real "$HOME/.docker"; mkdir -p "$HOME/.docker"
  cat > "$HOME/.docker/config.json" <<EOF
{"auths":{"registry.jit-e2e.example.com":{"auth":"$(printf 'e2euser:e2e-registry-pw' | base64)"}}}
EOF
  local dm; dm=$("$JIT" migrate "$HOME/.docker/config.json" -y 2>&1)
  expect_contains "docker migrate routed the registry" "$dm" "registry.jit-e2e.example.com"
  expect_file "docker-credential-jit shim exists" "$HOME/.jit/shims/docker-credential-jit"
  local dcfg; dcfg=$(cat "$HOME/.docker/config.json")
  expect_contains "config.json now uses a credHelper" "$dcfg" "credHelpers"
  local dg; dg=$(echo "registry.jit-e2e.example.com" | "$HOME/.jit/shims/docker-credential-jit" get 2>/dev/null)
  expect_contains "helper returns the username" "$dg" "e2euser"
  # --- git ---
  save_real "$HOME/.gitconfig"
  save_real "$HOME/.git-credentials"
  # seed a plaintext store credential (https://user:token@host), then migrate it
  printf 'https://e2euser:git-e2e-token@git.jit-e2e.example.com\n' > "$HOME/.git-credentials" 2>/dev/null || true
  "$JIT" migrate "$HOME/.git-credentials" -y >/dev/null 2>&1
  expect_file "git-credential-jit shim exists" "$HOME/.jit/shims/git-credential-jit"
  # behavioral proof: git's own config now routes credential lookups to jit
  local gh; gh=$(git config --global --get-all credential.helper 2>/dev/null)
  expect_contains "git credential.helper now routes to jit" "$gh" "jit"
}

# ============================================================ PHASE 8: audit/status
phase8(){
  section "Phase 8 · Audit, status, doctor"
  local a; a=$("$JIT" audit 2>&1)
  expect_contains "audit lists recent commands" "$a" "jit"
  # audit records the run's activity; grep on a single-word command that is
  # reliably logged as a cmd event (migrate). NOTE for the QA agents: vault
  # set/get/rm show up as their Touch-ID presence events, not greppable "vault
  # set" cmd lines — worth confirming that's intended, and that multi-word
  # --grep patterns behave.
  expect_contains "audit --kind cmd records commands" "$("$JIT" audit --kind cmd 2>&1)" "jit "
  expect_contains "audit --grep filters (single word)" "$("$JIT" audit --grep migrate 2>&1)" "migrate"
  local af; af=$("$JIT" audit --kind error 2>&1)
  expect_contains "audit --kind filter runs" "$af" "audit"
  local st; st=$("$JIT" status 2>&1)
  expect_contains "status prints version" "$st" "$("$JIT" version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
  expect_contains "status reconciles secrets" "$st" "reconciled"
  local dj; dj=$("$JIT" doctor --format json 2>&1)
  expect_contains "doctor --format json emits JSON" "$dj" '{'
  local do; do=$("$JIT" doctor --orphans 2>&1)
  expect_contains "doctor --orphans runs" "$do" "profile"
}

# ================================================= PHASE 9: destructive (opt-in)
phase9(){
  section "Phase 9 · Export/import round-trip + delete→init→import (opt-in)"
  # A known secret must be present for the round-trip assertion. If phase 1
  # didn't run, seed one here so --phase 9 works standalone.
  if [ -z "$AWS_VAL" ]; then
    AWS_VAL=$(rand_b64 40)
    gesture "seed a secret for the round-trip"
    printf '%s' "$AWS_VAL" | "$JIT" vault set "$NS/aws-key" --stdin -y >/dev/null 2>&1
  fi
  local backup="$WORK/vault-e2e.jitx"
  gesture "vault export"
  printf '%s' "$EXPORT_PASS" | "$JIT" vault export "$backup" --stdin >/dev/null 2>&1
  expect_file "export wrote a passphrase-encrypted backup" "$backup"
  # Crypto round-trip WITHOUT deleting: import overwrites in place. Always safe.
  gesture "vault import (overwrite in place)"
  printf '%s' "$EXPORT_PASS" | "$JIT" vault import "$backup" --stdin -y >/dev/null 2>&1
  gesture "get after import"
  expect_eq "secret survives export→import round-trip" "$("$JIT" vault get "$NS/aws-key" 2>/dev/null)" "$AWS_VAL"

  # Full delete→init→import only when NO live mount exists — a mount blocks
  # delete by design, and auto-unmounting the operator's real mounts is out of
  # scope for an automated gate. The manual delete drill covers the mounted case.
  local mounts; mounts=$("$JIT" status 2>&1 | grep -oE '[0-9]+ registered mount' | grep -oE '^[0-9]+' || echo 0)
  if [ "${mounts:-0}" -gt 0 ]; then
    info "skipping live vault delete: $mounts mount(s) registered (would require unmounting your real mounts)."
    info "→ run the manual delete drill in docs/testing/pre-release-live-test.md on a mount-free machine."
    pass "delete correctly gated by a live mount (guard verified)"
    return
  fi
  gesture "vault delete"
  local del; del=$("$JIT" vault delete -y 2>&1)
  expect_contains "vault delete destroyed the vault" "$del" "vault is gone"
  "$JIT" vault init >/dev/null 2>&1
  expect_contains "vault init recreated it" "$("$JIT" vault list 2>&1)" "No secrets stored yet"
  gesture "vault import after delete"
  printf '%s' "$EXPORT_PASS" | "$JIT" vault import "$backup" --stdin -y >/dev/null 2>&1
  gesture "get after restore"
  expect_eq "restored secret decrypts under fresh master key" "$("$JIT" vault get "$NS/aws-key" 2>/dev/null)" "$AWS_VAL"
}

# =================================================================== teardown
cleanup(){
  [ "$CLEANED" = 1 ] && return; CLEANED=1
  section "Teardown"
  # unmount any project mount still live
  [ -n "${FIX:-}" ] && [ -p "$FIX/.env" ] && "$JIT" unmount "$FIX/.env" -y >/dev/null 2>&1
  # drop every test profile. All test names (jit-e2e-proj, aws-jit-e2e-aws,
  # wrap-jit-e2e-tool, docker-registry.jit-e2e.*, git-git.jit-e2e.*) contain the
  # namespace, so one glob catches them — including the docker/git ones an
  # earlier per-name list missed and left for `doctor` to flag.
  rm -f "$HOME/.jit/profiles/"*"${NS}"* 2>/dev/null
  "$JIT" wrap undo "$WRAP_TOOL" >/dev/null 2>&1
  # remove every namespaced secret in ONE gesture (targeted — never
  # `orphans --prune`, which is machine-wide). Word-splitting is intentional.
  local paths; paths=$(list_test_secrets | tr '\n' ' ')
  if [ -n "${paths// }" ]; then
    gesture "1 × vault rm (whole test batch, one gesture)"
    # shellcheck disable=SC2086
    "$JIT" vault rm -y $paths >/dev/null 2>&1
  fi
  session_restore
  restore_real
  [ -n "$WORK" ] && [ "$KEEP" = 0 ] && rm -rf "$WORK"
  # baseline assertion — proof we left the real vault as we found it
  local after; after=$(real_secret_count)
  expect_eq "vault returned to baseline ($after == $BASELINE non-test secrets)" "$after" "$BASELINE"
}

# ===================================================================== main
main(){
  while [ $# -gt 0 ]; do
    case "$1" in
      --phase) PHASES="$2"; shift 2;;
      --destructive) DESTRUCTIVE=1; shift;;
      --os-creds) OS_CREDS=1; shift;;
      --keep) KEEP=1; shift;;
      -h|--help) sed -n '2,40p' "$0"; exit 0;;
      *) die "unknown option: $1";;
    esac
  done
  command -v "$JIT" >/dev/null 2>&1 || die "jit binary not found: $JIT"
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/jit-e2e.XXXXXX") || die "cannot make work dir"
  trap 'cleanup' EXIT INT TERM

  printf "${BLD}jit pre-release live test${RST}  (binary: %s)\n" "$(command -v "$JIT")"
  [ "$OS_CREDS" = 1 ] && PHASES="$PHASES,7"
  [ "$DESTRUCTIVE" = 1 ] && PHASES="$PHASES,9"
  local extra=""
  [ "$OS_CREDS" = 1 ] && extra="$extra +os-creds"
  [ "$DESTRUCTIVE" = 1 ] && extra="$extra +destructive"
  info "phases: $PHASES$extra"

  # Normalize the phase list first: map named aliases (so an agent can ask for
  # `--phase scan` or `--phase cmdtree`) to tokens, per-token in bash — BSD sed
  # lacks \b word boundaries. phase 0 is always first (it sets BASELINE).
  local norm="0" p
  for p in ${PHASES//,/ }; do
    case "$p" in
      cmdtree) p=c;; vault) p=1;; rekey) p=2;; scan) p=3;;
      migrate|mounts) p=4;; wrap) p=5;; aws|clisso|terraform) p=6;;
      docker|git) p=7;; audit|status|doctor) p=8;; destructive) p=9;;
    esac
    [ "$p" = "0" ] && continue
    norm="$norm,$p"
  done
  PHASES="$norm"

  # Only unlock when a vault-mutating phase is actually selected. A prompt-free
  # run (cmdtree / scan / audit-status-doctor) then costs ZERO Touch ID.
  case ",$PHASES," in
    *,1,*|*,2,*|*,4,*|*,5,*|*,6,*|*,7,*|*,9,*) session_setup;;
    *) info "no vault-mutating phase selected — skipping unlock (prompt-free run)";;
  esac

  for p in ${PHASES//,/ }; do
    case "$p" in
      0) phase0;; c) phasecmd;; 1) phase1;; 2) phase2;; 3) phase3;; 4) phase4;;
      5) phase5;; 6) phase6;; 7) phase7;; 8) phase8;; 9) phase9;;
      10) : ;;  # teardown runs via trap
      *) info "unknown phase '$p' — skipping";;
    esac
  done

  cleanup
  trap - EXIT INT TERM

  section "Summary"
  printf "  ${GRN}%d passed${RST}, ${RED}%d failed${RST}\n" "$PASS" "$FAIL"
  if [ "$FAIL" -gt 0 ]; then
    printf "\n  ${RED}failed checks:${RST}\n"
    local f; for f in "${FAILED[@]}"; do printf "    ${RED}✗${RST} %s\n" "$f"; done
    printf "\n${RED}${BLD}NOT READY TO RELEASE${RST}\n"; exit 1
  fi
  printf "\n${GRN}${BLD}all live checks passed — clear to cut the release${RST}\n"; exit 0
}
main "$@"
