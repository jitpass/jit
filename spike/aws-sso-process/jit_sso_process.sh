#!/bin/sh
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# A stand-in for the `jit aws-sso <profile>` credential_process command the
# spike evaluates. $VAULT plays the vault: $VAULT/sso-cache holds the sealed
# token files, $VAULT/config.sealed the user's original SSO profile
# definitions. $REAL_HOME is the user's home, whose ~/.aws/config has been
# rewritten to point each SSO profile here.
#
#   1. capture: a login `aws sso login` just wrote into the real cache is
#      newer than the vault's; move it in (and out of the real cache).
#   2. unseal the cache into a private temp HOME.
#   3. run AWS's own export-credentials there, against the sealed config:
#      the CLI does the refresh, rotation and GetRoleCredentials itself.
#   4. reseal the token files if the run changed them; discard the rest
#      (role credentials the CLI cached, telemetry).
#
# With LOCK=1 steps 2-4 run under an exclusive lock on the vault, so two
# concurrent refreshes cannot both present the same rotated-out token.
set -eu
profile="$1"
real_cache="$REAL_HOME/.aws/sso/cache"
mkdir -p "$VAULT/sso-cache"

run() {
  if [ -d "$real_cache" ] && [ -n "$(ls -A "$real_cache" 2>/dev/null)" ]; then
    mv "$real_cache"/*.json "$VAULT/sso-cache/" 2>/dev/null || true
  fi
  tmp=$(mktemp -d "$VAULT/../run.XXXXXX")
  mkdir -p "$tmp/.aws/sso/cache"
  cp -p "$VAULT"/sso-cache/*.json "$tmp/.aws/sso/cache/" 2>/dev/null || true
  before=$(cd "$tmp/.aws/sso/cache" && cat ./*.json 2>/dev/null | shasum)
  status=0
  # _AWS_CLI_PROFILE_CHAIN is export-credentials' loop guard: an outer
  # `aws configure export-credentials --profile dev` sets it to "dev", and
  # the inner run, resolving the same name against the sealed config where
  # dev IS the SSO profile, would refuse it as a cycle. It is not one.
  env -u _AWS_CLI_PROFILE_CHAIN HOME="$tmp" AWS_CONFIG_FILE="$VAULT/config.sealed" AWS_SHARED_CREDENTIALS_FILE=/dev/null \
    aws configure export-credentials --profile "$profile" --format process || status=$?
  after=$(cd "$tmp/.aws/sso/cache" && cat ./*.json 2>/dev/null | shasum)
  if [ "$before" != "$after" ]; then
    cp -p "$tmp"/.aws/sso/cache/*.json "$VAULT/sso-cache/"
    echo resealed >>"$VAULT/../reseals.log"
  fi
  find "$tmp" -type f | sed "s|$tmp/||" >>"$VAULT/../tmpfiles.log"
  rm -rf "$tmp"
  return $status
}

if [ "${LOCK:-0}" = 1 ]; then
  # macOS has no flock(1); perl's flock is the same syscall. system, not
  # exec: perl marks the lock's descriptor close-on-exec, so an exec'd
  # child would run with the lock already released.
  exec perl -MFcntl=:flock -e 'open(my $l, ">", shift) or die; flock($l, LOCK_EX) or die; system(@ARGV); exit($? >> 8)' \
    "$VAULT/.lock" env LOCK=0 "$0" "$@"
fi
run
