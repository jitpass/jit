#!/bin/zsh
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# End-to-end notarization probe: build a trivial Mach-O, sign it exactly the
# way releases are signed (quill, Developer ID .p12 with full chain), submit
# it to Apple's notary service with a bounded wait, and — on Accepted — prove
# the part Homebrew distribution actually depends on: a *quarantined*,
# *unstapled* bare binary passes Gatekeeper via the online ticket fetch.
#
# Environment contract (works locally and in CI):
#   QUILL_SIGN_P12        Developer ID Application .p12 — path OR base64 content.
#                         Must carry the full chain (leaf + G2 intermediate +
#                         Apple Root CA) or Apple rejects the signature.
#   QUILL_SIGN_PASSWORD   its password
#   NOTARY_ISSUER_ID      App Store Connect API key issuer (Team key —
#                         Individual keys cannot call the notary API at all)
#   NOTARY_KEY_ID         the key id
#   NOTARY_KEY            the .p8 — path, raw PEM content, or base64 content
#   NOTARY_TIMEOUT        bounded wait for a verdict (default 15m)
#   MODE                  "submit" (default) — full end-to-end run
#                         "history" — no new submission; just report the
#                         account's recent submissions and their statuses
#
# Exit codes (the workflow and FINDINGS.md key off these):
#   0  Accepted; the Gatekeeper leg passed, or was inconclusive because the
#      environment doesn't enforce Gatekeeper on exec (measured 2026-08-07:
#      GitHub's macOS runners run the unnotarized control too, so only a
#      real Mac can judge that leg — it passed locally 2026-08-06)
#   1  Invalid — Apple returned a verdict against the artifact (log dumped)
#   2  stuck In Progress past NOTARY_TIMEOUT — the known account condition
#   3  Accepted, but a discriminating environment (one that DID block the
#      control) blocked the quarantined notarized binary too — would break
#      brew-cask users even with notarization "working"

set -u
cd "$(dirname "$0")"

MODE="${MODE:-submit}"
NOTARY_TIMEOUT="${NOTARY_TIMEOUT:-15m}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

say() { print -r -- "==> $*" }

# --- notary key: accept a path, raw PEM, or base64 ------------------------
keyfile="$WORK/notary.p8"
if [[ -f "${NOTARY_KEY}" ]]; then
  cp "${NOTARY_KEY}" "$keyfile"
elif [[ "${NOTARY_KEY}" == *"-----BEGIN"* ]]; then
  print -r -- "${NOTARY_KEY}" > "$keyfile"
else
  print -r -- "${NOTARY_KEY}" | base64 -d > "$keyfile" || {
    say "NOTARY_KEY is neither a path, PEM, nor valid base64"; exit 64; }
fi
notary=(xcrun notarytool)
auth=(--key "$keyfile" --key-id "${NOTARY_KEY_ID}" --issuer "${NOTARY_ISSUER_ID}")

if [[ "$MODE" == "history" ]]; then
  say "submission history (no new submission)"
  "${notary[@]}" history "${auth[@]}"
  exit $?
fi

# --- build + sign ---------------------------------------------------------
say "building hello Mach-O"
go build -o "$WORK/hello" . || exit 65
# Keep an unnotarized control (only the linker's ad-hoc signature): the
# Gatekeeper leg below is only meaningful if this copy gets blocked.
cp "$WORK/hello" "$WORK/control"

say "signing with quill (same path goreleaser's notarize.macos uses)"
quill sign "$WORK/hello" || { say "quill sign failed"; exit 65; }
codesign -dv "$WORK/hello" 2>&1 | grep -E "Authority|TeamIdentifier|flags" || true

# --- submit with a bounded wait ------------------------------------------
# notarytool needs a zip for a bare binary; ditto preserves what matters.
ditto -c -k "$WORK/hello" "$WORK/hello.zip"

say "submitting (timeout ${NOTARY_TIMEOUT})"
submit_out="$WORK/submit.json"
t_submit=$(date +%s)
"${notary[@]}" submit "$WORK/hello.zip" "${auth[@]}" \
  --wait --timeout "${NOTARY_TIMEOUT}" --output-format json \
  | tee "$submit_out"
t_verdict=$(date +%s)
print ""

sub_id=$(grep -o '"id" *: *"[^"]*"' "$submit_out" | head -1 | sed 's/.*"\([^"]*\)"$/\1/')
verdict=$(grep -o '"status" *: *"[^"]*"' "$submit_out" | tail -1 | sed 's/.*"\([^"]*\)"$/\1/')
# upload + Apple's queue + scan, together: the number FINDINGS.md's gate
# criterion 2 is about (must sit well inside quill's ~18m JWT ceiling).
say "submission ${sub_id:-<no id>} → status: ${verdict:-<none>} after $((t_verdict - t_submit))s"

case "${verdict:-}" in
  Accepted) ;;
  Invalid|Rejected)
    say "verdict against the artifact — notary log follows"
    "${notary[@]}" log "$sub_id" "${auth[@]}" || true
    exit 1 ;;
  *)
    say "no verdict within ${NOTARY_TIMEOUT} — the known stuck-In-Progress condition"
    say "recent history for context:"
    "${notary[@]}" history "${auth[@]}" | head -40 || true
    exit 2 ;;
esac

say "Accepted — fetching notary log"
"${notary[@]}" log "$sub_id" "${auth[@]}" || true

# --- the brew-decisive check ---------------------------------------------
# jit ships a bare Mach-O, which cannot be stapled, so a Homebrew-cask user
# (whose download brew quarantines) depends on Gatekeeper fetching the ticket
# online. Simulate exactly that user, A/B: quarantine both the notarized
# binary and the unnotarized control, and execute each. The control MUST be
# blocked (SIGKILL) or the environment isn't discriminating and the leg
# proves nothing. spctl output is printed as evidence only: its `execute`
# policy approves only .apps, so a bare CLI gets "rejected (the code is valid
# but does not seem to be an app)" even when notarized — measured 2026-08-06.
say "Gatekeeper check on a quarantined, unstapled copy"
spctl --status || true
qtag="0083;$(printf '%x' "$(date +%s)");notarize-e2e-spike;"
cp "$WORK/hello" "$WORK/hello-quarantined"
xattr -w com.apple.quarantine "$qtag" "$WORK/hello-quarantined"
xattr -w com.apple.quarantine "$qtag" "$WORK/control"

spctl --assess --type execute -vv "$WORK/hello-quarantined" 2>&1 || true

ctl_out=$("$WORK/control" 2>&1); ctl_rc=$?
run_out=$("$WORK/hello-quarantined" 2>&1); run_rc=$?
print -r -- "control (ad-hoc, quarantined):   rc=$ctl_rc"
print -r -- "notarized, quarantined:          rc=$run_rc  $run_out"

if (( ctl_rc == 0 )); then
  say "WARN — the unnotarized control ran too: this environment does not"
  say "enforce Gatekeeper on exec (GitHub macOS runners behave this way), so"
  say "the Gatekeeper leg proves nothing here. The notary verdict above"
  say "stands as this run's result; judge the Gatekeeper leg on a real Mac."
  exit 0
fi
if (( run_rc == 0 )) && [[ "$run_out" == *"hello"* ]]; then
  say "PASS — Gatekeeper blocks the control but runs the notarized copy: the online ticket fetch works."
  say "Safe to re-add notarize + the cask once this is consistent (see FINDINGS.md gate)."
  exit 0
fi
say "Accepted by notary, but Gatekeeper blocked the quarantined notarized copy (rc=$run_rc)"
exit 3
