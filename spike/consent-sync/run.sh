#!/bin/bash
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# Runs the consent-sync spike's scenarios. Every one raises a REAL Touch ID
# dialog on this Mac; none opens the vault, the keychain or the running jit
# service, and the Secure Enclave key is ephemeral.
#
#   ./run.sh build      build both halves into $OUT
#   ./run.sh auto       the unattended ones: cancel on both paths, no panel,
#                       a stuck panel (each dialog closes by itself)
#   ./run.sh approve    approve with Touch ID, three times (measures the gap)
#   ./run.sh cancel     press Cancel on the dialog yourself
#   ./run.sh deny       press Deny on the panel yourself
#   ./run.sh again      the keychain cancel, Cancel on the dialog, Deny on
#                       the panel (spoken cues, since `!` output is buffered)
#   ./run.sh all        build, auto, approve, cancel, deny
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${TMPDIR:-/tmp}/consent-sync-spike}"
mkdir -p "$OUT"
# A unix socket path is capped at 104 bytes on macOS, which a deep $OUT
# passes, so the socket gets a short directory of its own.
SOCKDIR="$(mktemp -d)"
SOCK="$SOCKDIR/s.sock"
trap 'rm -rf "$SOCKDIR"' EXIT
if [ ${#SOCK} -ge 104 ]; then
    echo "socket path too long (${#SOCK} bytes): $SOCK" >&2
    exit 1
fi

build() {
    (cd "$HERE" && go build -o "$OUT/service" .)
    swiftc -O -framework AppKit -o "$OUT/panel" "$HERE/panel/main.swift"
    echo "built $OUT/service and $OUT/panel"
}

# trial NAME SERVICE-FLAGS -- PANEL-FLAGS
trial() {
    local name="$1"; shift
    local sflags=() pflags=() seen=0
    for a in "$@"; do
        if [ "$a" = "--" ]; then seen=1; continue; fi
        if [ $seen = 0 ]; then sflags+=("$a"); else pflags+=("$a"); fi
    done
    echo
    echo "=== $name"
    "$OUT/service" -sock "$SOCK" "${sflags[@]}" &
    local spid=$!
    sleep 0.3
    "$OUT/panel" -sock "$SOCK" ${pflags[@]+"${pflags[@]}"} &
    local ppid=$!
    wait $spid || true
    wait $ppid 2>/dev/null || true
    sleep 0.5
}

auto() {
    trial "A1 enclave: the panel denies 1.5 s in (the dialog must go away)" -mode enclave -- -auto-deny 1500
    trial "A2 keychain: the panel denies 1.5 s in" -mode keychain -- -auto-deny 1500
    trial "A3 enclave, stuck panel (never says shown): the prompt starts after the 250 ms wait; denies 1.5 s in" -mode enclave -- -no-ack -auto-deny 1500
    echo
    echo "=== A4 enclave, no panel at all: the prompt starts at once. Press Cancel on the dialog."
    "$OUT/service" -no-panel -mode enclave
}

approve() {
    for i in 1 2 3; do
        echo; echo ">>> Approve with Touch ID ($i of 3)"
        trial "B$i enclave: approve" -mode enclave --
    done
}

cancel() {
    echo; echo ">>> Press Cancel on the Touch ID dialog"
    trial "C1 enclave: Cancel on the dialog" -mode enclave --
}

deny() {
    echo; echo ">>> Press Deny on the panel (top right), not on the dialog"
    trial "D1 enclave: Deny on the panel" -mode enclave --
}

again() {
    echo "Step 1: nothing to do, the dialog closes by itself."
    trial "A2 keychain: the panel denies 1.5 s in" -mode keychain -- -auto-deny 1500
    sleep 2
    echo "Step 2: press Cancel on the Touch ID dialog."
    say -v Samantha "Step 2. Press Cancel on the Touch I D dialog." 2>/dev/null || true
    cancel
    sleep 2
    echo "Step 3: click Deny on the panel at the top right. Do not touch the sensor."
    say -v Samantha "Step 3. Click Deny on the panel, top right. Do not touch the sensor." 2>/dev/null || true
    deny
}

case "${1:-all}" in
    again) build; again ;;
    build) build ;;
    auto) auto ;;
    approve) approve ;;
    cancel) cancel ;;
    deny) deny ;;
    all) build; auto; approve; cancel; deny ;;
    *) sed -n '2,17p' "$0"; exit 2 ;;
esac
