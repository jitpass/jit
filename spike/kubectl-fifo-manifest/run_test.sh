#!/bin/zsh
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
#
# Drives a REAL `kubectl apply` (no --dry-run) against the spike's mock
# apiserver (see main.go -mode apiserver: core-v1 discovery + a secrets
# endpoint that typed-decodes data via json []byte, the same mechanism as the
# real apiserver's "illegal base64" rejection), against regular files and
# against a FIFO served by the spike's mount.Serve-alike (-mode fifo).
#
# Answers, in order:
#   B1  valid manifest applies cleanly end to end
#   B2  jit decoy manifest (data: jit-hidden-*) fails LOUDLY - and the mock's
#       request log shows whether kubectl rejected client-side (no POST seen)
#       or shipped it to the server (POST seen, 400 returned)
#   B3  stringData decoy is silently ACCEPTED and becomes the stored value
#       (the hazard motivating the stringData->data conversion)
#   B4  default client validation (--validate=strict) behavior when openapi
#       is unavailable, for completeness
#   D   kubectl reads a FIFO at -f; exact open/serve count per invocation
set -u
cd "$(dirname "$0")"

WORK=$(mktemp -d /tmp/kubectl-fifo-spike.XXXXXX)
API_LOG="$WORK/apiserver.log"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

echo "kubectl: $(kubectl version --client 2>/dev/null | head -1)"
echo "workdir: $WORK"
echo

go build -o "$WORK/spike" . || exit 1

# --- mock apiserver + kubeconfig -------------------------------------------
"$WORK/spike" -mode apiserver -listen 127.0.0.1:18080 2>> "$API_LOG" &
PIDS+=($!)
until curl -sf http://127.0.0.1:18080/api > /dev/null; do sleep 0.05; done

export KUBECONFIG="$WORK/kubeconfig"
cat > "$KUBECONFIG" <<'EOF'
apiVersion: v1
kind: Config
clusters:
  - name: spike
    cluster: { server: "http://127.0.0.1:18080" }
contexts:
  - name: spike
    context: { cluster: spike, namespace: default }
current-context: spike
EOF

# --- fixtures ---------------------------------------------------------------
cat > "$WORK/valid.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  username: YWRtaW4=
  password: aHVudGVyMg==
EOF

# Exactly what jit would serve outside a grant: DecoyNotice comment header +
# mount.DecoyValues placeholders ("jit-hidden-" + var name, never valid base64).
cat > "$WORK/decoy.yaml" <<'EOF'
# This file is managed by jit. Values below are decoys; run through jit to reveal.
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
data:
  username: jit-hidden-SECRET_DB_CREDS_USERNAME
  password: jit-hidden-SECRET_DB_CREDS_PASSWORD
EOF

cat > "$WORK/stringdata-decoy.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
type: Opaque
stringData:
  password: jit-hidden-SECRET_DB_CREDS_PASSWORD
EOF

run() {
  echo "\$ $*"
  "$@" 2>&1 | sed 's/^/    /' | head -8
  echo "    exit=${pipestatus[1]}"
  echo
}
api_log_tail() { echo "    apiserver saw:"; tail -n "$1" "$API_LOG" | sed 's/^/      /'; echo; }

echo "=== B1. valid manifest, regular file, REAL apply ==="
run kubectl apply --validate=false -f "$WORK/valid.yaml"
api_log_tail 4

echo "=== B2. decoy manifest (invalid base64), REAL apply ==="
run kubectl apply --validate=false -f "$WORK/decoy.yaml"
api_log_tail 4

echo "=== B3. stringData decoy, REAL apply (expect: silently accepted) ==="
run kubectl apply --validate=false -f "$WORK/stringdata-decoy.yaml"
api_log_tail 4

echo "=== B4. decoy with DEFAULT validation (openapi unavailable here) ==="
run kubectl apply -f "$WORK/decoy.yaml"

echo "=== D. FIFO tests (server replicates mount.Serve incl. recreate-after-close) ==="
fifo_case() {
  local label=$1 manifest=$2; shift 2
  local fifo="$WORK/secret.yaml" log="$WORK/fifo-$label.log"
  rm -f "$fifo"
  "$WORK/spike" -mode fifo -path "$fifo" -file "$manifest" -idle-exit 6s 2> "$log" &
  local spid=$!
  until [ -p "$fifo" ]; do sleep 0.05; done   # never launch the reader before the FIFO exists
  echo "\$ kubectl $* -f <fifo serving $(basename "$manifest")>"
  kubectl "$@" -f "$fifo" 2>&1 | sed 's/^/    /' | head -8
  echo "    exit=${pipestatus[1]}"
  kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
  echo "    server cycles:"; grep '^SERVER cycle=' "$log" | sed 's/^/      /'
  echo
}
fifo_case valid "$WORK/valid.yaml" apply --validate=false
api_log_tail 4
fifo_case decoy "$WORK/decoy.yaml" apply --validate=false
api_log_tail 4

echo "done."
