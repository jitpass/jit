#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"

FIFO=/tmp/jit-spike-env
rm -f "$FIFO"
rm -f server.log

./named-pipe-spike -path "$FIFO" -count 4 > server.log 2>&1 &
SERVER_PID=$!

echo "=== waiting for FIFO to actually exist (this is the real-world requirement:"
echo "    don't launch the target app until the mount point is confirmed present) ==="
for i in $(seq 1 50); do
  [ -p "$FIFO" ] && break
  sleep 0.05
done
if [ ! -p "$FIFO" ]; then
  echo "FIFO never appeared — failing"
  kill "$SERVER_PID" 2>/dev/null
  exit 1
fi
echo "FIFO ready after polling."

echo "=== Reader 1 (immediate cat, right after FIFO confirmed) ==="
cat "$FIFO"

echo "=== Reader 2 (cat after a pause, simulating a later hot-reload) ==="
sleep 0.5
cat "$FIFO"

echo "=== Reader 3 (rapid back-to-back open, no pause) ==="
cat "$FIFO"

echo "=== Reader 4 (final cycle) ==="
sleep 0.2
cat "$FIFO"

wait "$SERVER_PID"
echo "=== server exit code: $? ==="
echo "=== server log ==="
cat server.log
