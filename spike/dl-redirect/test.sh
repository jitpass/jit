#!/bin/zsh
# Drive the redirect Worker locally (wrangler dev, no Cloudflare account
# needed) and prove the four things the production change depends on:
#   1. every client class gets a 302 to the exact GitHub URL
#   2. the path allowlist rejects open-redirect probes with 404
#   3. bytes fetched THROUGH the redirect hash-match the release's own
#      published checksums.txt (the cask sha256 therefore stays valid)
#   4. a HEAD request (brew probes with one) also redirects
set -uo pipefail
cd "$(dirname "$0")"

PORT=8787
BASE="http://127.0.0.1:$PORT"
PASS=0; FAIL=0
ok()  { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }

echo "[dl-redirect spike] starting wrangler dev ..."
npx --yes wrangler@4 dev --port $PORT --log-level warn > wrangler-dev.log 2>&1 &
WPID=$!
trap 'kill $WPID 2>/dev/null' EXIT

for i in {1..60}; do
  curl -s -o /dev/null "$BASE/" && break
  sleep 1
done
curl -s -o /dev/null "$BASE/" || { echo "wrangler dev never came up — see wrangler-dev.log"; exit 1; }
echo "[dl-redirect spike] up on $BASE"

TAG=$(curl -s https://api.github.com/repos/jitpass/jit/releases/latest | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')
echo "[dl-redirect spike] latest release: $TAG"
echo

echo "[1] 302 + exact Location, per client class"
for ua in "Homebrew/4.3.0 (Macintosh; arm64 Mac OS X 15)" "curl/8.7.1" "jit-upgrade" "Mozilla/5.0 (Macintosh)"; do
  hdr=$(curl -s -o /dev/null -A "$ua" -w '%{http_code} %{redirect_url}' \
    "$BASE/jitpass/jit/releases/download/$TAG/jitpass_darwin_arm64.tar.gz")
  want="302 https://github.com/jitpass/jit/releases/download/$TAG/jitpass_darwin_arm64.tar.gz"
  [ "$hdr" = "$want" ] && ok "UA '$ua' -> $hdr" || bad "UA '$ua' -> got '$hdr' want '$want'"
done
hdr=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' \
  "$BASE/jitpass/jit/releases/latest/download/checksums.txt")
case "$hdr" in
  "302 https://github.com/jitpass/jit/releases/latest/download/checksums.txt") ok "latest/checksums.txt -> $hdr";;
  *) bad "latest/checksums.txt -> $hdr";;
esac
echo

echo "[2] allowlist: open-redirect probes must 404"
for p in \
  "/jitpass/jit/releases/download/$TAG/evil.sh" \
  "/jitpass/jit/releases/download/not-a-tag/jitpass_darwin_arm64.tar.gz" \
  "/jitpass/jit/releases/download/..%2f..%2fevil/jitpass_darwin_arm64.tar.gz" \
  "/other/repo/releases/download/$TAG/jitpass_darwin_arm64.tar.gz" \
  "/" ; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$p")
  [ "$code" = "404" ] && ok "404 $p" || bad "want 404 got $code for $p"
done
echo

echo "[3] byte integrity through the redirect (the check the cask sha256 depends on)"
curl -sL -A "Homebrew/4.3.0" -o /tmp/dl-spike.tar.gz \
  "$BASE/jitpass/jit/releases/download/$TAG/jitpass_darwin_arm64.tar.gz"
curl -sL -o /tmp/dl-spike-sums.txt \
  "$BASE/jitpass/jit/releases/download/$TAG/checksums.txt"
got=$(shasum -a 256 /tmp/dl-spike.tar.gz | cut -d' ' -f1)
want=$(grep 'jitpass_darwin_arm64.tar.gz' /tmp/dl-spike-sums.txt | cut -d' ' -f1)
[ -n "$got" ] && [ "$got" = "$want" ] \
  && ok "sha256 through redirect matches published checksums.txt ($got)" \
  || bad "sha256 mismatch: got=$got want=$want"
echo

echo "[4] HEAD also redirects (brew probes with HEAD before fetching)"
code=$(curl -s -o /dev/null -I -w '%{http_code}' \
  "$BASE/jitpass/jit/releases/download/$TAG/jitpass_darwin_arm64.tar.gz")
[ "$code" = "302" ] && ok "HEAD -> 302" || bad "HEAD -> $code"
echo

echo "[5] the log line the Worker emits (classification evidence)"
grep -o 'dl client=[^ ]* tag=[^ ]* asset=[^ ]*' wrangler-dev.log | sort | uniq -c | sed 's/^/  /'
echo

echo "── $PASS passed, $FAIL failed"
exit $((FAIL > 0))
