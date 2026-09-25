#!/bin/sh
# S3f. Every step signs with the team's Apple Development identity; the
# release signs with Developer ID, so the certificate part of each designated
# requirement differs from production, but the question is whether a change
# of IDENTIFIER (jit -> com.jitpass.agent) breaks the item's ACL.
set -u
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="Apple Development: Meni Tasa (PKB9L7KK78)"
rm -rf out && mkdir -p out
clang -fobjc-arc -framework Foundation -framework Security -o out/acl acl.m

# 1. Today's shape: a bare Mach-O signed with identifier "jit".
cp out/acl out/jit
codesign --force --options runtime --timestamp=none -i jit --sign "$ID" out/jit 2>/dev/null

helper() { # name identifier-flag...
  app="out/$1.app/Contents"; mkdir -p "$app/MacOS"
  sed 's#<string>sekey</string>#<string>jit</string>#' ../s3a/Info.plist > "$app/Info.plist"
  cp "$PROFILE" "$app/embedded.provisionprofile"
  cp out/acl "$app/MacOS/jit"
  shift
  codesign --force --options runtime --timestamp=none "$@" --entitlements ../s3a/agent.entitlements --sign "$ID" "out/$(basename "$(dirname "$app")")" 2>/dev/null
}
helper HelperDefault                 # identifier = CFBundleIdentifier (com.jitpass.agent), what A1 ships
helper HelperKeepsJit -i jit         # identifier forced back to "jit"

echo "== identifiers"
for b in out/jit out/HelperDefault.app out/HelperKeepsJit.app; do
  printf "%-26s " "$b"; codesign -dv "$b" 2>&1 | grep '^Identifier='
done
echo "== the old jit creates the item (as every current vault's key was)"
out/jit create
echo "== control: the same old jit reads it"
out/jit read
echo "== A1 as built: helper, identifier com.jitpass.agent"
out/HelperDefault.app/Contents/MacOS/jit read
echo "== candidate fix: helper, identifier kept as jit"
out/HelperKeepsJit.app/Contents/MacOS/jit read
echo "== cleanup"
out/jit delete
