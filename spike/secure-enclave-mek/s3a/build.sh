#!/bin/sh
# Builds three variants of the same program:
#   out/JitPassAgentSpike.app  bundle + embedded profile + entitlements (the test)
#   out/bare-signed            same entitlements, no bundle   (control: AMFI should kill it)
#   out/bundle-noent           bundle + profile, no entitlements (control: -34018)
set -eu
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="Apple Development: Meni Tasa (PKB9L7KK78)"
rm -rf out && mkdir -p out
clang -fobjc-arc -framework Foundation -framework Security -o out/sekey sekey.m

mkbundle() { # name
  b="out/$1.app/Contents"; mkdir -p "$b/MacOS"
  cp Info.plist "$b/Info.plist"; cp out/sekey "$b/MacOS/sekey"
  cp "$PROFILE" "$b/embedded.provisionprofile"
}
mkbundle JitPassAgentSpike
codesign --force --options runtime --timestamp=none --entitlements agent.entitlements --sign "$ID" out/JitPassAgentSpike.app
mkbundle bundle-noent
codesign --force --options runtime --timestamp=none --sign "$ID" out/bundle-noent.app
cp out/sekey out/bare-signed
codesign --force --options runtime --timestamp=none --entitlements agent.entitlements --sign "$ID" out/bare-signed
codesign --verify --strict out/JitPassAgentSpike.app && echo "signed: out/JitPassAgentSpike.app"
