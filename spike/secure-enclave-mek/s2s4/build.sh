#!/bin/sh
# out/JitPassAgentSpike.app with CFBundleExecutable=probe; dev identity, the
# S3a entitlements, the dev profile.
set -eu
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="Apple Development: Meni Tasa (PKB9L7KK78)"
rm -rf out && mkdir -p out/JitPassAgentSpike.app/Contents/MacOS
clang -fobjc-arc -framework Foundation -framework Security -framework LocalAuthentication -framework CoreGraphics \
  -o out/JitPassAgentSpike.app/Contents/MacOS/probe probe.m
sed 's#<string>sekey</string>#<string>probe</string>#' ../s3a/Info.plist > out/JitPassAgentSpike.app/Contents/Info.plist
cp "$PROFILE" out/JitPassAgentSpike.app/Contents/embedded.provisionprofile
codesign --force --options runtime --timestamp=none --entitlements ../s3a/agent.entitlements --sign "$ID" out/JitPassAgentSpike.app
codesign --verify --strict out/JitPassAgentSpike.app && echo "signed: out/JitPassAgentSpike.app (exe: probe)"
