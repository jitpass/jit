#!/bin/sh
# out/JitPassAgentSpike.app with CFBundleExecutable=jit (a Go binary), signed
# with the dev identity, the S3a entitlements and the dev profile.
set -eu
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="Apple Development: Meni Tasa (PKB9L7KK78)"
rm -rf out && mkdir -p out/JitPassAgentSpike.app/Contents/MacOS
CGO_ENABLED=1 go build -o out/JitPassAgentSpike.app/Contents/MacOS/jit .
sed 's#<string>sekey</string>#<string>jit</string>#' ../s3a/Info.plist > out/JitPassAgentSpike.app/Contents/Info.plist
cp "$PROFILE" out/JitPassAgentSpike.app/Contents/embedded.provisionprofile
codesign --force --options runtime --timestamp=none --entitlements ../s3a/agent.entitlements --sign "$ID" out/JitPassAgentSpike.app
codesign --verify --strict out/JitPassAgentSpike.app && echo "signed: out/JitPassAgentSpike.app (exe: jit)"
