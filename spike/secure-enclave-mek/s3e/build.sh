#!/bin/sh
# S3e: the layout track A ships. An outer app whose OLD path
# Contents/MacOS/jit is a symlink into a nested helper bundle
# Contents/Helpers/JitPassAgentSpike.app, whose main executable is the S3c
# Go jit with the entitlements and the profile. Signed inside out.
set -eu
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="Apple Development: Meni Tasa (PKB9L7KK78)"
OUT=out/OuterSpike.app
H="$OUT/Contents/Helpers/JitPassAgentSpike.app"
rm -rf out && mkdir -p "$OUT/Contents/MacOS" "$H/Contents/MacOS"
# helper: the S3c Go program, as jit
(cd ../s3c && CGO_ENABLED=1 go build -o ../s3e/"$H/Contents/MacOS/jit" .)
sed 's#<string>sekey</string>#<string>jit</string>#' ../s3a/Info.plist > "$H/Contents/Info.plist"
cp "$PROFILE" "$H/Contents/embedded.provisionprofile"
# outer: its own main executable, plist, and the compat symlink
clang -o "$OUT/Contents/MacOS/OuterSpike" outer.m
cat > "$OUT/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.jitpass.spike.outer</string>
<key>CFBundleExecutable</key><string>OuterSpike</string>
<key>CFBundleName</key><string>Outer Spike</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
</dict></plist>
PL
ln -s ../Helpers/JitPassAgentSpike.app/Contents/MacOS/jit "$OUT/Contents/MacOS/jit"
# inside out: helper with entitlements, then the outer app (no entitlements)
codesign --force --options runtime --timestamp=none --entitlements ../s3a/agent.entitlements --sign "$ID" "$H"
codesign --force --options runtime --timestamp=none --sign "$ID" "$OUT"
codesign --verify --strict --deep "$OUT" && echo "verify --strict --deep: OK"
