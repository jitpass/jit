#!/bin/sh
# S3g build. Four signings of the same program (owner.m):
#   out/oldjit             bare Mach-O, identifier jit, no entitlements: every
#                          released jit's shape (they are Developer ID; this
#                          Mac has only the team's Apple Development identity)
#   out/Helper.app         the JitPass Agent helper's shape: bundle
#                          com.jitpass.agent, embedded profile, identifier jit,
#                          application-identifier + keychain-access-groups
#   out/HelperNoEnt.app    the same bundle, identifier jit, NO entitlements
#                          and no profile (isolates what the entitlements do)
#   out/adhoc              ad-hoc signed
set -eu
cd "$(dirname "$0")"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
ID="${SIGN_IDENTITY:-Apple Development: Meni Tasa (PKB9L7KK78)}"
rm -rf out && mkdir -p out
clang -fobjc-arc -framework Foundation -framework Security -o out/owner owner.m

cp out/owner out/oldjit
codesign --force --options runtime --timestamp=none -i jit --sign "$ID" out/oldjit

bundle() { # name [codesign args...]
  n=$1; shift
  c="out/$n.app/Contents"; mkdir -p "$c/MacOS"
  sed 's#<string>sekey</string>#<string>jit</string>#' ../s3a/Info.plist > "$c/Info.plist"
  cp out/owner "$c/MacOS/jit"
  codesign --force --options runtime --timestamp=none -i jit "$@" --sign "$ID" "out/$n.app"
}
bundle HelperNoEnt
mkdir -p out/Helper.app/Contents
cp "$PROFILE" out/Helper.app/Contents/embedded.provisionprofile
bundle Helper --entitlements ../s3a/agent.entitlements

cp out/owner out/adhoc
codesign --force --sign - out/adhoc

for b in out/oldjit out/Helper.app out/HelperNoEnt.app out/adhoc; do
  printf "%-22s %s\n" "$b" "$(codesign -dv "$b" 2>&1 | grep -E '^(Identifier|TeamIdentifier)=' | tr '\n' ' ')"
done
