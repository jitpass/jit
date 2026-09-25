#!/usr/bin/env bash
# se-test.sh: run internal/secureenclave's tests against the REAL Secure
# Enclave.
#
# A plain `go test` binary cannot reach the enclave: persisting an enclave key
# needs the keychain-access-groups entitlement, which only a provisioning
# profile embedded in a bundle can authorize, and only for that bundle's main
# executable (spike/secure-enclave-mek/FINDINGS.md, S3a). So this builds the
# package's test binary, makes it the main executable of a throwaway bundle
# with the JitPass Agent profile, signs it, and runs it with JIT_SE_TEST=1.
#
# Every key the tests make has a TEST-ONLY tag and is deleted before they
# end; nothing here touches the real vault key (tag com.jitpass.vault.kek).
#
# Usage:
#   scripts/se-test.sh                        # unattended: keys that never ask
#   JIT_SE_INTERACTIVE=1 scripts/se-test.sh   # also the Touch ID key (one dialog)
#   PKG=./internal/cli JIT_SE_INTERACTIVE=1 scripts/se-test.sh -test.run TestHardwareMoveRoundTrip
#                                             # the key move, TEST-ONLY names (three dialogs)
# Env:
#   PROFILE        provisioning profile (default: the dev profile in ~/Downloads)
#   SIGN_IDENTITY  codesign identity (default: the team's Apple Development one)
#   TEAM_ID        default CZC6BH93GJ
#   PKG            the package whose tests to run (default ./internal/secureenclave)
#
# Needs a Mac listed in the development profile. CI cannot run this until the
# profile is a CI secret (design/secure-enclave-plan.md, B1); until then it is
# a pre-release step on a Mac.
set -euo pipefail

TEAM_ID="${TEAM_ID:-CZC6BH93GJ}"
PKG="${PKG:-./internal/secureenclave}"
PROFILE="${PROFILE:-$HOME/Downloads/JitPass_Agent_Dev.provisionprofile}"
BUNDLE_ID="com.jitpass.agent"
GROUP="$TEAM_ID.com.jitpass.vault"

die() { echo "se-test: $*" >&2; exit 1; }

cd "$(dirname "$0")/.."
[[ -f "$PROFILE" ]] || die "no provisioning profile at $PROFILE (set PROFILE)"

# The profile must be for this app ID and team, or the binary is killed at
# launch with no message worth reading.
plist=$(security cms -D -i "$PROFILE") || die "cannot decode $PROFILE"
appid=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.application-identifier" /dev/stdin <<<"$plist")
[[ "$appid" == "$TEAM_ID.$BUNDLE_ID" ]] || die "$PROFILE is for $appid, want $TEAM_ID.$BUNDLE_ID"

# Pick the identity by TEAM (the certificate's OU), never by name, the rule
# jit-app's sign.sh follows. An Apple Development identity: a development
# profile does not accept a Developer ID signature.
if [[ -z "${SIGN_IDENTITY:-}" ]]; then
  while read -r _ sha name; do
    name=${name#\"}; name=${name%\"}
    [[ "$name" == "Apple Development:"* ]] || continue
    if security find-certificate -Z -a -c "$name" -p 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | grep -q "OU=$TEAM_ID"; then
      SIGN_IDENTITY="$sha"; break
    fi
  done < <(security find-identity -v -p codesigning | grep -E '^ +[0-9]+\)')
fi
[[ -n "${SIGN_IDENTITY:-}" ]] || die "no Apple Development identity for team $TEAM_ID (see spike/secure-enclave-mek/FINDINGS.md: WWDR G3)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
app="$work/SecureEnclaveTest.app"
mkdir -p "$app/Contents/MacOS"

CGO_ENABLED=1 go test -c -o "$app/Contents/MacOS/secureenclave.test" "$PKG"
cp "$PROFILE" "$app/Contents/embedded.provisionprofile"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
<key>CFBundleExecutable</key><string>secureenclave.test</string>
<key>CFBundleName</key><string>jit test</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
</dict></plist>
PLIST
cat > "$work/test.entitlements" <<ENT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.application-identifier</key><string>$TEAM_ID.$BUNDLE_ID</string>
<key>com.apple.developer.team-identifier</key><string>$TEAM_ID</string>
<key>keychain-access-groups</key><array><string>$GROUP</string></array>
</dict></plist>
ENT
codesign --force --options runtime --timestamp=none --entitlements "$work/test.entitlements" --sign "$SIGN_IDENTITY" "$app"
codesign --verify --strict "$app"

JIT_SE_TEST=1 "$app/Contents/MacOS/secureenclave.test" -test.v -test.count=1 "$@"
