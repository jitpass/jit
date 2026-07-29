// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DerivedCredential is a credential-bearing file a TOOL wrote for itself,
// downstream of anything jit hands out — an STS session the AWS CLI cached
// after using a migrated key, an SSO token `aws sso login` stored.
//
// These are not findings and never become findings. A finding is something
// jit can offer to fix; these are outside its model by construction, because
// the value was minted by the tool rather than stored by the user, and it will
// be minted again the next time the tool runs. Migrating them would be a lie,
// and jit deliberately does not manage, clean or decoy them.
//
// What jit was doing wrong was not failing to protect them — it was saying
// nothing. They are hex-named, so the content sweep's filename hints walk past
// without opening them; `.terraform` and `Library` are pruned outright. So a
// user could migrate ~/.aws/credentials, watch `jit scan` come back clean, and
// still have a live plaintext session token sitting in the very directory jit
// had just tidied. An advisory costs nothing and closes that gap: the boundary
// becomes documented and visible rather than merely true.
type DerivedCredential struct {
	// Path is the file or directory holding the derived credential.
	Path string
	// What it is, in the user's terms — not a severity, not an instruction.
	What string
	// Advice is the one thing worth doing about it, if anything.
	Advice string
}

// ScanDerivedCredentials reports the derived artifacts jit knows how to
// recognize. It only ever reports things that actually exist: an advisory that
// lists hypothetical paths is noise, and noise is what stops people reading
// advisories.
//
// Cheap by design — a couple of stats and one small file read, no walking. It
// runs on every scan, including the ones that find nothing, because "nothing
// found" is exactly the report these artifacts are most likely to be hiding
// behind.
func ScanDerivedCredentials(cfg Config) []DerivedCredential {
	var out []DerivedCredential

	if n := countFilesIn(filepath.Join(cfg.HomeDir, ".aws", "cli", "cache")); n > 0 {
		out = append(out, DerivedCredential{
			Path:   filepath.Join(cfg.HomeDir, ".aws", "cli", "cache"),
			What:   "STS session credentials the AWS CLI cached for itself, in plaintext",
			Advice: "they expire on their own; delete the directory to clear them now",
		})
	}
	if n := countFilesIn(filepath.Join(cfg.HomeDir, ".aws", "sso", "cache")); n > 0 {
		out = append(out, DerivedCredential{
			Path:   filepath.Join(cfg.HomeDir, ".aws", "sso", "cache"),
			What:   "SSO access tokens and role credentials, in plaintext",
			Advice: "`aws sso logout` clears them",
		})
	}
	if hasAssumeRoleProfile(filepath.Join(cfg.HomeDir, ".aws", "config")) {
		out = append(out, DerivedCredential{
			Path:   filepath.Join(cfg.HomeDir, ".aws", "config"),
			What:   "assume-role profiles, which jit does not migrate (they carry no stored key of their own — only a role to assume with someone else's)",
			Advice: "migrating the source profile still protects the long-lived key; the session minted from it is cached by the CLI",
		})
	}

	return out
}

// countFilesIn returns how many regular files sit directly in dir. Contents
// are never opened: existence is the entire claim being made, and a scanner
// that reads a credential to report that a credential exists has defeated its
// own purpose.
func countFilesIn(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n
}

// hasAssumeRoleProfile reports whether ~/.aws/config declares any role_arn.
//
// Deliberately a line scan rather than a real INI parse: the question is only
// whether this machine has the shape of setup whose credentials jit's own
// discovery skips (DiscoverAWSProfiles selects on aws_secret_access_key, which
// an assume-role profile does not have), and a false positive costs one honest
// advisory line.
func hasAssumeRoleProfile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// A hand-edited config has short lines, but a machine-generated or
	// corrupt one can exceed the default 64KB token and stop the scan early.
	// Raising the cap keeps a long line from quietly ending the search before
	// it reaches a role_arn further down.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "role_arn") {
			return true
		}
	}
	// Falling out of the loop means either "no role_arn" or "the read failed
	// partway" — and both answer false, deliberately. An advisory exists to be
	// believed, so it reports only what was actually seen; a guess made from a
	// failed read is exactly the kind of line that teaches people to skip
	// these blocks.
	return false
}
