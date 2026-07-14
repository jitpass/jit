// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// envFileNamePattern matches .env, .env.local, .env.production, etc.
var envFileNamePattern = regexp.MustCompile(`^\.env(\..+)?$`)

// envTemplateSuffixes mark a .env-family file as a template/example, not a
// real file with real values — a universal, well-established convention
// (committed to git on purpose, meant to be shared). Real-world dogfooding
// (2026-07-06) showed roughly half of all .env findings on a real machine
// were .env.example files, which is exactly the kind of noise that erodes
// trust in the tool: flagging a template's mere existence the same as a
// real .env file is wrong. Content is still scanned for escalation (a real
// secret accidentally left in a template is still worth catching) — only
// the baseline "presence" finding is suppressed when nothing escalates.
var envTemplateSuffixes = map[string]bool{
	"example":  true,
	"sample":   true,
	"template": true,
	"dist":     true,
}

func isEnvTemplateFile(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return envTemplateSuffixes[ext]
}

// jitPointerFileSuffix mirrors internal/migrate/pointerfile.go's own
// PointerFilePath suffix (small independent copy, matching this file's
// existing convention for envFileNamePattern/envTemplateSuffixes rather
// than an audit->migrate import). envFileNamePattern's wildcard suffix
// match (meant to catch `.env.local`/`.env.production`) also matches
// jit's own `<file>.pointers` companion — e.g. `.env.pointers` — since
// it's just ".env" followed by another suffix. Without this exclusion,
// `jit audit` would falsely report a git-safe pointer file (which holds
// only `KEY=jit://vault/...` lines, never a real value) as an exposed
// .env secret — confirmed as the same underlying pattern bug that made
// `jit migrate` re-discover and destroy its own `.pointers` files on a
// second run (a real, reported incident — GAPS.md #30).
const jitPointerFileSuffix = ".pointers"

func isJitPointerFile(name string) bool {
	return strings.HasSuffix(name, jitPointerFileSuffix)
}

// pointerFileHeaderPrefix mirrors internal/migrate's own constant of the
// same name (small independent copy, matching this package's convention of
// not importing internal/migrate). It's the start of a jit pointer file's
// first line.
const pointerFileHeaderPrefix = "# jit pointer file"

// isJitPointerContent recognizes a jit pointer file by CONTENT, not name —
// the case isJitPointerFile's suffix check misses: a backup-suffixed .env
// file (.env.bak etc.) that `jit migrate` replaced in place with pointer
// content, keeping its original name (GAPS.md #66). Without this, audit
// re-reports that git-safe pointer file (only `KEY=jit://vault/...` lines,
// never a real value) as an exposed .env secret. Guarded to regular files:
// opening a live-mount FIFO with no writer would block the whole scan.
func isJitPointerContent(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) // #nosec G304 -- discovered path, confirmed a regular file just above
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return false
	}
	return strings.HasPrefix(scanner.Text(), pointerFileHeaderPrefix)
}

// envLinePattern matches `KEY=value` or `# KEY=value` (commented out).
// Group 1 is the optional leading "#" (non-empty means commented), group 2
// is the key, group 3 is the raw value.
var envLinePattern = regexp.MustCompile(`^\s*(#\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)

// ScanEnvFiles implements RFC.md §4 category 2: presence and location of
// .env files. Findings are file-level (RFC's literal wording — "presence
// and location," not "every variable inside"), not per-variable, but file
// content is still inspected to decide whether a file-level finding
// escalates to Critical, per the cross-cutting signals in RFC.md §4.
func ScanEnvFiles(cfg Config) ([]Finding, error) {
	var findings []Finding
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		name := d.Name()
		if !envFileNamePattern.MatchString(name) {
			return nil
		}
		if isJitPointerFile(name) || isJitPointerContent(path) {
			return nil
		}
		f, found, buildErr := buildEnvFileFinding(cfg, path, isEnvTemplateFile(name))
		if buildErr != nil {
			return nil // unreadable file — skip it, don't fail the whole scan
		}
		if found {
			findings = append(findings, f)
		}
		return nil
	})
	return findings, err
}

// buildEnvFileFinding returns found=false (no Finding) when path is a
// template file and nothing in it escalates — see envTemplateSuffixes.
func buildEnvFileFinding(cfg Config, path string, isTemplate bool) (Finding, bool, error) {
	file, err := openFile(path)
	if err != nil {
		return Finding{}, false, err
	}
	defer file.Close()

	var active, commented int
	var prodMatch, ipMatch, secretShaped, tokenMatch bool
	var publicIP, secretShapedKey, tokenVendor string
	var tokenVerified bool

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		m := envLinePattern.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		if m[1] != "" {
			commented++
		} else {
			active++
		}

		key := m[2]
		rawValue := unquote(m[3])
		if IsAlreadyMasked(rawValue) {
			continue // per RFC.md §4: already-masked values are never evaluated for these signals
		}
		if IsProductionIndicator(key) || IsProductionIndicator(rawValue) {
			prodMatch = true
		}
		if ip, ok := MatchPublicIP(rawValue); ok && !ipMatch {
			ipMatch = true
			publicIP = ip
		}
		// Checked regardless of template/comment status, same as
		// prodMatch/ipMatch above: a value that positively matches a known
		// vendor token format is meaningful evidence even in a template
		// file (a real token pasted into a .env.example is exactly the
		// kind of accident worth catching) and even when commented out
		// (still plaintext at rest).
		if !tokenMatch {
			if vendor, verified, ok := MatchKnownTokenPattern(rawValue); ok {
				tokenMatch, tokenVendor, tokenVerified = true, vendor, verified
			}
		}
		// Only active (uncommented) variables count toward this, only for
		// real files (not templates — see below), and rawValue being
		// non-empty rules out a bare `KEY=` placeholder line. Real-world
		// review (2026-07-06) found this gap directly: a real, company-wide
		// management key sat in a variable named "DESCOPE_MGMT_KEY" and was
		// rated Low, identical to a file containing nothing but
		// NAME=whatever — because nothing here was checking whether a
		// variable NAME looks like a real secret, the same LooksLikeSecretKey
		// check the shell-config scanner already applies.
		//
		// Templates are deliberately exempt from this specific check: an
		// .env.example's entire purpose is documenting which secret-shaped
		// variable NAMES a real .env needs (API_KEY, DATABASE_URL are
		// exactly what a template is supposed to contain) — the name alone
		// is not evidence of anything for a template, only its value is
		// (still covered by prodMatch/ipMatch above, which inspect values).
		if !isTemplate && m[1] == "" && rawValue != "" && !secretShaped && LooksLikeSecretKey(key) {
			secretShaped = true
			secretShapedKey = key
		}
	}
	if err := scanner.Err(); err != nil {
		return Finding{}, false, err
	}

	if isTemplate && !prodMatch && !ipMatch && !tokenMatch {
		return Finding{}, false, nil
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypeEnvFilePresent
	f.FilePath = path
	f.Confidence = ConfidenceHigh
	f.ProductionIndicatorMatch = prodMatch
	if ipMatch {
		f.PublicIPMatch = &publicIP
	}

	switch {
	case prodMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a value matching the production-indicator pattern"
	case ipMatch:
		f.Severity = SeverityCritical
		f.Evidence = "contains a public IP address in a visible value"
	case tokenMatch:
		f.Severity = SeverityHigh
		if tokenVerified {
			f.Confidence = ConfidenceHigh
			f.Evidence = fmt.Sprintf("contains a value matching %s's known token format", tokenVendor)
		} else {
			f.Confidence = ConfidenceMedium
			f.Evidence = fmt.Sprintf("contains a value that looks like it may be a %s (pattern not independently verified)", tokenVendor)
		}
	case secretShaped:
		f.Severity = SeverityHigh
		f.Evidence = fmt.Sprintf("contains %q, a variable name that looks like a real credential", secretShapedKey)
	default:
		f.Severity = SeverityLow
		// Spell out *why* this is a finding at all, not just the raw count —
		// a real user reading "12 variable(s) found (12 active, 0 commented
		// out)" understandably asked what that meant. The point isn't the
		// count, it's that every one of those values is stored here as
		// plaintext regardless of whether it's currently active or
		// commented out.
		f.Evidence = fmt.Sprintf(
			"%d variable(s) in this file (%d active, %d commented out) — either way, the values are stored here in plaintext",
			active+commented, active, commented,
		)
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f, true, nil
}
