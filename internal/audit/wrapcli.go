// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/wrap"
)

// ScanWrappableCLITokens reports plaintext tokens sitting in the config
// files of CLIs the wrap catalog knows how to fix (docs/internal/WRAP-PLAN.md §3.4).
// It consumes wrap's own catalog and extractors, so detection here and
// migration in `jit wrap <tool>` literally share code and can't drift: a
// token this scanner can see is by construction one wrap can move.
//
// Native-delegated entries (aws, terraform, docker) are skipped — their
// files are already ScanCredentialFiles' beat, and double-reporting one
// file under two categories would inflate the summary counts.
//
// A Source that points at a .env-family file (gemini's ~/.env and
// ~/.gemini/.env) is skipped here for the same reason: ScanEnvFiles already
// walks and reports those, so letting this scanner report them too would
// double-count the identical at-rest secret under two finding types (a real
// inflation of TotalFindings/ExposureScore, confirmed for GEMINI_API_KEY).
// ScanEnvFiles' name/value heuristics catch GEMINI_API_KEY there anyway, and
// it re-attaches the `jit wrap` remediation to its own finding via
// wrap.WrappableToolForPath, so skipping here costs neither detection nor the
// actionable hint.
func ScanWrappableCLITokens(cfg Config) ([]Finding, error) {
	var findings []Finding
	for _, tool := range wrap.CatalogTools() {
		entry, _ := wrap.Lookup(tool)
		if entry.Kind != wrap.KindShim {
			continue
		}
		for _, src := range entry.Sources {
			if envFileNamePattern.MatchString(filepath.Base(src.Path)) {
				continue // ScanEnvFiles owns .env-family files; don't double-report
			}
			value, found, err := wrap.ExtractToken(cfg.HomeDir, src)
			if err != nil || !found {
				// An unreadable or token-less file is a skip, never a
				// failed run — same forgiveness as every other scanner.
				continue
			}

			f := cfg.baseFinding()
			f.FindingType = FindingTypeWrappableCLIToken
			f.Severity = SeverityHigh
			f.FilePath = wrap.ExpandHome(cfg.HomeDir, src.Path)
			parts := strings.Split(src.Selector, "/")
			key := parts[len(parts)-1]
			if key == "" { // raw source: no selector — the file name is the key
				key = filepath.Base(src.Path)
			}
			f.KeyName = &key
			preview := MaskValue(value)
			f.ValuePreview = &preview
			f.Confidence = ConfidenceHigh
			f.Evidence = fmt.Sprintf("%s in plaintext; one command moves it into the vault and keeps %s working: jit wrap %s", entry.Doc, tool, tool)
			// Set here, not in annotateRemedies: only this scanner knows
			// which catalog tool owns the file, and the command is the tool
			// name, not the file path.
			f.Remedy = RemedyWrap
			f.FixCommand = "jit wrap " + tool
			f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
			findings = append(findings, f)
			break // first matching source is the live token; one finding per tool
		}
	}
	return findings, nil
}
