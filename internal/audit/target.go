// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// TargetedScan scans exactly the files and directories named in targets and
// nothing else — the engine behind `jit scan <path>...`. Unlike Scan, it never
// probes the fixed machine-wide locations (~/.aws/credentials, ~/.ssh, shell
// rc files, …): pointing jit at ./project must not drag in every credential
// store on the machine.
//
// Each target is dispatched by kind:
//
//   - a directory is walked (same noiseDir/symlink bounds as the home walk)
//     and every file run through the name-gated content scanners — env, IaC,
//     MCP, and suspicious-filename — exactly as a machine-wide walk would.
//   - a regular file is classified directly, name gate bypassed: naming it is
//     a strong statement of intent, so a shell rc / env / MCP / IaC file is
//     routed to its scanner by name, a private-key body is content-sniffed,
//     and anything that matches no structured category is swept for vendor
//     tokens (scanFileContentForTokens) — this is what lets `jit scan
//     token.txt` catch a bare JWT the name-based scanners never would.
//
// Symlinks are skipped (no-follow, matching the home walk). Findings are
// deduplicated by record_id so overlapping targets (a directory plus a file
// inside it) don't report the same file twice.
func TargetedScan(cfg Config, targets []string) ([]Finding, ScanSummary, error) {
	start := time.Now()

	var all []Finding
	for _, target := range targets {
		info, err := os.Lstat(target)
		if err != nil {
			continue // unstattable — the CLI already fails loud on a missing path
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			continue // no-follow, same policy as walkHomeDir
		case info.IsDir():
			all = append(all, scanTargetDir(cfg, target)...)
		case info.Mode().IsRegular():
			all = append(all, scanTargetFile(cfg, target)...)
		}
	}
	all = dedupeFindings(all)

	// Same central archived tagging Scan applies (see scan.go): a targeted
	// path can just as easily point into ~/.Trash or a timestamped backup.
	for i := range all {
		all[i].Archived = LooksArchived(all[i].FilePath)
	}

	summary := buildScanSummary(cfg, all, countProtectedMounts(cfg.MountRegistryPath), time.Since(start))
	return all, summary, nil
}

// scanTargetDir walks dir and runs the name-gated content scanners on every
// regular file, mirroring what a machine-wide walk does under $HOME. The
// generic vendor-token sweep is deliberately NOT run here — it is reserved for
// files the user names explicitly (scanTargetFile), so a directory scan keeps
// the low-false-positive, name-gated behavior of the full scan.
func scanTargetDir(cfg Config, dir string) []Finding {
	var findings []Finding
	_ = walkHomeDir(dir, func(path string, d fs.DirEntry) error {
		name := d.Name()
		if fs, err := classifyEnvFile(cfg, path, name); err == nil {
			findings = append(findings, fs...)
		}
		findings = append(findings, classifyIACFile(cfg, path, name)...)
		if fs, err := classifyMCPFile(cfg, path, name); err == nil {
			findings = append(findings, fs...)
		}
		findings = append(findings, classifySuspiciousFile(cfg, path, name)...)
		return nil
	})
	return findings
}

// scanTargetFile classifies one explicitly named regular file. A name that
// matches a structured category (shell rc, env, MCP, IaC) is routed to that
// scanner, which reports the secret far more precisely than a raw content
// sweep could. A private-key body is always content-sniffed. Only when no
// structured category claims the file does the generic vendor-token sweep run
// — otherwise a `.env` would be reported twice, once structured and once by
// the sweep.
func scanTargetFile(cfg Config, path string) []Finding {
	name := filepath.Base(path)
	var findings []Finding
	structured := false

	if isShellConfigName(name) {
		structured = true
		if fs, err := scanShellConfigFile(cfg, path); err == nil {
			findings = append(findings, fs...)
		}
	}
	if envFileNamePattern.MatchString(name) {
		structured = true
		if fs, err := classifyEnvFile(cfg, path, name); err == nil {
			findings = append(findings, fs...)
		}
	}
	if mcpConfigFileNames[name] {
		structured = true
		if fs, err := classifyMCPFile(cfg, path, name); err == nil {
			findings = append(findings, fs...)
		}
	}
	if isTFVars, isK8s := iacNameGates(name); isTFVars || isK8s {
		structured = true
		findings = append(findings, classifyIACFile(cfg, path, name)...)
	}

	// Content checks that don't care what the file is named. The private-key
	// sniff (inSSHDir=false → a key here is "outside ~/.ssh") always runs;
	// suspicious-name rules are orthogonal to the structured categories above.
	if f, err := inspectPrivateKeyFile(cfg, path, false); err == nil && f != nil {
		findings = append(findings, *f)
	}
	findings = append(findings, classifySuspiciousFile(cfg, path, name)...)

	// The vendor-token sweep is the fallback for a file no structured scanner
	// recognizes (token.txt, config.txt, a random dump) — the whole reason a
	// bare JWT was previously invisible to `jit scan`.
	if !structured {
		if fs, err := scanFileContentForTokens(cfg, path); err == nil {
			findings = append(findings, fs...)
		}
	}
	return findings
}

// dedupeFindings removes findings sharing a record_id, preserving first-seen
// order. Overlapping targets (a directory and a file within it, or the same
// path named twice) can otherwise surface one file's finding more than once;
// record_id is the documented dedup key, so collapsing on it here matches how
// a downstream NDJSON consumer would.
func dedupeFindings(findings []Finding) []Finding {
	seen := make(map[string]bool, len(findings))
	out := findings[:0]
	for _, f := range findings {
		if seen[f.RecordID] {
			continue
		}
		seen[f.RecordID] = true
		out = append(out, f)
	}
	return out
}
