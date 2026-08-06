// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
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
//     and MCP — exactly as a machine-wide walk would.
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
	// Read failures on a NAMED file are reported, never swallowed. The
	// machine-wide scan has always surfaced these as degraded scanners; the
	// targeted path used to drop them, so `jit scan ~/.zsh_history` on a file
	// it could not open (permissions, or past the size bound) printed
	// "CLEAN — exposure 0/100" and exited 0. That is the exact failure the
	// size-bound comment in shellhistory.go exists to prevent, arriving by the
	// other door: "we could not look" must never render as "there is nothing
	// there".
	var degraded []ScannerFailure
	for _, target := range targets {
		info, err := os.Lstat(target)
		if err != nil {
			continue // unstattable — the CLI already fails loud on a missing path
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			continue // no-follow, same policy as walkHomeDir
		case info.IsDir():
			if cfg.Progress != nil {
				cfg.Progress(filepath.Base(target))
			}
			all = append(all, scanTargetDir(cfg, target)...)
		case info.Mode().IsRegular():
			if cfg.Progress != nil {
				cfg.Progress(filepath.Base(target))
			}
			fs, failures := scanTargetFile(cfg, target)
			all = append(all, fs...)
			degraded = append(degraded, failures...)
		}
	}
	all = dedupeFindings(all)

	// Same redundancy filter Scan applies: a targeted directory scan runs the
	// classify halves too, so a claimed file could otherwise be reported both
	// by its own category and as an exposed_secret.
	all = dropRedundantExposedSecrets(all)

	// Same central archived/fixture tagging Scan applies (see scan.go): a
	// targeted path can just as easily point into ~/.Trash or a timestamped
	// backup, and `jit scan ./internal` is if anything the MORE likely way to
	// be handed a repository full of test fixtures.
	tagArchivedAndFixtures(all)
	// And the same remedy/cause annotation, for the same no-drift reason.
	annotateRemedies(all, cfg.HomeDir)

	summary := buildScanSummary(cfg, all, countProtectedMounts(cfg.MountRegistryPath), time.Since(start))
	summary.DegradedScanners = degraded
	coverage := ComputeCoverage(cfg.MountRegistryPath, all)
	summary.SecretsTotal = coverage.Total()
	summary.SecretsProtected = coverage.Protected
	summary.SecretsMigratable = coverage.Migratable
	return all, summary, nil
}

// scanTargetDir walks dir and runs the name-gated content scanners on every
// regular file, mirroring what a machine-wide walk does under $HOME. It
// dispatches from the same categories table Scan does, rather than naming the
// classifiers by hand, so a category can never be covered by one walk and
// silently missed by the other — which is exactly what had happened to the
// project-local .npmrc check, present in the machine-wide walk and absent
// here. The generic vendor-token sweep is deliberately NOT run — it is
// reserved for files the user names explicitly (scanTargetFile), so a
// directory scan keeps the low-false-positive, name-gated behavior of the
// full scan.
func scanTargetDir(cfg Config, dir string) []Finding {
	var findings []Finding
	_ = walkHomeDir(dir, func(path string, d fs.DirEntry) error {
		name := d.Name()
		for _, c := range categories {
			if c.classify != nil {
				findings = append(findings, c.classify(cfg, path, name)...)
			}
		}
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
func scanTargetFile(cfg Config, path string) ([]Finding, []ScannerFailure) {
	name := filepath.Base(path)
	var findings []Finding
	var failures []ScannerFailure
	structured := false
	// note records a scanner that could not read this file, so the summary can
	// say so instead of reporting a clean scan of a file nobody read.
	note := func(scanner string, err error) {
		failures = append(failures, ScannerFailure{
			Scanner: scanner,
			Error:   fmt.Sprintf("%s: %v", ShortenHome(cfg.HomeDir, path), err),
		})
	}

	if isShellConfigName(name) {
		structured = true
		if fs, err := scanShellConfigFile(cfg, path); err == nil {
			findings = append(findings, fs...)
		} else {
			note("shell config", err)
		}
	}
	// A named history file routes to its own scanner rather than the generic
	// sweep below: the sweep would match the same tokens but knows nothing of
	// the format, so it would report line numbers inside zsh's metadata and
	// pay the full pattern cost on every timestamp.
	if isShellHistoryName(name) {
		structured = true
		if fs, err := scanShellHistoryFile(cfg, path); err == nil {
			findings = append(findings, fs...)
		} else {
			note("shell history", err)
		}
	}
	if envFileNamePattern.MatchString(name) {
		structured = true
		findings = append(findings, classifyEnvFile(cfg, path, name)...)
	}
	if mcpConfigFileNames[name] {
		structured = true
		findings = append(findings, classifyMCPFile(cfg, path, name)...)
	}
	// scanNpmrcFile directly, not classifyProjectNpmrc: that one excludes the
	// global ~/.npmrc because the machine-wide scan's fixed half owns it, but
	// a targeted scan has no fixed half — naming ~/.npmrc explicitly has to
	// scan it, not skip it.
	if name == ".npmrc" {
		structured = true
		if fs, err := scanNpmrcFile(path, cfg); err == nil {
			findings = append(findings, fs...)
		} else {
			note("npmrc", err)
		}
	}
	if isTFVars, isK8s := iacNameGates(name); isTFVars || isK8s {
		structured = true
		findings = append(findings, classifyIACFile(cfg, path, name)...)
	}

	// A content check that doesn't care what the file is named: the
	// private-key sniff (inSSHDir=false → a key here is "outside ~/.ssh").
	if f, err := inspectPrivateKeyFile(cfg, path, false); err == nil && f != nil {
		findings = append(findings, *f)
	}

	// The vendor-token sweep is the fallback for a file no structured scanner
	// recognizes (token.txt, config.txt, a random dump) — the whole reason a
	// bare JWT was previously invisible to `jit scan`.
	if !structured {
		if fs, err := scanFileContentForTokens(cfg, path); err == nil {
			findings = append(findings, fs...)
		} else {
			note("exposed secrets", err)
		}
	}
	return findings, failures
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
