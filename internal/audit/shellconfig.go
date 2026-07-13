// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
)

// shellConfigFiles are the shell init files checked, relative to HomeDir.
// RFC.md §4 category 1 names .zshrc/.bashrc/etc. as examples, not an
// exhaustive list — this covers the common cases for zsh and bash, the two
// default shells on modern macOS and most Linux distros.
var shellConfigFiles = []string{
	".zshrc",
	".zprofile",
	".bashrc",
	".bash_profile",
	".profile",
}

// exportLinePattern matches `export KEY=value` (with or without quotes
// around the value). Deliberately scoped to exactly RFC.md §4's stated
// category definition ("plaintext `export KEY=value` assignments") rather
// than also matching bare `KEY=value` — a bare assignment without `export`
// never reaches a child process's environment, so it's a materially
// different (and much noisier, since it'd match far more of a typical shell
// config) risk than what this category is about.
var exportLinePattern = regexp.MustCompile(`^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)

// ScanShellConfigs implements RFC.md §4 category 1.
func ScanShellConfigs(cfg Config) ([]Finding, error) {
	var findings []Finding
	for _, name := range shellConfigFiles {
		path := filepath.Join(cfg.HomeDir, name)
		fileFindings, err := scanShellConfigFile(cfg, path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return findings, err
		}
		findings = append(findings, fileFindings...)
	}
	return findings, nil
}

func scanShellConfigFile(cfg Config, path string) ([]Finding, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		m := exportLinePattern.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}
		key := m[1]
		if !LooksLikeSecretKey(key) {
			continue
		}
		rawValue := unquote(m[2])
		line := lineNum // capture per-iteration value, not the loop variable's address

		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeShellConfigSecret,
			FilePath:     path,
			Line:         &line,
			KeyName:      key,
			RawValue:     rawValue,
			BaseSeverity: SeverityHigh, // RFC.md §4 risk table: "any shell-config plaintext export" -> High
			Confidence:   ConfidenceHigh,
			Evidence:     "export statement assigns a value to a key name that looks like a secret",
		}))
	}
	return findings, scanner.Err()
}

// unquote strips a single layer of matching surrounding quotes, if present,
// so a masked preview doesn't include the quote characters themselves.
func unquote(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
