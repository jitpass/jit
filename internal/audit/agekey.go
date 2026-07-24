// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ageKeyRelativePaths are the two locations sops actually reads a
// default age key file from on macOS, in sops's own resolution order:
// the platform config dir (Application Support — what sops uses when
// XDG_CONFIG_HOME is unset, the common case on a Mac) and the XDG
// convention path many developers create anyway because every Linux
// tutorial names it. Both are checked because which one a machine uses
// depends on env vars the audit can't see; missing the Application
// Support path would skip the standard macOS location entirely.
var ageKeyRelativePaths = [][]string{
	{"Library", "Application Support", "sops", "age", "keys.txt"},
	{".config", "sops", "age", "keys.txt"},
}

// ScanSOPSAgeKeys implements the sops_age_key category (schema 0.6.0): the
// age private key file sops, kluctl, Flux, and helm-secrets all share.
// This file is the single highest-value secret on a machine that uses
// SOPS-encrypted repos — one plaintext line decrypts every encrypted
// secret in every repo, for every environment those repos cover — which
// is why it gets its own category instead of folding into the generic
// credential-file list.
func ScanSOPSAgeKeys(cfg Config) ([]Finding, error) {
	var findings []Finding
	for _, rel := range ageKeyRelativePaths {
		path := filepath.Join(append([]string{cfg.HomeDir}, rel...)...)
		// Lstat + IsRegular, not a bare open: `jit migrate home` can turn
		// this file into a live template mount, and opening that FIFO
		// would block the scan forever with no agent writing — the same
		// guard scanGCPApplicationDefaultCredentials applies, needed here
		// because this is a fixed path checked outside walkHomeDir's own
		// filter.
		if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() {
			if statErr != nil && !os.IsNotExist(statErr) {
				return nil, statErr
			}
			continue
		}
		fs, err := scanAgeKeyFile(cfg, path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		findings = append(findings, fs...)
	}
	return findings, nil
}

func scanAgeKeyFile(cfg Config, path string) ([]Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	keyIndex := 0
	lineNo := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
			continue // comment lines carry the public key and dates, not secrets
		}
		keyIndex++
		keyName := "age_secret_key"
		if keyIndex > 1 {
			keyName = fmt.Sprintf("age_secret_key_%d", keyIndex)
		}
		n := lineNo
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeSOPSAgeKey,
			FilePath:     path,
			Line:         &n,
			KeyName:      keyName,
			RawValue:     line,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "SOPS age private key: decrypts every SOPS-encrypted secret this key guards (sops, kluctl, Flux, helm-secrets)",
		}))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return findings, nil
}
