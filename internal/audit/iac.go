// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"bufio"
	"io/fs"
	"strings"
)

// ScanIACFiles implements RFC.md §4 category 6: IaC variable files,
// detection only (no auto-fix yet, per RFC.md §1/§4). Covers Terraform's
// terraform.tfvars/*.auto.tfvars convention and Kubernetes/Helm-style
// secrets.yaml manifests — the latter added after real-world review
// (2026-07-06, see ROADMAP.md) showed it's far more common in practice
// than .tfvars alone. Findings are file-level, with content still
// inspected for the universal cross-cutting escalation signals (RFC.md §4:
// "regardless of category").
func ScanIACFiles(cfg Config) ([]Finding, error) {
	var findings []Finding
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		name := d.Name()
		isTFVars := name == "terraform.tfvars" || strings.HasSuffix(name, ".auto.tfvars")
		isK8sSecrets := strings.ToLower(name) == "secrets.yaml" || strings.ToLower(name) == "secret.yaml"

		if !isTFVars && !isK8sSecrets {
			return nil
		}

		if isK8sSecrets {
			// The k8s filename convention is much more generic-sounding
			// than "terraform.tfvars" — confirm content actually looks
			// like a Secret manifest before flagging, to avoid a false
			// positive on an unrelated file that happens to share the name.
			confirmed, err := fileContainsSubstring(path, "kind: Secret")
			if err != nil || !confirmed {
				return nil
			}
		}

		f, err := buildIACFinding(cfg, path)
		if err != nil {
			return nil // unreadable file — skip it, don't fail the whole audit
		}
		findings = append(findings, f)
		return nil
	})
	return findings, err
}

func fileContainsSubstring(path, substr string) (bool, error) {
	file, err := openFile(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substr) {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func buildIACFinding(cfg Config, path string) (Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return Finding{}, err
	}
	defer file.Close()

	var prodMatch, ipMatch bool
	var publicIP string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if IsAlreadyMasked(strings.TrimSpace(line)) {
			continue
		}
		if IsProductionIndicator(line) {
			prodMatch = true
		}
		if ip, ok := MatchPublicIP(line); ok && !ipMatch {
			ipMatch = true
			publicIP = ip
		}
	}
	if err := scanner.Err(); err != nil {
		return Finding{}, err
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypeIACVariableFile
	f.FilePath = path
	f.Confidence = ConfidenceMedium
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
	default:
		f.Severity = SeverityInfo
		f.Evidence = "infrastructure-as-code variable file — detection only, no automated fix yet"
	}

	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return f, nil
}
