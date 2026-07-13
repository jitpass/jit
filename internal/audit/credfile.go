// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScanCredentialFiles implements RFC.md §4 category 3: known credential
// file formats, by system. Findings are per-field (RFC's own NDJSON example
// uses key_name "aws_secret_access_key" for this category), unlike .env's
// file-level granularity.
//
// Terraform Cloud and GCP application-default-credentials were added to the
// original RFC-named set (AWS, kubeconfig, npmrc) after real-world review
// (2026-07-06, see ROADMAP.md) showed both appearing repeatedly.
func ScanCredentialFiles(cfg Config) ([]Finding, error) {
	var all []Finding
	for _, scan := range []func(Config) ([]Finding, error){
		scanAWSCredentials,
		scanKubeconfig,
		scanNpmrc,
		scanTerraformCloud,
		scanGCPApplicationDefaultCredentials,
	} {
		findings, err := scan(cfg)
		if err != nil {
			return all, err
		}
		all = append(all, findings...)
	}
	return all, nil
}

// --- AWS credentials (~/.aws/credentials, INI format) ---

func scanAWSCredentials(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".aws", "credentials")
	file, err := openFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	sections, err := parseINISections(file)
	if err != nil {
		return nil, nil // malformed file — skip it, don't fail the whole audit
	}

	var findings []Finding
	for profile, kv := range sections {
		secret, ok := kv["aws_secret_access_key"]
		if !ok || secret == "" {
			continue
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      profile + "/aws_secret_access_key",
			RawValue:     secret,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("AWS secret access key found in profile %q", profile),
		}))
	}
	return findings, nil
}

// parseINISections is a minimal hand-rolled INI parser scoped to exactly
// what AWS's credentials file format needs — no nested sections, no
// multi-line values, no escaping. Not pulling in a dependency for this
// (TECH_STACK.md §0's dependency-minimalism principle) since the format is
// this simple.
func parseINISections(r *os.File) (map[string]map[string]string, error) {
	sections := map[string]map[string]string{}
	currentSection := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			if sections[currentSection] == nil {
				sections[currentSection] = map[string]string{}
			}
			continue
		}
		if currentSection == "" {
			continue
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		sections[currentSection][key] = value
	}
	return sections, scanner.Err()
}

// --- kubeconfig (~/.kube/config, YAML) ---

type kubeconfigFile struct {
	Users []struct {
		Name string                 `yaml:"name"`
		User map[string]interface{} `yaml:"user"`
	} `yaml:"users"`
}

func scanKubeconfig(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".kube", "config")
	file, err := openFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var kc kubeconfigFile
	if err := yaml.NewDecoder(file).Decode(&kc); err != nil {
		return nil, nil // malformed/empty YAML — skip, don't fail the whole audit
	}

	var findings []Finding
	for _, u := range kc.Users {
		for _, field := range []string{"token", "client-key-data"} {
			raw, ok := u.User[field]
			if !ok {
				continue
			}
			str, ok := raw.(string)
			if !ok || str == "" {
				continue
			}
			findings = append(findings, cfg.ValueFinding(ValueFindingParams{
				FindingType:  FindingTypeCredentialFile,
				FilePath:     path,
				KeyName:      fmt.Sprintf("%s/%s", u.Name, field),
				RawValue:     str,
				BaseSeverity: SeverityHigh,
				Confidence:   ConfidenceHigh,
				Evidence:     fmt.Sprintf("kubeconfig user %q has an embedded %s", u.Name, field),
			}))
		}
	}
	return findings, nil
}

// --- npmrc (~/.npmrc and any project-local .npmrc, key=value) ---

var npmrcLinePattern = regexp.MustCompile(`^\s*([^=\s]+)\s*=\s*(.*?)\s*$`)

func scanNpmrc(cfg Config) ([]Finding, error) {
	var findings []Finding

	globalPath := filepath.Join(cfg.HomeDir, ".npmrc")
	// Lstat + IsRegular, not a bare Stat: `jit migrate home` can turn the
	// global ~/.npmrc itself into a live template mount, and opening that
	// FIFO would block the scan with no agent writing (or read decoy
	// content and report jit's own protection as an exposed credential) —
	// the same guard walkHomeDir applies to every walked file, needed here
	// because this is a fixed path checked outside the walk.
	if info, statErr := os.Lstat(globalPath); statErr == nil && info.Mode().IsRegular() {
		f, err := scanNpmrcFile(globalPath, cfg)
		if err != nil {
			return nil, err
		}
		findings = append(findings, f...)
	}

	// Project-local .npmrc files can live anywhere — reuse the broad,
	// bounded walk (task #22) rather than only checking cwd.
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		if d.Name() != ".npmrc" || path == globalPath {
			return nil
		}
		f, ferr := scanNpmrcFile(path, cfg)
		if ferr != nil {
			return nil
		}
		findings = append(findings, f...)
		return nil
	})
	return findings, err
}

func scanNpmrcFile(path string, cfg Config) ([]Finding, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		m := npmrcLinePattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1]
		lowerKey := strings.ToLower(key)
		if !strings.Contains(lowerKey, "_authtoken") && !strings.Contains(lowerKey, "_password") {
			continue
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      key,
			RawValue:     unquote(m[2]),
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     "npm registry credential found in .npmrc",
		}))
	}
	return findings, scanner.Err()
}

// --- Terraform Cloud (~/.terraform.d/credentials.tfrc.json, JSON) ---

type tfcCredentialsFile struct {
	Credentials map[string]struct {
		Token string `json:"token"`
	} `json:"credentials"`
}

func scanTerraformCloud(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".terraform.d", "credentials.tfrc.json")
	file, err := openFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var tfc tfcCredentialsFile
	if err := json.NewDecoder(file).Decode(&tfc); err != nil {
		return nil, nil
	}

	var findings []Finding
	for host, cred := range tfc.Credentials {
		if cred.Token == "" {
			continue
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      host,
			RawValue:     cred.Token,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("Terraform Cloud API token found for host %q", host),
		}))
	}
	return findings, nil
}

// --- GCP application default credentials (~/.config/gcloud/..., JSON) ---

func scanGCPApplicationDefaultCredentials(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".config", "gcloud", "application_default_credentials.json")
	file, err := openFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var raw map[string]interface{}
	if err := json.NewDecoder(file).Decode(&raw); err != nil {
		return nil, nil
	}

	credType, _ := raw["type"].(string)

	// Check both shapes (service_account -> private_key, authorized_user ->
	// refresh_token) rather than branching strictly on the "type" field,
	// which keeps this working even if that field is missing/unexpected.
	for _, field := range []string{"private_key", "refresh_token"} {
		value, ok := raw[field].(string)
		if !ok || value == "" {
			continue
		}
		return []Finding{cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      field,
			RawValue:     value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("GCP application default credentials (%s) found", credType),
		})}, nil
	}
	return nil, nil
}
