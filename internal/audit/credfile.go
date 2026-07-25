// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
// (2026-07-06, see ROADMAP.md) showed both appearing repeatedly. Docker
// registry logins (~/.docker/config.json) joined for the same reason:
// `docker login` without a credential store keeps them base64-encoded in
// the file — encoding, not encryption, the same gap as a base64 Secret
// manifest.
func ScanCredentialFiles(cfg Config) ([]Finding, error) {
	fixed, err := scanKnownCredentialFiles(cfg)
	if err != nil {
		return fixed, err
	}
	walked, err := walkForCategory(cfg, classifyProjectNpmrc)
	// Same fixed-then-walked composition Scan performs, dedupe included, so
	// this standalone entry point and a machine-wide scan can't report a
	// different number of findings for the same home directory.
	return append(fixed, dropAlreadyReported(fixed, walked)...), err
}

// scanKnownCredentialFiles is this category's fixed half (see categories):
// every credential store that lives at one known path. The one part of the
// category that has to be discovered — a project-local .npmrc, which can sit
// anywhere — is classifyProjectNpmrc's job.
func scanKnownCredentialFiles(cfg Config) ([]Finding, error) {
	var all []Finding
	for _, scan := range []func(Config) ([]Finding, error){
		scanAWSCredentials,
		scanKubeconfig,
		scanGlobalNpmrc,
		scanTerraformCloud,
		scanDockerConfig,
		scanGitCredentials,
		scanGCPApplicationDefaultCredentials,
		scanNetrc,
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

	// Sorted, not raw map order: Go randomizes map iteration per run, so a
	// file with two profiles emitted its findings in a different order every
	// time — which made two NDJSON reports of an unchanged machine diff
	// dirty, for no reason but the map. Every scanner that iterates a parsed
	// map does this (see also scanTerraformCloud, scanDockerConfig,
	// scanMCPConfigFile); Scan's fixed category order is only half of a
	// deterministic report if the order within a category is a coin flip.
	var findings []Finding
	for _, profile := range slices.Sorted(maps.Keys(sections)) {
		kv := sections[profile]
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

func scanGlobalNpmrc(cfg Config) ([]Finding, error) {
	globalPath := filepath.Join(cfg.HomeDir, ".npmrc")
	// Lstat + IsRegular, not a bare Stat: `jit migrate home` can turn the
	// global ~/.npmrc itself into a live template mount, and opening that
	// FIFO would block the scan with no agent writing (or read decoy
	// content and report jit's own protection as an exposed credential) —
	// the same guard walkHomeDir applies to every walked file, needed here
	// because this is a fixed path checked outside the walk.
	info, err := os.Lstat(globalPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil
	}
	return scanNpmrcFile(globalPath, cfg)
}

// classifyProjectNpmrc is the credential category's discovery half: a .npmrc
// can live in any project, so it's found by the shared walk (task #22) rather
// than by only checking cwd.
//
// It deliberately does NOT skip the global ~/.npmrc that scanGlobalNpmrc also
// reads. A path check here looked like the obvious way to avoid double-
// reporting that one file, but it silently broke `jit scan <dir>`: a targeted
// scan runs no fixed half, so excluding the path meant the file was reported
// by nobody. Scan drops the duplicate at the seam instead — see
// dropAlreadyReported.
func classifyProjectNpmrc(cfg Config, path, name string) []Finding {
	if name != ".npmrc" {
		return nil
	}
	findings, err := scanNpmrcFile(path, cfg)
	if err != nil {
		return nil // unreadable file — skip it, don't fail the whole scan
	}
	return findings
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
	for _, host := range slices.Sorted(maps.Keys(tfc.Credentials)) { // sorted: see scanAWSCredentials
		cred := tfc.Credentials[host]
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

// --- Docker registry logins (~/.docker/config.json, JSON) ---

// dockerConfigFile decodes only the fields the scan needs; a registry
// entry left as {} (docker's own marker once a credential store holds the
// secret) has none of them and is skipped.
type dockerConfigFile struct {
	Auths map[string]struct {
		Auth          string `json:"auth"`
		Password      string `json:"password"`
		IdentityToken string `json:"identitytoken"`
	} `json:"auths"`
}

func scanDockerConfig(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".docker", "config.json")
	file, err := openFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var dc dockerConfigFile
	if err := json.NewDecoder(file).Decode(&dc); err != nil {
		return nil, nil // malformed file — skip it, don't fail the whole audit
	}

	var findings []Finding
	for _, registry := range slices.Sorted(maps.Keys(dc.Auths)) { // sorted: see scanAWSCredentials
		entry := dc.Auths[registry]
		// The secret is whichever of the three fields actually holds one:
		// an identity token, the password half of the base64 "user:pass"
		// auth value, or a rare literal password field.
		secret := entry.IdentityToken
		if secret == "" && entry.Auth != "" {
			if decoded, err := base64.StdEncoding.DecodeString(entry.Auth); err == nil {
				// The username can't contain ':' (the registry protocol
				// rejects it), so everything after the FIRST colon is the
				// password even when the password itself contains colons.
				if _, pass, found := strings.Cut(string(decoded), ":"); found {
					secret = pass
				}
			}
		}
		if secret == "" {
			secret = entry.Password
		}
		if secret == "" {
			continue
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      registry,
			RawValue:     secret,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("Docker registry credential found for %q (config.json's base64 auth is encoding, not encryption)", registry),
		}))
	}
	return findings, nil
}

// --- git HTTPS credentials (~/.git-credentials and the XDG twin) ---

// scanGitCredentials reports every plaintext login in git's `store` helper
// files. git keeps them as `https://user:pass@host` lines, one per host, in
// ~/.git-credentials (and ~/.config/git/credentials when XDG is in use) —
// plaintext, the same at-rest gap as a base64 docker auth. Detection mirrors
// internal/migrate.parseGitCredentialsFile, so `jit scan` reports exactly
// the credentials `jit migrate --only git` (and `jit wrap git`) will convert.
func scanGitCredentials(cfg Config) ([]Finding, error) {
	var findings []Finding
	for _, path := range []string{
		filepath.Join(cfg.HomeDir, ".git-credentials"),
		filepath.Join(cfg.HomeDir, ".config", "git", "credentials"),
	} {
		f, err := scanGitCredentialsFile(path, cfg)
		if err != nil {
			return findings, err
		}
		findings = append(findings, f...)
	}
	return findings, nil
}

func scanGitCredentialsFile(path string, cfg Config) ([]Finding, error) {
	// Lstat + IsRegular, the same defensive guard the other fixed-path
	// scanners use: never block on a FIFO or follow a symlink out of the
	// audited home for a path checked outside walkHomeDir's own filter.
	info, statErr := os.Lstat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, statErr
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed git-credentials path under the audited home, not external input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var findings []Finding
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, perr := url.Parse(line)
		if perr != nil || u.Host == "" || u.User == nil {
			continue
		}
		pw, ok := u.User.Password()
		if !ok || pw == "" {
			continue
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      u.Host,
			RawValue:     pw,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("git HTTPS credential found for host %q in plaintext; jit wrap git moves it into the vault and keeps git push/fetch over HTTPS working", u.Host),
		}))
	}
	return findings, nil
}

// --- GCP application default credentials (~/.config/gcloud/..., JSON) ---

func scanGCPApplicationDefaultCredentials(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".config", "gcloud", "application_default_credentials.json")
	// Lstat + IsRegular, not a bare open: `jit migrate home` can turn this
	// file itself into a live template mount, and opening that FIFO would
	// block the scan forever with no agent writing (or read decoy/real
	// mount content and report jit's own protection as an exposed
	// credential) — the same guard scanNpmrc applies to the global
	// ~/.npmrc, needed here because this is a fixed path checked outside
	// walkHomeDir's own filter.
	if info, statErr := os.Lstat(path); statErr != nil || !info.Mode().IsRegular() {
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, statErr
		}
		return nil, nil
	}
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

// --- netrc (~/.netrc, machine/login/password) ---

func scanNetrc(cfg Config) ([]Finding, error) {
	path := filepath.Join(cfg.HomeDir, ".netrc")
	// Lstat + IsRegular, the same FIFO guard scanNpmrc/scanGCP apply: `jit
	// migrate home` can turn ~/.netrc itself into a live template mount, and
	// reading that FIFO would block the scan with no agent writing (or read
	// decoy content and report jit's own protection as an exposed
	// credential). This is a fixed path checked outside walkHomeDir's own
	// filter, so it needs its own guard.
	info, statErr := os.Lstat(path)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil, nil
		}
		return nil, statErr
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.netrc path under the audited home, not external input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var findings []Finding
	for _, pw := range netrcPasswords(data) {
		machine := pw.machine
		if machine == "" {
			machine = "netrc"
		}
		findings = append(findings, cfg.ValueFinding(ValueFindingParams{
			FindingType:  FindingTypeCredentialFile,
			FilePath:     path,
			KeyName:      machine,
			RawValue:     pw.value,
			BaseSeverity: SeverityHigh,
			Confidence:   ConfidenceHigh,
			Evidence:     fmt.Sprintf("netrc password found for machine %q", machine),
		}))
	}
	return findings, nil
}

type netrcPassword struct {
	machine string
	value   string
}

// netrcPasswords extracts every `password <value>` with its machine
// context, mirroring internal/migrate/netrc.go's walkNetrcTokens grammar
// EXACTLY — machine/default context, login/account values skipped as
// usernames (not secrets), and macdef macro bodies skipped to their
// terminating blank line. That agreement is the point: `jit scan` must
// report precisely the passwords `jit migrate --only netrc` will convert,
// never a "password" word inside a curl/ftp macro script. Kept as audit's
// own copy (audit doesn't import internal/migrate) — the same
// mirror-with-cross-reference discipline scanNpmrc/scanShellConfig follow.
func netrcPasswords(data []byte) []netrcPassword {
	type tok struct {
		text     string
		start    int
		afterEnd int
	}
	var toks []tok
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
	for i, n := 0, len(data); i < n; {
		for i < n && isSpace(data[i]) {
			i++
		}
		if i >= n {
			break
		}
		s := i
		for i < n && !isSpace(data[i]) {
			i++
		}
		toks = append(toks, tok{text: string(data[s:i]), start: s, afterEnd: i})
	}

	// macdefBodyEnd mirrors internal/migrate/netrc.go's netrcMacdefBodyEnd:
	// from is just past the macro NAME token (still mid-declaration-line), so
	// the first newline ends the declaration and the body starts on the next
	// line; the body runs to the first blank line, or EOF.
	macdefBodyEnd := func(from int) int {
		declEnd := bytes.IndexByte(data[from:], '\n')
		if declEnd < 0 {
			return len(data)
		}
		j := from + declEnd + 1
		for j < len(data) {
			nl := bytes.IndexByte(data[j:], '\n')
			if nl < 0 {
				return len(data)
			}
			lineEnd := j + nl + 1
			if len(bytes.TrimSpace(data[j:lineEnd])) == 0 {
				return lineEnd
			}
			j = lineEnd
		}
		return len(data)
	}

	var out []netrcPassword
	machine := ""
	skipUntil := -1
	for k := 0; k < len(toks); k++ {
		t := toks[k]
		if t.start < skipUntil {
			continue
		}
		switch t.text {
		case "machine":
			if k+1 < len(toks) {
				machine = toks[k+1].text
				k++
			}
		case "default":
			machine = "default"
		case "login", "account":
			if k+1 < len(toks) {
				k++ // value is a username, not a secret — skip it
			}
		case "password":
			if k+1 < len(toks) {
				out = append(out, netrcPassword{machine: machine, value: toks[k+1].text})
				k++
			}
		case "macdef":
			if k+1 < len(toks) {
				skipUntil = macdefBodyEnd(toks[k+1].afterEnd)
				k++
			}
		}
	}
	return out
}
