// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// awsCredentialKeys are the fields ApplyAWSProfile moves into the vault —
// the AWS CLI's own static-credential trio (access key, secret key, and
// an optional temporary session token).
var awsCredentialKeys = []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}

// AWSCredentialMigration describes what jit migrate did to one AWS CLI
// profile.
type AWSCredentialMigration struct {
	ProfileName       string // the AWS profile name, e.g. "default" or "prod"
	CredentialsPath   string
	CredentialsBackup string
	ConfigPath        string
	ConfigBackup      string
	VaultProfileName  string // "aws-<ProfileName>"
	VaultProfilePath  string
	Variables         []string
}

// AWSCredentialsPath returns ~/.aws/credentials.
func AWSCredentialsPath(home string) string {
	return filepath.Join(home, ".aws", "credentials")
}

// AWSConfigPath returns ~/.aws/config.
func AWSConfigPath(home string) string {
	return filepath.Join(home, ".aws", "config")
}

// DiscoverAWSProfiles returns every profile name in ~/.aws/credentials
// that has an aws_secret_access_key set (mirroring
// audit.ScanCredentialFiles' own detection) and so has something for
// ApplyAWSProfile to migrate. Sorted for determinism.
func DiscoverAWSProfiles(home string) ([]string, error) {
	_, sections, err := parseINILines(AWSCredentialsPath(home))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for name, kv := range sections {
		if kv["aws_secret_access_key"] != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// ApplyAWSProfile moves profileName's static credentials out of
// ~/.aws/credentials and into v's vault, under a home-rooted global
// profile (profile.GlobalRoot) named "aws-<profileName>" — the AWS
// CLI/SDK invokes credential_process from whatever directory the calling
// command happens to run in, not any particular jit project directory,
// so the profile has to resolve independent of cwd the same way
// shell-config/MCP profiles do.
//
// Rewrites ~/.aws/config to add (or update) a credential_process line
// under the correct section for profileName — "[default]" for AWS's own
// irregular special case, "[profile <name>]" for every other named
// profile; getting this wrong silently produces a config the AWS CLI
// never applies. Both ~/.aws/credentials and ~/.aws/config are backed up
// first (backupFile), and only the three known credential keys are
// removed from the credentials file's target section — its section
// header and any other content (comments, other profiles) are left
// exactly as they were, even if the section becomes otherwise empty.
//
// dedup, if non-nil, makes a multi-profile run back up the shared
// ~/.aws/credentials (and ~/.aws/config) exactly once — the pristine
// pre-run state — instead of once per profile (each capturing the file
// already stripped of the earlier profiles). See BackupTracker (GAPS.md
// #65); the CLI passes one tracker shared across every profile in the run.
func ApplyAWSProfile(v *vault.Vault, home, profileName string, dedup ...*BackupTracker) (AWSCredentialMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}
	credPath := AWSCredentialsPath(home)
	credLines, sections, err := parseINILines(credPath)
	if err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("reading %s: %w", credPath, err)
	}
	kv := sections[profileName]
	if kv == nil || kv["aws_secret_access_key"] == "" {
		return AWSCredentialMigration{}, fmt.Errorf("profile %q not found (or has no aws_secret_access_key) in %s", profileName, credPath)
	}

	vaultProfileName := "aws-" + profileName
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("resolving global profile root: %w", err)
	}
	vaultProfilePath, err := profile.Path(globalRoot, vaultProfileName)
	if err != nil {
		return AWSCredentialMigration{}, err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(vaultProfilePath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return AWSCredentialMigration{}, fmt.Errorf("loading existing profile %s: %w", vaultProfilePath, lerr)
	}

	varByINIKey := map[string]string{
		"aws_access_key_id":     "ACCESS_KEY_ID",
		"aws_secret_access_key": "SECRET_ACCESS_KEY",
		"aws_session_token":     "SESSION_TOKEN",
	}
	var varNames []string
	for _, iniKey := range awsCredentialKeys {
		val, ok := kv[iniKey]
		if !ok || val == "" {
			continue
		}
		varName := varByINIKey[iniKey]
		secretPath := vaultProfileName + "/" + varName
		if err := v.Set(secretPath, []byte(val)); err != nil {
			return AWSCredentialMigration{}, fmt.Errorf("storing %s in vault: %w", varName, err)
		}
		entries[varName] = secretPath
		varNames = append(varNames, varName)
	}
	sort.Strings(varNames)

	if err := writeProfileManifest(vaultProfilePath, entries); err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("writing profile %s: %w", vaultProfilePath, err)
	}

	credBackup, err := tracker.backupOnce(v, credPath)
	if err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("backing up %s: %w", credPath, err)
	}

	configPath := AWSConfigPath(home)
	// Config may not exist yet (a credentials-only setup, e.g. a fresh
	// AWS CLI install that's never run `aws configure`) — that's fine,
	// upsertINISection creates it.
	configLines, _, err := parseINILines(configPath)
	if err != nil && !os.IsNotExist(err) {
		return AWSCredentialMigration{}, fmt.Errorf("reading %s: %w", configPath, err)
	}
	// configHandled: an earlier profile in this run already backed up
	// ~/.aws/config or recorded it created — this profile must do neither
	// again (a second backup would win over that first profile's
	// RemoveOnRestore record and leave the jit-written config behind; a
	// second created-record is redundant). It still upserts its own
	// credential_process section below either way.
	configHandled := tracker.alreadyHandled(configPath)
	var configBackup string
	_, configStatErr := os.Stat(configPath)
	configExisted := configStatErr == nil
	if configExisted && !configHandled {
		configBackup, err = tracker.backupOnce(v, configPath)
		if err != nil {
			return AWSCredentialMigration{}, fmt.Errorf("backing up %s: %w", configPath, err)
		}
	}

	jitPath, err := resolveJitExecutable()
	if err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	// vaultProfileName is already constrained to a safe charset upstream —
	// v.Set above ran it through the vault's secret-path sanitizer (letters,
	// digits, '.', '_', '-', '/' only), so an AWS profile name carrying a
	// whitespace/quote/']' character makes migration fail before reaching
	// here. Quote it anyway, exactly like jitPath, so this line's safety
	// never silently depends on that upstream ordering staying put.
	// (credential_process is shlex-split by botocore with no shell, so the
	// quoting is for correct tokenization, not shell-metacharacter defense.)
	command := fmt.Sprintf("%s aws-credential-process --profile %s", quoteIfNeeded(jitPath), quoteIfNeeded(vaultProfileName))

	newConfigLines := upsertINIValue(configLines, awsConfigSectionName(profileName), "credential_process", command)
	if err := os.WriteFile(configPath, []byte(strings.Join(newConfigLines, "\n")), 0o600); err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("writing %s: %w", configPath, err)
	}
	// ~/.aws/config didn't exist before this run — migrate just created it to
	// hold the credential_process line. Record it so `jit migrate undo`
	// removes the jit-created file instead of leaving a dangling
	// credential_process pointing at a vault profile (an existing config, by
	// contrast, was backed up above and gets its exact original bytes back).
	if !configExisted && !configHandled {
		absConfig, err := filepath.Abs(configPath)
		if err != nil {
			return AWSCredentialMigration{}, fmt.Errorf("resolving %s: %w", configPath, err)
		}
		if err := RecordCreatedFile(v.Root, absConfig); err != nil {
			return AWSCredentialMigration{}, fmt.Errorf("recording created %s in the undo index: %w", configPath, err)
		}
		// Later profiles in this run share this now-created config: they must
		// not back it up (that backup would win over this RemoveOnRestore
		// record) or record it created a second time.
		tracker.markCreated(configPath)
	}

	newCredLines := removeINIKeys(credLines, profileName, awsCredentialKeys)
	if err := os.WriteFile(credPath, []byte(strings.Join(newCredLines, "\n")), 0o600); err != nil {
		return AWSCredentialMigration{}, fmt.Errorf("writing %s: %w", credPath, err)
	}

	return AWSCredentialMigration{
		ProfileName:       profileName,
		CredentialsPath:   credPath,
		CredentialsBackup: credBackup,
		ConfigPath:        configPath,
		ConfigBackup:      configBackup,
		VaultProfileName:  vaultProfileName,
		VaultProfilePath:  vaultProfilePath,
		Variables:         varNames,
	}, nil
}

// awsConfigSectionName maps a logical AWS profile name to its section
// header text in ~/.aws/config — AWS's own irregular convention: the
// default profile is "[default]", but every other named profile is
// "[profile <name>]", unlike ~/.aws/credentials where every profile
// (including default) is just "[<name>]".
func awsConfigSectionName(profileName string) string {
	if profileName == "default" {
		return "default"
	}
	return "profile " + profileName
}

// parseINILines reads path and returns both its raw lines (for a
// caller that needs to surgically edit specific lines while preserving
// everything else — comments, formatting, sections it doesn't
// understand) and a parsed sections map (section name -> key -> value).
// A minimal hand-rolled parser scoped to exactly what AWS's INI-style
// files need, mirroring internal/audit/credfile.go's own precedent
// rather than pulling in a dependency (TECH_STACK.md §0).
func parseINILines(path string) (lines []string, sections map[string]map[string]string, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.aws/{credentials,config} path, not external input
	if err != nil {
		return nil, nil, err
	}
	lines = strings.Split(string(data), "\n")
	sections = map[string]map[string]string{}
	current := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			current = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if sections[current] == nil {
				sections[current] = map[string]string{}
			}
			continue
		}
		if current == "" {
			continue
		}
		idx := strings.Index(trimmed, "=")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		val := strings.TrimSpace(trimmed[idx+1:])
		sections[current][key] = val
	}
	return lines, sections, nil
}

// removeINIKeys drops any line inside section whose key (case-insensitive)
// is in keys, leaving the section header and every other line —
// including comments and keys it doesn't recognize — untouched.
func removeINIKeys(lines []string, section string, keys []string) []string {
	drop := make(map[string]bool, len(keys))
	for _, k := range keys {
		drop[strings.ToLower(k)] = true
	}

	out := make([]string, 0, len(lines))
	current := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			current = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			out = append(out, line)
			continue
		}
		if current == section {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
				if drop[key] {
					continue
				}
			}
		}
		out = append(out, line)
	}
	return out
}

// upsertINIValue sets key=value inside section, updating an existing line
// for key if one exists (preserving its position), appending a new line
// at the end of the section if the section exists but key doesn't, or
// appending an entirely new section at the end of the file if section
// doesn't exist yet.
func upsertINIValue(lines []string, section, key, value string) []string {
	newLine := key + " = " + value
	out := make([]string, 0, len(lines)+2)
	current := ""
	sectionSeen := false
	written := false

	flushIfLeavingTarget := func(nextSection string) {
		if current == section && sectionSeen && !written {
			out = append(out, newLine)
			written = true
		}
		current = nextSection
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			flushIfLeavingTarget(name)
			if current == section {
				sectionSeen = true
			}
			out = append(out, line)
			continue
		}
		if current == section {
			if idx := strings.Index(trimmed, "="); idx >= 0 {
				k := strings.TrimSpace(trimmed[:idx])
				if strings.EqualFold(k, key) {
					if !written {
						out = append(out, newLine)
						written = true
					}
					continue // drop the old value line, replaced above
				}
			}
		}
		out = append(out, line)
	}
	flushIfLeavingTarget("") // handles the target section being the last one in the file

	if !sectionSeen {
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "["+section+"]", newLine)
	}
	return out
}

// quoteIfNeeded wraps s in double quotes if it contains whitespace —
// credential_process's value is parsed with shell-like tokenization
// (botocore's documented behavior), so an unquoted path containing a
// space (e.g. jit installed under a directory with one) would otherwise
// be split into multiple tokens.
func quoteIfNeeded(s string) string {
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
