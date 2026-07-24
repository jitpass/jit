// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// sopsAgeKeyPrefix marks an age secret key line in keys.txt. Everything
// else in the file (comment lines carrying the public key and creation
// date) is non-secret and survives in the template verbatim, the npmrc
// registry-line treatment.
const sopsAgeKeyPrefix = "AGE-SECRET-KEY-1"

const sopsAgeVarName = "SOPS_AGE_KEY"

// SOPSAgeMigration describes what jit migrate did to an age key file.
type SOPSAgeMigration struct {
	FilePath     string
	BackupPath   string
	TemplatePath string
	ProfileName  string
	ProfilePath  string
	// NamespaceMovedFrom mirrors GCPADCMigration's field of the same name:
	// the profile name this file would have used had the vault not already
	// held another migration's secret there (GAPS.md #55).
	NamespaceMovedFrom string
}

// SOPSAgeKeyPaths returns the locations sops actually reads a default age
// key file from on macOS, in sops's own resolution order: the platform
// config dir (Application Support — what sops uses when XDG_CONFIG_HOME is
// unset, the common case on a Mac) and the XDG convention path many
// developers create anyway because every Linux tutorial names it. Both are
// candidates because which one a machine uses depends on env vars a
// discovery pass can't see — and unlike ADC there is no "the" fixed path.
// Keep in sync with audit's ageKeyRelativePaths.
func SOPSAgeKeyPaths(home string) []string {
	return []string{
		filepath.Join(home, "Library", "Application Support", "sops", "age", "keys.txt"),
		filepath.Join(home, ".config", "sops", "age", "keys.txt"),
	}
}

// locateSOPSAgeSecret is the single extraction path DiscoverSOPSAge and
// ApplySOPSAge share (the locateGCPADCSecrets discipline: Discover treats
// any error as "not migratable", Apply as fail-loud, so Apply's error path
// is unreachable through the CLI). It finds the file's single age secret
// key and returns the placeholder-substituted template plus the key bytes.
//
// Exactly one key, by design: a multi-key file can't round-trip through
// one SOPS_AGE_KEY variable without inventing a numbering scheme the env
// injection side (sops's own SOPS_AGE_KEY env var) has no analog for, so
// per the tfvars convention it is skipped with the audit finding left
// standing — reported, never half-migrated.
func locateSOPSAgeSecret(data []byte) (template []byte, key []byte, err error) {
	placeholder := "${" + sopsAgeVarName + "}"
	// FormatTemplate is position-blind byte substitution: pre-existing
	// placeholder text anywhere in the file would get the real key written
	// into it at serve time.
	if bytes.Contains(data, []byte(placeholder)) {
		return nil, nil, fmt.Errorf("file already contains the literal %s", placeholder)
	}

	var keys [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if !bytes.HasPrefix(trimmed, []byte(sopsAgeKeyPrefix)) {
			continue
		}
		// An age key is a single bech32 token; interior whitespace means a
		// format this extraction doesn't understand (a trailing comment, a
		// mangled line) — refuse rather than vault half a line.
		if bytes.ContainsAny(trimmed, " \t") {
			return nil, nil, fmt.Errorf("age key line has interior whitespace")
		}
		keys = append(keys, trimmed)
	}
	switch len(keys) {
	case 0:
		return nil, nil, fmt.Errorf("no %s line to migrate", sopsAgeKeyPrefix)
	case 1:
	default:
		return nil, nil, fmt.Errorf("%d age keys in one file; one SOPS_AGE_KEY variable can't serve them", len(keys))
	}
	key = append([]byte(nil), keys[0]...)

	// The key token must locate uniquely in the raw bytes for the byte
	// substitution to provably land on the right span — the same "the
	// pattern found what the parse saw" validation locateGCPADCSecrets
	// does, trivial here because the token is its own unique needle.
	if bytes.Count(data, key) != 1 {
		return nil, nil, fmt.Errorf("age key bytes appear more than once in the file")
	}
	idx := bytes.Index(data, key)
	var buf []byte
	buf = append(buf, data[:idx]...)
	buf = append(buf, placeholder...)
	buf = append(buf, data[idx+len(key):]...)
	template = buf

	if bytes.Contains(template, []byte(sopsAgeKeyPrefix)) {
		return nil, nil, fmt.Errorf("template still contains an age secret key after substitution")
	}
	return template, key, nil
}

// DiscoverSOPSAge returns the age key files this migration can safely
// convert — zero, one, or (a machine that somehow populated both standard
// locations) two paths. Each is its own migration unit; claimNamespace
// hands the second one "sops-age-2" without any precedence logic here. A
// file audit flags but this returns nothing for (locate refused it: no
// key, multiple keys) simply stays an audit finding — reported, never
// half-migrated.
func DiscoverSOPSAge(home string) ([]string, error) {
	var found []string
	for _, path := range SOPSAgeKeyPaths(home) {
		// Same guard as DiscoverGCPADC: a file already converted to a FIFO
		// by an earlier migration must never be opened for read here —
		// opening a FIFO for read blocks until a writer (jit agent)
		// connects, which would hang this scan forever on a machine with
		// no agent running.
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path) // #nosec G304 -- fixed sops config paths, not external input
		if err != nil {
			return nil, err
		}
		if _, _, lerr := locateSOPSAgeSecret(data); lerr != nil {
			continue // nothing this migration can safely convert
		}
		found = append(found, path)
	}
	return found, nil
}

// ApplySOPSAge moves the age key file's secret line into v's vault and
// replaces the file with a FIFO serving a template-substituted
// reconstruction (mount.FormatTemplate) — the ApplyGCPADC shape: a file
// mixing secret and non-secret content, where only the key line is filled
// in from the vault at serve time. home roots the "sops-age" profile in
// the home-rooted store, since keys.txt is a machine singleton with no
// project directory to root a profile in.
//
// The vault leaf equals the manifest key (SOPS_AGE_KEY both sides), the
// re-run idempotency rule tfvars established: claimNamespace counts a
// vault path as this migration's own only when the existing manifest maps
// the variable to that exact path, so anything else forks "sops-age-2"
// instead of overwriting a stranger's secret.
//
// SOPS_AGE_KEY is deliberately also sops's own env var: `jit run --profile
// sops-age -- kluctl deploy` serves the key straight through the
// environment (sops prefers the env var over the key file), so the FIFO
// mount and env injection are two paths to the same secret, not two
// mechanisms to keep in sync.
func ApplySOPSAge(v *vault.Vault, home, path string) (SOPSAgeMigration, error) {
	// Same reason as DiscoverSOPSAge's guard, on Apply's own read: a path
	// that became a FIFO since discovery must fail loud here, not block
	// forever inside os.ReadFile waiting for a writer.
	info, err := os.Lstat(path)
	if err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("checking %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return SOPSAgeMigration{}, fmt.Errorf("%s is not a regular file (already a live mount?)", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed sops config paths, not external input
	if err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}
	template, key, err := locateSOPSAgeSecret(data)
	if err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("%s: %v, refusing to half-migrate", path, err)
	}

	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, home, "sops-age", []string{sopsAgeVarName})
	if err != nil {
		return SOPSAgeMigration{}, err
	}

	meta, err := newProvenance(vault.ClassSOPS, path)
	if err != nil {
		return SOPSAgeMigration{}, err
	}
	secretPath := profileName + "/" + sopsAgeVarName
	if err := v.SetWithMeta(secretPath, key, meta); err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("storing %s in vault: %w", sopsAgeVarName, err)
	}
	entries[sopsAgeVarName] = secretPath

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".keys.txt.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil { // #nosec G703 -- templatePath is internally derived (claimNamespace's hardcoded "sops-age" namespace + a fixed suffix), not user-controlled path input
		return SOPSAgeMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return SOPSAgeMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return SOPSAgeMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		NamespaceMovedFrom: movedFrom,
	}, nil
}
