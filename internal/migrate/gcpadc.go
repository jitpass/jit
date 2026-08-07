// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

// gcpADCSecretFields maps the ADC JSON fields this migration moves into
// the vault to their profile variable names and the byte pattern that
// locates each one in the raw file. Exactly the two fields
// audit.scanGCPApplicationDefaultCredentials flags: authorized_user's
// refresh_token (what `gcloud auth application-default login` writes) and
// service_account's private_key. Deliberately NOT client_secret — for the
// authorized_user shape it's gcloud's own installed-app OAuth client
// secret, a well-known public constant baked into every gcloud install
// (Google's own docs call installed-app client secrets non-confidential),
// so treating it as a vault secret would only inflate the migration
// without protecting anything. Everything else in the file (client_id,
// quota_project_id, type, ...) is likewise non-secret and stays in the
// template verbatim, the same way npmrc's registry= lines do.
//
// This is also why there is no credential_process-style rewrite here the
// way awscreds.go does for ~/.aws/config: GCP's only executable hook
// (external_account's credential_source.executable, AIP-4117) exists
// solely for workload identity federation — the executable must return an
// OIDC/SAML subject token for an STS exchange against a real workload
// identity pool, and every consuming process must opt in via
// GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES=1. Neither shape audit
// actually finds on disk (authorized_user, service_account) has any
// process hook at all, so the live template mount is the mechanism that
// keeps SDKs working transparently.
var gcpADCSecretFields = []struct {
	Field   string
	VarName string
	Pattern *regexp.Regexp
}{
	{"refresh_token", "REFRESH_TOKEN", gcpADCValuePattern("refresh_token")},
	{"private_key", "PRIVATE_KEY", gcpADCValuePattern("private_key")},
}

// gcpADCValuePattern matches field's key/value pair on the file's RAW
// bytes — the quoted key, then the complete JSON string literal that
// follows it, with group 1 being the value's contents between (not
// including) its quotes. `(?:[^"\\]|\\.)*` is the standard "JSON string
// body" fragment: any run of non-quote/non-backslash bytes or two-byte
// escape sequences, so an escaped `\"` inside the value can't end the
// match early — and, symmetrically, the pattern's own leading `"` can't
// match a `\"`-escaped quote inside some other value's string body.
func gcpADCValuePattern(field string) *regexp.Regexp {
	return regexp.MustCompile(`"` + field + `"\s*:\s*"((?:[^"\\]|\\.)*)"`)
}

// gcpADCSecret is one secret locateGCPADCSecrets extracted: its profile
// variable name and its RAW byte span from the file — the JSON string
// literal's contents, still escaped. See ApplyGCPADC's doc comment for
// why the escaped form (not the decoded value) is what the vault stores.
type gcpADCSecret struct {
	Field    string // the ADC JSON key, e.g. "refresh_token"
	VarName  string
	RawValue []byte
}

// GCPADCMigration describes what jit migrate did to the ADC file.
type GCPADCMigration struct {
	FilePath     string
	BackupPath   string
	TemplatePath string
	CredType     string // the file's "type" field, e.g. "authorized_user" or "service_account"
	ProfileName  string
	ProfilePath  string
	Variables    []string
	// NamespaceMovedFrom mirrors NpmrcMigration's field of the same name:
	// the profile name this file would have used had the vault not already
	// held another migration's secret there (GAPS.md #55).
	NamespaceMovedFrom string
}

// GCPADCPath returns the fixed location of GCP's application default
// credentials file — the one path every Google client library checks
// after $GOOGLE_APPLICATION_CREDENTIALS.
func GCPADCPath(home string) string {
	return filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
}

// locateGCPADCSecrets is the single extraction path DiscoverGCPADC and
// ApplyGCPADC share: parse data as an ADC file, find each present secret
// field's exact byte span, and return the placeholder-substituted
// template plus the extracted raw values. Discover treating any error as
// "not migratable" while Apply treats it as fail-loud is what makes
// Apply's own error path unreachable through the CLI — a file this
// function can't handle is never discovered in the first place, so a
// whole a home-wide `jit migrate ~` run can't abort mid-way (after earlier
// categories already mutated the machine) on a file only Apply turns out
// to choke on.
//
// The byte-level location is validated against the structure-aware parse
// before anything is trusted, because the two can disagree on adversarial
// or degenerate input and a silent disagreement here means the REAL
// secret stays behind in the plaintext template — the one failure a
// secrets tool must never let pass quietly:
//
//   - the vaulted span must decode (as a JSON string) to exactly the
//     value json.Unmarshal saw at the top level — catches a duplicate key
//     (Unmarshal keeps the last, the pattern finds the first) and a
//     matching key/value pair nested inside some earlier object;
//   - the finished template must re-parse with each migrated field's
//     top-level value now exactly its ${VAR} placeholder — a second,
//     independent proof the substitution landed on the real field;
//   - data must not already contain a ${VAR} literal anywhere: the mount
//     substitutes placeholders wherever they appear at serve time
//     (FormatTemplate is position-blind), so pre-existing placeholder text
//     in a non-secret field would get the real secret written into it.
func locateGCPADCSecrets(data []byte) (template []byte, secrets []gcpADCSecret, credType string, err error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, "", fmt.Errorf("not a JSON object: %w", err)
	}
	credType, _ = raw["type"].(string)

	template = data
	for _, sf := range gcpADCSecretFields {
		parsedValue, ok := raw[sf.Field].(string)
		if !ok || parsedValue == "" {
			continue
		}
		placeholder := "${" + sf.VarName + "}"
		if bytes.Contains(data, []byte(placeholder)) {
			return nil, nil, "", fmt.Errorf("file already contains the literal %s", placeholder)
		}
		m := sf.Pattern.FindSubmatchIndex(template)
		if m == nil {
			return nil, nil, "", fmt.Errorf("found a %q value when parsed but couldn't locate its bytes", sf.Field)
		}
		rawValue := append([]byte(nil), template[m[2]:m[3]]...)
		var decoded string
		if err := json.Unmarshal(append(append([]byte(`"`), rawValue...), '"'), &decoded); err != nil || decoded != parsedValue {
			return nil, nil, "", fmt.Errorf("the first %q byte span doesn't hold the file's top-level value (duplicate or nested key?)", sf.Field)
		}
		var buf []byte
		buf = append(buf, template[:m[2]]...)
		buf = append(buf, placeholder...)
		buf = append(buf, template[m[3]:]...)
		template = buf
		secrets = append(secrets, gcpADCSecret{Field: sf.Field, VarName: sf.VarName, RawValue: rawValue})
	}
	if len(secrets) == 0 {
		return nil, nil, "", fmt.Errorf("no refresh_token or private_key to migrate")
	}

	var reparsed map[string]interface{}
	if err := json.Unmarshal(template, &reparsed); err != nil {
		return nil, nil, "", fmt.Errorf("substituted template no longer parses: %w", err)
	}
	for _, s := range secrets {
		if got, _ := reparsed[s.Field].(string); got != "${"+s.VarName+"}" {
			return nil, nil, "", fmt.Errorf("template's top-level %q is not its placeholder after substitution", s.Field)
		}
	}
	return template, secrets, credType, nil
}

// DiscoverGCPADC returns a zero- or one-element slice: the ADC path when
// the file exists and locateGCPADCSecrets can fully handle it. A slice,
// not a bool, so the CLI's category table can treat this
// machine-singleton exactly like every multi-item category. A file audit
// flags but this returns nothing for (locate refused it) simply stays an
// audit finding — reported, never half-migrated.
func DiscoverGCPADC(home string) ([]string, error) {
	path := GCPADCPath(home)

	// Same guard as DiscoverNpmrcFiles: a file already converted to a FIFO
	// by an earlier migration must never be opened for read here — opening
	// a FIFO for read blocks until a writer (jit agent) connects, which
	// would hang this scan forever on a machine with no agent running.
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil
	}

	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.config/gcloud path, not external input
	if err != nil {
		return nil, err
	}
	if _, _, _, lerr := locateGCPADCSecrets(data); lerr != nil {
		return nil, nil // nothing this migration can safely convert
	}
	return []string{path}, nil
}

// ApplyGCPADC moves the ADC file's secret fields into v's vault and
// replaces the file with a FIFO serving a template-substituted
// reconstruction (mount.FormatTemplate), exactly the ApplyNpmrc shape: a
// file mixing secret and non-secret content, where only the secret
// values are filled in from the vault at serve time and every other byte
// passes through untouched. path is the discovered file (GCPADCPath —
// passed rather than re-derived so the caller's loop variable is the
// thing actually migrated); home roots the "gcp-adc" profile in the
// home-rooted store, since — like the global ~/.npmrc — the ADC file is a
// machine singleton with no project directory to root a profile in.
//
// The vault stores each secret's RAW byte span from the file — the JSON
// string literal's contents, still escaped — NOT the JSON-decoded value.
// This is load-bearing, not an oversight: FormatTemplate is byte-level
// substitution with no JSON awareness, so serving valid JSON requires the
// substituted value to be exactly what sat between the original quotes.
// Decoding would turn a service account private_key's `\n` escapes into
// real newlines and the served file into a JSON parse error. For
// authorized_user's refresh_token the two forms coincide (OAuth tokens
// carry no JSON-special characters), which is why the stored value is
// also directly usable via `jit run --profile gcp-adc` there; a
// PRIVATE_KEY read back through jit run/export keeps its literal \n
// pairs — acceptable, since the mount is the consumption path and the
// escaped form is what Google's own file format holds anyway.
func ApplyGCPADC(v *vault.Vault, home, path string) (GCPADCMigration, error) {
	// Same reason as DiscoverGCPADC's guard, on Apply's own read: a path
	// that became a FIFO since discovery (an already-migrated file reached
	// via a direct Apply call, or a concurrent second migrate) must fail
	// loud here, not block forever inside os.ReadFile waiting for a writer.
	info, err := os.Lstat(path)
	if err != nil {
		return GCPADCMigration{}, fmt.Errorf("checking %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return GCPADCMigration{}, fmt.Errorf("%s is not a regular file (already a live mount?)", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.config/gcloud path, not external input
	if err != nil {
		return GCPADCMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}
	template, secrets, credType, err := locateGCPADCSecrets(data)
	if err != nil {
		return GCPADCMigration{}, fmt.Errorf("%s: %v, refusing to half-migrate", path, err)
	}

	varNames := make([]string, 0, len(secrets))
	for _, s := range secrets {
		varNames = append(varNames, s.VarName)
	}
	sort.Strings(varNames)

	// Same merge-and-guard as ApplyNpmrc: home is the profilesRoot (the
	// ADC file is machine-global), and claimNamespace moves to "gcp-adc-2"
	// if the vault already holds another migration's value at one of these
	// paths (GAPS.md #55).
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, home, "gcp-adc", varNames)
	if err != nil {
		return GCPADCMigration{}, err
	}

	meta, err := newProvenance(vault.ClassGCP, path)
	if err != nil {
		return GCPADCMigration{}, err
	}
	for _, s := range secrets {
		secretPath := profileName + "/" + s.VarName
		if err := v.SetWithMeta(secretPath, s.RawValue, meta); err != nil {
			return GCPADCMigration{}, fmt.Errorf("storing %s in vault: %w", s.VarName, err)
		}
		entries[s.VarName] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return GCPADCMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return GCPADCMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}

	templatePath := strings.TrimSuffix(profilePath, ".yaml") + ".adc.json.tmpl"
	if err := os.WriteFile(templatePath, template, 0o600); err != nil { // #nosec G703 -- templatePath is internally derived (claimNamespace's hardcoded "gcp-adc" namespace + a fixed suffix), not user-controlled path input
		return GCPADCMigration{}, fmt.Errorf("writing template %s: %w", templatePath, err)
	}

	if err := mount.CreateFIFO(path); err != nil {
		return GCPADCMigration{}, fmt.Errorf("mounting %s: %w", path, err)
	}

	return GCPADCMigration{
		FilePath:           path,
		BackupPath:         backupPath,
		TemplatePath:       templatePath,
		CredType:           credType,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}
