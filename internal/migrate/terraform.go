// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Terraform Cloud migration (GAPS.md #16, RFC.md Pillar III Tier 2, same
// shape as AWS's credential_process): `terraform login` stores a plain
// API token in ~/.terraform.d/credentials.tfrc.json. Terraform's own
// credentials-helper protocol is the native hook: a `credentials_helper
// "jit"` block in ~/.terraformrc plus an executable named
// terraform-credentials-jit in ~/.terraform.d/plugins makes terraform
// ask jit for the token instead of reading a file — and Terraform
// consults the helper only for hosts with no static credentials block,
// so removing the token from credentials.tfrc.json is what activates it.

// terraformHelperName is the <name> in `credentials_helper "<name>"` and
// the terraform-credentials-<name> executable filename — Terraform's own
// naming convention ties the two together.
const terraformHelperName = "jit"

// terraformProfilePrefix namespaces the global vault profile for a host:
// "terraform-app.terraform.io" — dots are legal in both profile names and
// vault paths, so the hostname is used verbatim.
const terraformProfilePrefix = "terraform-"

// TerraformMigration describes what jit migrate did to one Terraform
// Cloud/Enterprise host's stored token.
type TerraformMigration struct {
	Host              string
	CredentialsPath   string
	CredentialsBackup string
	RCPath            string
	RCBackup          string // "" when ~/.terraformrc didn't exist before this run
	HelperPath        string
	VaultProfileName  string // "terraform-<host>"
	VaultProfilePath  string
	Variables         []string
}

// TerraformCredentialsPath returns ~/.terraform.d/credentials.tfrc.json —
// where `terraform login` stores API tokens.
func TerraformCredentialsPath(home string) string {
	return filepath.Join(home, ".terraform.d", "credentials.tfrc.json")
}

// TerraformRCPath returns ~/.terraformrc, Terraform's CLI configuration
// file (the Unix location; Windows uses terraform.rc, out of scope with
// the rest of jit).
func TerraformRCPath(home string) string {
	return filepath.Join(home, ".terraformrc")
}

// TerraformHelperPath returns where the credentials-helper executable
// lives: Terraform searches ~/.terraform.d/plugins for a program named
// terraform-credentials-<name>.
func TerraformHelperPath(home string) string {
	return filepath.Join(home, ".terraform.d", "plugins", "terraform-credentials-"+terraformHelperName)
}

// tfrcCredentials is credentials.tfrc.json's shape, decoded generically
// (json.RawMessage at both levels) so rewriting one host's entry
// preserves any other top-level key or per-host field byte-for-byte —
// the same "preserve everything you don't understand" discipline
// kubeconfig.go's generic-map YAML editing follows.
type tfrcCredentials struct {
	raw   map[string]json.RawMessage
	hosts map[string]json.RawMessage
}

type tfrcHostCredential struct {
	Token string `json:"token"`
}

// errTerraformCredsMalformed marks a credentials.tfrc.json jit can't
// parse — distinguished from a read error so DiscoverTerraformHosts can
// skip it (nothing parseable means nothing safely rewritable) while
// still propagating genuine I/O failures.
var errTerraformCredsMalformed = errors.New("malformed credentials.tfrc.json")

func parseTerraformCredentials(path string) (*tfrcCredentials, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.terraform.d path, not external input
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", errTerraformCredsMalformed, path, err)
	}
	hosts := map[string]json.RawMessage{}
	if credsRaw, ok := raw["credentials"]; ok {
		if err := json.Unmarshal(credsRaw, &hosts); err != nil {
			return nil, fmt.Errorf("%w: %s: credentials: %v", errTerraformCredsMalformed, path, err)
		}
	}
	return &tfrcCredentials{raw: raw, hosts: hosts}, nil
}

func (c *tfrcCredentials) token(host string) string {
	hostRaw, ok := c.hosts[host]
	if !ok {
		return ""
	}
	var cred tfrcHostCredential
	if err := json.Unmarshal(hostRaw, &cred); err != nil {
		return ""
	}
	return cred.Token
}

// marshalWithout re-encodes the file with host's entry removed and every
// other key untouched.
func (c *tfrcCredentials) marshalWithout(host string) ([]byte, error) {
	hosts := make(map[string]json.RawMessage, len(c.hosts))
	for h, raw := range c.hosts {
		if h != host {
			hosts[h] = raw
		}
	}
	hostsRaw, err := marshalJSONNoEscape(hosts, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]json.RawMessage, len(c.raw))
	for k, v := range c.raw {
		out[k] = v
	}
	out["credentials"] = hostsRaw
	return marshalJSONNoEscape(out, "  ")
}

// DiscoverTerraformHosts returns every hostname in
// ~/.terraform.d/credentials.tfrc.json with a non-empty token (mirroring
// audit.scanTerraformCloud's detection), sorted for determinism. A
// missing or unparseable file yields nothing rather than an error — a
// file jit can't parse is also one it could never safely rewrite, so
// there's genuinely nothing to offer (same reasoning as audit's own
// malformed-file tolerance), and one bad file must not kill a whole
// `jit migrate home` sweep.
func DiscoverTerraformHosts(home string) ([]string, error) {
	creds, err := parseTerraformCredentials(TerraformCredentialsPath(home))
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, errTerraformCredsMalformed) {
			return nil, nil
		}
		return nil, err
	}
	var hosts []string
	for host := range creds.hosts {
		if creds.token(host) != "" {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts, nil
}

// terraformHelperPattern finds an existing credentials_helper block in
// ~/.terraformrc — Terraform allows at most one, so a helper that isn't
// jit's is a hard conflict, never something to silently replace (it's
// the user's own deliberate configuration).
var terraformHelperPattern = regexp.MustCompile(`(?m)^\s*credentials_helper\s+"([^"]+)"`)

// checkTerraformRCConflict inspects ~/.terraformrc before anything is
// mutated: returns the error to fail with if a NON-jit credentials
// helper is already configured, and whether jit's own block is already
// present (a re-run — idempotent, nothing to add).
func checkTerraformRCConflict(rcPath string) (alreadyInstalled bool, err error) {
	data, err := os.ReadFile(rcPath) // #nosec G304 -- fixed ~/.terraformrc path, not external input
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", rcPath, err)
	}
	m := terraformHelperPattern.FindSubmatch(data)
	if m == nil {
		return false, nil
	}
	if string(m[1]) == terraformHelperName {
		return true, nil
	}
	return false, fmt.Errorf("%s already configures credentials_helper %q, Terraform allows only one helper, so jit won't replace it; remove that block first if you want jit to manage these tokens", rcPath, string(m[1]))
}

// upsertTerraformProfile merges TOKEN -> its vault path into host's
// global profile manifest, preserving any existing entries — the same
// merge-not-overwrite discipline every other Apply* here follows.
// Returns the profile name, manifest path, and secret path used.
func upsertTerraformProfile(v *vault.Vault, host string, token []byte) (name, manifestPath, secretPath string, err error) {
	name = terraformProfilePrefix + host
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return "", "", "", fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err = profile.Path(globalRoot, name)
	if err != nil {
		return "", "", "", err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(manifestPath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet — start fresh
	default:
		return "", "", "", fmt.Errorf("loading existing profile %s: %w", manifestPath, lerr)
	}

	secretPath = name + "/TOKEN"
	if err := v.Set(secretPath, token); err != nil {
		return "", "", "", fmt.Errorf("storing token in vault: %w", err)
	}
	entries["TOKEN"] = secretPath
	if err := writeProfileManifest(manifestPath, entries, nil); err != nil {
		return "", "", "", fmt.Errorf("writing profile %s: %w", manifestPath, err)
	}
	return name, manifestPath, secretPath, nil
}

// ApplyTerraformHost moves host's API token out of
// ~/.terraform.d/credentials.tfrc.json and into v's vault under a
// home-rooted global profile ("terraform-<host>" — terraform invokes its
// credentials helper from whatever directory a run happens to use, so
// the profile must resolve independent of cwd, same as AWS/kubeconfig),
// writes the terraform-credentials-jit helper executable, adds the
// credentials_helper block to ~/.terraformrc, and rewrites the
// credentials file without that host's entry. Standard ordering: vault
// writes → profile manifest → backups → wiring → rewrite the source
// file; the conflict check (an existing non-jit helper) happens before
// any of it, so a run that can't complete never half-mutates.
//
// dedup, if non-nil, makes a run migrating several hosts from one
// credentials.tfrc.json back the shared credentials file (and
// ~/.terraformrc) up once — its pristine pre-run state — rather than once
// per host, so undo restores the original rather than the last, most-
// stripped snapshot. See BackupTracker (GAPS.md #65).
func ApplyTerraformHost(v *vault.Vault, home, host string, dedup ...*BackupTracker) (TerraformMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}
	credPath := TerraformCredentialsPath(home)
	creds, err := parseTerraformCredentials(credPath)
	if err != nil {
		return TerraformMigration{}, fmt.Errorf("reading %s: %w", credPath, err)
	}
	token := creds.token(host)
	if token == "" {
		return TerraformMigration{}, fmt.Errorf("host %q not found (or has no token) in %s", host, credPath)
	}

	rcPath := TerraformRCPath(home)
	helperInstalled, err := checkTerraformRCConflict(rcPath)
	if err != nil {
		return TerraformMigration{}, err
	}

	profileName, manifestPath, _, err := upsertTerraformProfile(v, host, []byte(token))
	if err != nil {
		return TerraformMigration{}, err
	}

	credBackup, err := tracker.backupOnce(v, credPath)
	if err != nil {
		return TerraformMigration{}, fmt.Errorf("backing up %s: %w", credPath, err)
	}
	// ~/.terraformrc is shared across every host in this run, and may not
	// exist yet (jit creates it below to hold the credentials_helper block).
	// Same discipline as ~/.aws/config: back it up once at its pristine state
	// if it existed; if jit creates it, record it for removal on undo. An
	// earlier host in this run that already handled it (rcHandled) does
	// neither again.
	rcHandled := tracker.alreadyHandled(rcPath)
	_, rcStatErr := os.Stat(rcPath)
	rcExisted := rcStatErr == nil
	var rcBackup string
	if rcExisted && !rcHandled {
		rcBackup, err = tracker.backupOnce(v, rcPath)
		if err != nil {
			return TerraformMigration{}, fmt.Errorf("backing up %s: %w", rcPath, err)
		}
	}

	helperPath, err := writeTerraformHelper(home)
	if err != nil {
		return TerraformMigration{}, err
	}
	if !helperInstalled {
		if err := appendTerraformHelperBlock(rcPath); err != nil {
			return TerraformMigration{}, err
		}
	}
	if !rcExisted && !rcHandled {
		absRC, err := filepath.Abs(rcPath)
		if err != nil {
			return TerraformMigration{}, fmt.Errorf("resolving %s: %w", rcPath, err)
		}
		if err := RecordCreatedFile(v.Root, absRC); err != nil {
			return TerraformMigration{}, fmt.Errorf("recording created %s in the undo index: %w", rcPath, err)
		}
		tracker.markCreated(rcPath)
	}

	rewritten, err := creds.marshalWithout(host)
	if err != nil {
		return TerraformMigration{}, fmt.Errorf("re-encoding %s: %w", credPath, err)
	}
	if err := os.WriteFile(credPath, append(rewritten, '\n'), 0o600); err != nil {
		return TerraformMigration{}, fmt.Errorf("writing %s: %w", credPath, err)
	}

	return TerraformMigration{
		Host:              host,
		CredentialsPath:   credPath,
		CredentialsBackup: credBackup,
		RCPath:            rcPath,
		RCBackup:          rcBackup,
		HelperPath:        helperPath,
		VaultProfileName:  profileName,
		VaultProfilePath:  manifestPath,
		Variables:         []string{"TOKEN"},
	}, nil
}

// writeTerraformHelper writes the terraform-credentials-jit executable —
// a two-line shell wrapper exec-ing this jit binary, since Terraform
// discovers helpers strictly by executable name and jit can't rename
// itself. The absolute path is baked in the same way the launchd plist's
// ProgramArguments bakes it (single-quoted, so a path with spaces or
// shell metacharacters survives). Overwrites unconditionally: the script
// is jit's own artifact, and a rebuilt/moved jit binary should refresh
// it on the next migrate rather than keep exec-ing a stale path.
func writeTerraformHelper(home string) (string, error) {
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return "", fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	helperPath := TerraformHelperPath(home)
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(helperPath), err)
	}
	script := fmt.Sprintf("#!/bin/sh\n# Written by jit migrate, Terraform credentials helper. See `jit terraform-credentials --help`.\nexec %s terraform-credentials \"$@\"\n", singleQuote(jitPath))
	if err := os.WriteFile(helperPath, []byte(script), 0o700); err != nil { // #nosec G306 -- must be executable; helper runs as this same user
		return "", fmt.Errorf("writing %s: %w", helperPath, err)
	}
	return helperPath, nil
}

// appendTerraformHelperBlock adds the credentials_helper block to
// ~/.terraformrc, creating the file if needed and preserving any existing
// content — callers must have already run checkTerraformRCConflict.
func appendTerraformHelperBlock(rcPath string) error {
	existing, err := os.ReadFile(rcPath) // #nosec G304 -- fixed ~/.terraformrc path, not external input
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", rcPath, err)
	}
	block := fmt.Sprintf("credentials_helper %q {\n  args = []\n}\n", terraformHelperName)
	content := string(existing)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if content != "" {
		content += "\n"
	}
	content += block
	if err := os.WriteFile(rcPath, []byte(content), 0o600); err != nil { // #nosec G703 -- fixed ~/.terraformrc path, not external input
		return fmt.Errorf("writing %s: %w", rcPath, err)
	}
	return nil
}

// StoreTerraformToken implements the helper protocol's "store" verb
// (`terraform login` after migration): the token goes into the vault and
// the host's global profile, exactly as ApplyTerraformHost would have
// put it — so a re-login keeps working through jit instead of landing a
// fresh plaintext token back in credentials.tfrc.json.
func StoreTerraformToken(v *vault.Vault, host, token string) error {
	if token == "" {
		return fmt.Errorf("empty token for host %q", host)
	}
	_, _, _, err := upsertTerraformProfile(v, host, []byte(token))
	return err
}

// ForgetTerraformToken implements the helper protocol's "forget" verb
// (`terraform logout`): removes the host's token from the vault and its
// profile manifest. Idempotent — forgetting a host that was never stored
// is a no-op, matching how terraform treats a logout with nothing saved.
func ForgetTerraformToken(v *vault.Vault, host string) error {
	name := terraformProfilePrefix + host
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err := profile.Path(globalRoot, name)
	if err != nil {
		return err
	}
	if err := v.Remove(name + "/TOKEN"); err != nil && !errors.Is(err, vault.ErrNotFound) {
		return err
	}
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// singleQuote wraps s in single quotes for safe splicing into a shell
// script, escaping any single quotes s itself contains ('\” — end the
// quoted string, emit a literal quote, reopen).
func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
