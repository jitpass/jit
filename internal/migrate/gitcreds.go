// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Git HTTPS credential migration (same shape as Docker's and Terraform's
// credential-helper migrations): git's `store` helper writes each remote's
// username and password/token into ~/.git-credentials, one
// `https://user:pass@host` URL per line, in plaintext. Git's own
// credential-helper protocol is the native hook: an executable named
// git-credential-<name> on $PATH, selected by a `credential.helper = <name>`
// line in the git config, makes git (and everything that shells out to it,
// including `git push` over HTTPS, submodule fetches, and LFS) ask jit for
// the credential instead of reading the file.
//
// This file holds the parts that don't touch the git config: the wire
// protocol, the ~/.git-credentials parser, per-host vault profiles, and the
// store/erase verbs the serving command calls. Activating the helper in the
// git config (the credential.helper rewrite) is deliberately separate, since
// git's multi-helper semantics need their own handling.

// gitHelperName is the <name> in `credential.helper <name>` and the
// git-credential-<name> executable filename. Git's own naming convention
// ties the two together, like Docker's docker-credential-<name>.
const gitHelperName = "jit"

// gitProfilePrefix namespaces the global vault profile for a remote host:
// "git-github.com" for credentials git uses against github.com.
const gitProfilePrefix = "git-"

// GitCredential is one git credential context, matching the attributes git's
// credential protocol exchanges (git-credential(1), INPUT/OUTPUT FORMAT).
// jit keys on host alone (git's default, credential.useHttpPath=false, treats
// a whole host as one credential); Path is captured for display but does not
// affect the vault profile, the same host-level granularity Docker's registry
// keying uses.
type GitCredential struct {
	Protocol string
	Host     string
	Path     string
	Username string
	Password string
}

// ErrGitMultipleAccounts reports a host carrying more than one account in
// git's plaintext store — two GitHub logins (work and personal) being the
// ordinary case.
//
// jit's git support is host-level throughout: one vault profile per host
// ("git-<host>"), holding one USERNAME/PASSWORD pair, and a helper that
// answers per host. That model cannot represent two accounts, and the rewrite
// that follows a migration strips EVERY line for the host. So migrating such a
// host vaulted the first account and deleted the second — no vault copy, no
// mention in the plan, nothing but the encrypted whole-file backup standing
// between the user and a lost token.
//
// Refused rather than half-done. Supporting multiple accounts properly means
// per-account profiles and a helper that matches on the username git supplies,
// which is a feature, not something to infer inside a rewrite that is already
// deleting the evidence.
var ErrGitMultipleAccounts = errors.New("git host has multiple accounts, which jit's host-level credential model cannot represent")

// quoteAll renders names for an error message, keeping an empty username
// legible rather than printing a bare comma.
func quoteAll(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			out = append(out, "(no username)")
			continue
		}
		out = append(out, strconv.Quote(n))
	}
	return out
}

// ParseGitCredentialInput reads the key=value lines git writes to a helper's
// stdin, one per line, terminated by a blank line or EOF (git-credential(1)).
// A `url=` line is expanded into its components the way git itself does, so a
// helper invoked with either the split attributes or the compact url form
// behaves identically. Unknown keys are ignored, as the protocol requires.
func ParseGitCredentialInput(r io.Reader) (GitCredential, error) {
	var c GitCredential
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" { // blank line terminates the request
			break
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch key {
		case "protocol":
			c.Protocol = value
		case "host":
			c.Host = value
		case "path":
			c.Path = value
		case "username":
			c.Username = value
		case "password":
			c.Password = value
		case "url":
			if u, err := url.Parse(value); err == nil {
				if u.Scheme != "" {
					c.Protocol = u.Scheme
				}
				if u.Host != "" {
					c.Host = u.Host
				}
				if p := strings.TrimPrefix(u.Path, "/"); p != "" {
					c.Path = p
				}
				if u.User != nil {
					if name := u.User.Username(); name != "" {
						c.Username = name
					}
					if pw, ok := u.User.Password(); ok {
						c.Password = pw
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return GitCredential{}, err
	}
	return c, nil
}

// GitCredentialsPath returns ~/.git-credentials, where git's `store` helper
// keeps plaintext credentials. Git also honors ~/.config/git/credentials
// (the XDG path) and $HOME/.netrc; the XDG file is handled by DiscoverGit
// below, and .netrc is jit migrate's netrc category, not this one.
func GitCredentialsPath(home string) string {
	return filepath.Join(home, ".git-credentials")
}

// GitCredentialsXDGPath returns ~/.config/git/credentials, the XDG location
// git's `store` helper uses when XDG_CONFIG_HOME points there.
func GitCredentialsXDGPath(home string) string {
	return filepath.Join(home, ".config", "git", "credentials")
}

// GitHelperPath returns where the credential-helper executable lives. Git
// discovers helpers strictly by $PATH lookup of git-credential-<name>, so
// the script goes in jit's own shim directory, the one directory jit already
// keeps on PATH (~/.jit/shims, the same DockerHelperPath uses). Deliberately
// a shell script, not a symlink: wrap's shim dispatch only considers
// symlinks, so a script is invisible to it.
func GitHelperPath(home string) string {
	return filepath.Join(home, ".jit", "shims", "git-credential-"+gitHelperName)
}

// gitHostSanitizer collapses everything profile.Path's name pattern would
// reject into '-'.
var gitHostSanitizer = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// sanitizeGitHost maps a remote host to the stable name component both
// migration and the helper protocol derive independently: "github.com" stays
// "github.com", "ghe.example.com:8443" becomes "ghe.example.com-8443". Git
// passes the SAME host to a helper's get/store/erase that keys the stored
// credential, so both sides always agree without any host->profile index on
// disk. Returns "" when nothing survives.
func sanitizeGitHost(host string) string {
	s := gitHostSanitizer.ReplaceAllString(host, "-")
	return strings.Trim(s, "-")
}

// GitProfileName returns the global vault profile name for a remote host, or
// "" for a host that sanitizes to nothing (no such host can ever have been
// migrated).
func GitProfileName(host string) string {
	s := sanitizeGitHost(host)
	if s == "" {
		return ""
	}
	return gitProfilePrefix + s
}

// parseGitCredentialsFile reads a git-credentials store file into its
// credential entries. Each non-empty line is a URL of the form
// scheme://user:pass@host[/path]; a line that doesn't parse, or that carries
// no username/password, is skipped rather than failing the whole file (a
// stray comment or a malformed leftover must not block a migrate sweep).
func parseGitCredentialsFile(path string) ([]GitCredential, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.git-credentials path, not external input
	if err != nil {
		return nil, err
	}
	var creds []GitCredential
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil || u.Host == "" || u.User == nil {
			continue
		}
		pw, ok := u.User.Password()
		if !ok || pw == "" {
			continue
		}
		creds = append(creds, GitCredential{
			Protocol: u.Scheme,
			Host:     u.Host,
			Path:     strings.TrimPrefix(u.Path, "/"),
			Username: u.User.Username(),
			Password: pw,
		})
	}
	return creds, nil
}

// DiscoverGitCredentials returns every host with a plaintext credential in
// ~/.git-credentials or its XDG twin, deduplicated by host (host-level
// keying) and sorted for determinism. Missing files yield nothing rather
// than an error, so a home without git's plaintext store contributes nothing
// to a `jit migrate home` sweep (same tolerance as DiscoverDockerRegistries).
func DiscoverGitCredentials(home string) ([]GitCredential, error) {
	seen := map[string]GitCredential{}
	for _, path := range []string{GitCredentialsPath(home), GitCredentialsXDGPath(home)} {
		creds, err := parseGitCredentialsFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, c := range creds {
			if sanitizeGitHost(c.Host) == "" {
				continue
			}
			if _, ok := seen[c.Host]; !ok {
				seen[c.Host] = c
			}
		}
	}
	hosts := make([]GitCredential, 0, len(seen))
	for _, c := range seen {
		hosts = append(hosts, c)
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Host < hosts[j].Host })
	return hosts, nil
}

// upsertGitProfile merges USERNAME/PASSWORD -> their vault paths into the
// host's global profile manifest, preserving any existing entries, the same
// merge-not-overwrite discipline every other Apply/Store here follows.
// Returns the profile name and manifest path used.
func upsertGitProfile(v *vault.Vault, host, username, password string, meta vault.Meta) (name, manifestPath string, err error) {
	name = GitProfileName(host)
	if name == "" {
		return "", "", fmt.Errorf("host %q sanitizes to nothing usable as a profile name", host)
	}
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return "", "", fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err = profile.Path(globalRoot, name)
	if err != nil {
		return "", "", err
	}

	entries := profile.Profile{}
	switch existing, lerr := profile.LoadFile(manifestPath); {
	case lerr == nil:
		for k, v2 := range existing {
			entries[k] = v2
		}
	case errors.Is(lerr, os.ErrNotExist):
		// no existing profile yet, start fresh
	default:
		return "", "", fmt.Errorf("loading existing profile %s: %w", manifestPath, lerr)
	}

	for varName, value := range map[string]string{"USERNAME": username, "PASSWORD": password} {
		secretPath := name + "/" + varName
		if err := v.SetWithMeta(secretPath, []byte(value), meta); err != nil {
			return "", "", fmt.Errorf("storing %s in vault: %w", varName, err)
		}
		entries[varName] = secretPath
	}
	if err := writeProfileManifest(manifestPath, entries, nil); err != nil {
		return "", "", fmt.Errorf("writing profile %s: %w", manifestPath, err)
	}
	return name, manifestPath, nil
}

// StoreGitCredential implements the helper protocol's "store" verb (a
// `git push` that authenticated with a typed-in password after migration):
// the credential goes into the vault and the host's global profile, exactly
// as the migration would have put it, so it keeps working through jit instead
// of landing a fresh plaintext line back in ~/.git-credentials.
func StoreGitCredential(v *vault.Vault, c GitCredential) error {
	if c.Password == "" {
		return fmt.Errorf("empty password for host %q", c.Host)
	}
	// Live credential-helper "store" after migration: no store file to
	// point at, so class-only provenance (fresh group, no origin), the same
	// shape a re-migrated host keeps once it already exists in the vault.
	meta, err := newProvenance(vault.ClassGit, "")
	if err != nil {
		return err
	}
	_, _, err = upsertGitProfile(v, c.Host, c.Username, c.Password, meta)
	return err
}

// EraseGitCredential implements the helper protocol's "erase" verb (git
// erasing a rejected credential, or a manual `git credential-jit erase`):
// removes the host's credential from the vault and its profile manifest.
// Idempotent: erasing a host that was never stored is a no-op, matching how
// git treats an erase with nothing saved.
func EraseGitCredential(v *vault.Vault, host string) error {
	name := GitProfileName(host)
	if name == "" {
		return nil
	}
	globalRoot, err := profile.GlobalRoot()
	if err != nil {
		return fmt.Errorf("resolving global profile root: %w", err)
	}
	manifestPath, err := profile.Path(globalRoot, name)
	if err != nil {
		return err
	}
	for _, varName := range []string{"USERNAME", "PASSWORD"} {
		if err := v.Remove(name + "/" + varName); err != nil && !errors.Is(err, vault.ErrNotFound) {
			return err
		}
	}
	if err := os.Remove(manifestPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GitMigration describes what jit migrate did to one host's stored git
// credential.
type GitMigration struct {
	Host              string
	CredentialsPath   string // the ~/.git-credentials (or XDG) file the entry lived in
	CredentialsBackup string
	ConfigPath        string // the git config file whose credential.helper was set
	ConfigBackup      string // "" when the config file didn't exist before this run
	HelperPath        string
	VaultProfileName  string // "git-<host>"
	VaultProfilePath  string
	Variables         []string
	// ReplacedStoreHelper is true when this run removed a `store` (plaintext)
	// credential.helper, the one jit is displacing.
	ReplacedStoreHelper bool
}

// gitGlobalConfigPath returns the git config file `git config --global` would
// write to: ~/.gitconfig, unless it's absent and the XDG file
// (~/.config/git/config) exists. Git always reads ~/.gitconfig as a global
// config with highest precedence, so setting credential.helper there takes
// effect regardless.
func gitGlobalConfigPath(home string) string {
	dotfile := filepath.Join(home, ".gitconfig")
	if _, err := os.Stat(dotfile); err == nil {
		return dotfile
	}
	xdg := filepath.Join(home, ".config", "git", "config")
	if _, err := os.Stat(xdg); err == nil {
		return xdg
	}
	return dotfile
}

// runGitConfig runs `git config --file <cfgPath> <args...>` and returns its
// trimmed stdout and exit code. git owns its own config format (includes,
// escaping, ordering, multi-valued keys), so jit drives it through git rather
// than hand-editing the INI, the same reason migrate already shells out to
// git for HasGitHistory. A non-ExitError (git missing, not executable) is a
// real error; an ExitError's code is returned for the caller to interpret
// (git uses 1 for "key not found", 5 for "nothing to unset").
func runGitConfig(cfgPath string, args ...string) (stdout string, code int, err error) {
	full := append([]string{"config", "--file", cfgPath}, args...)
	cmd := exec.Command("git", full...) // #nosec G204 -- fixed subcommand; cfgPath is jit's own home path, the rest are constants
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return strings.TrimRight(out.String(), "\n"), ee.ExitCode(), nil
		}
		return "", -1, fmt.Errorf("running git config: %w (%s)", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimRight(out.String(), "\n"), 0, nil
}

// gitCredentialHelpers returns the credential.helper values configured in
// cfgPath, in order. A missing key or file (git exit 1) yields nothing.
func gitCredentialHelpers(cfgPath string) ([]string, error) {
	out, code, err := runGitConfig(cfgPath, "--get-all", "credential.helper")
	if err != nil {
		return nil, err
	}
	if code == 1 { // key not set, or file absent
		return nil, nil
	}
	if code != 0 {
		return nil, fmt.Errorf("git config --get-all credential.helper exited %d", code)
	}
	var helpers []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			helpers = append(helpers, line)
		}
	}
	return helpers, nil
}

// configureGitHelper makes jit the credential helper in cfgPath: it removes
// any `store` helper (the plaintext one jit displaces) and adds `jit` if not
// already present, leaving any other helper (a secure one like osxkeychain)
// in place, since git tries helpers in order and a secure store has nothing
// in ~/.git-credentials to migrate anyway. Idempotent. Reports whether it
// removed a store helper and whether jit was already installed.
func configureGitHelper(cfgPath string, drained bool) (replacedStore, alreadyInstalled bool, err error) {
	helpers, err := gitCredentialHelpers(cfgPath)
	if err != nil {
		return false, false, err
	}
	var hasJit, hasStore bool
	for _, h := range helpers {
		switch h {
		case gitHelperName:
			hasJit = true
		case "store":
			hasStore = true
		}
	}
	// The `store` helper is only removed once nothing is left for it to serve.
	//
	// Removing it is a MACHINE-WIDE action while migration is per-host, so an
	// unconditional unset broke every credential this run did not migrate: the
	// line stayed in ~/.git-credentials, but with no store helper configured
	// git stopped consulting the file, so the credential was simultaneously
	// still on disk in plaintext AND unusable. A host jit skips (see
	// ErrGitMultipleAccounts) is exactly that case.
	//
	// Checked after this host's own strip, so on a run that migrates
	// everything the last host still drains the file and clears the helper —
	// the intended end state is reached, just by observation instead of
	// assumption.
	if hasStore && drained {
		// value regex ^store$ so an unrelated "storefoo" is never touched.
		_, code, err := runGitConfig(cfgPath, "--unset-all", "credential.helper", `^store$`)
		if err != nil {
			return false, false, err
		}
		if code != 0 && code != 5 { // 5 == nothing matched, already gone
			return false, false, fmt.Errorf("git config --unset-all credential.helper exited %d", code)
		}
		replacedStore = true
	}
	if !hasJit {
		if _, code, err := runGitConfig(cfgPath, "--add", "credential.helper", gitHelperName); err != nil {
			return false, false, err
		} else if code != 0 {
			return false, false, fmt.Errorf("git config --add credential.helper exited %d", code)
		}
	}
	return replacedStore, hasJit, nil
}

// gitCredentialStoresEmpty reports whether git's plaintext stores hold no
// credentials any more — the condition under which the `store` helper has
// nothing left to serve and can be removed. A missing file counts as empty; a
// file that cannot be parsed counts as NOT empty, so an unreadable store never
// talks jit into disabling the helper that reads it.
func gitCredentialStoresEmpty(home string) (bool, error) {
	for _, path := range []string{GitCredentialsPath(home), GitCredentialsXDGPath(home)} {
		creds, err := parseGitCredentialsFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return false, fmt.Errorf("reading %s: %w", path, err)
		}
		if len(creds) > 0 {
			return false, nil
		}
	}
	return true, nil
}

// stripHostFromGitCredentials rewrites a git-credentials store file with every
// line for host removed. Host-level, matching the migration's keying — which
// is exactly why ApplyGitCredential refuses a host with more than one account
// before ever reaching here (ErrGitMultipleAccounts): this removes them all,
// and only one of them was vaulted.
//
// Not byte-for-byte, despite an earlier claim in this comment: kept lines are
// trimmed and rejoined with "\n", so blank lines, trailing whitespace and CRLF
// line endings do not survive. Harmless for a file whose every meaningful line
// is a URL, and stated here rather than promised away.
func stripHostFromGitCredentials(path, host string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- fixed ~/.git-credentials path, not external input
	if err != nil {
		return err
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if u, err := url.Parse(trimmed); err == nil && u.Host == host {
			continue
		}
		kept = append(kept, trimmed)
	}
	out := strings.Join(kept, "\n")
	if out != "" {
		out += "\n"
	}
	return os.WriteFile(path, []byte(out), 0o600) // #nosec G703 -- fixed git-credentials path under the audited home, not external input
}

// ApplyGitCredential moves host's credential out of git's plaintext store and
// into v's vault under a home-rooted global profile ("git-<host>" — git
// invokes its credential helper from whatever directory a command runs in, so
// the profile must resolve independent of cwd, same as AWS/Docker/Terraform),
// writes the git-credential-jit helper executable, sets credential.helper to
// jit in the git config (removing the plaintext `store` helper), and rewrites
// the store file with that host's line removed. Standard ordering: vault
// writes → profile manifest → backups → wiring → rewrite the source file.
//
// dedup, if non-nil, makes a run migrating several hosts back the shared
// store file and git config up once, at their pristine pre-run state, rather
// than once per host, so undo restores the original rather than the last,
// most-stripped snapshot. See BackupTracker (GAPS.md #65).
func ApplyGitCredential(v *vault.Vault, home, host string, dedup ...*BackupTracker) (GitMigration, error) {
	var tracker *BackupTracker
	if len(dedup) > 0 {
		tracker = dedup[0]
	}

	var found *GitCredential
	var credPath string
	var accounts []string
	for _, path := range []string{GitCredentialsPath(home), GitCredentialsXDGPath(home)} {
		creds, err := parseGitCredentialsFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return GitMigration{}, fmt.Errorf("reading %s: %w", path, err)
		}
		for i := range creds {
			if creds[i].Host != host {
				continue
			}
			// EVERY account for this host, not just the first. The strip below
			// is host-level and removes them all, so counting only the first
			// was how a second account's token got deleted from the plaintext
			// store having never been vaulted — see ErrGitMultipleAccounts.
			accounts = append(accounts, creds[i].Username)
			if found == nil {
				c := creds[i]
				found, credPath = &c, path
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		return GitMigration{}, fmt.Errorf("host %q not found (or has no plaintext credential) in git's credential store", host)
	}
	if len(accounts) > 1 {
		return GitMigration{}, fmt.Errorf("%w: %s has %d accounts (%s) in %s",
			ErrGitMultipleAccounts, host, len(accounts), strings.Join(quoteAll(accounts), ", "), credPath)
	}

	cfgPath := gitGlobalConfigPath(home)

	meta, err := newProvenance(vault.ClassGit, credPath)
	if err != nil {
		return GitMigration{}, err
	}
	profileName, manifestPath, err := upsertGitProfile(v, host, found.Username, found.Password, meta)
	if err != nil {
		return GitMigration{}, err
	}

	credBackup, err := tracker.backupOnce(v, credPath)
	if err != nil {
		return GitMigration{}, fmt.Errorf("backing up %s: %w", credPath, err)
	}

	// The git config file is shared across every host in this run and may not
	// exist yet (git config --add creates it). Same discipline as
	// ~/.terraformrc: back it up once at its pristine state if it existed; if
	// jit creates it, record it for removal on undo.
	cfgHandled := tracker.alreadyHandled(cfgPath)
	_, cfgStatErr := os.Stat(cfgPath)
	cfgExisted := cfgStatErr == nil
	var cfgBackup string
	if cfgExisted && !cfgHandled {
		cfgBackup, err = tracker.backupOnce(v, cfgPath)
		if err != nil {
			return GitMigration{}, fmt.Errorf("backing up %s: %w", cfgPath, err)
		}
	}

	helperPath, err := writeGitHelper(home)
	if err != nil {
		return GitMigration{}, err
	}

	// Strip first, then configure: whether git still needs its `store` helper
	// is a question about what remains in the file, so it can only be answered
	// after this host's own lines are gone.
	if err := stripHostFromGitCredentials(credPath, host); err != nil {
		return GitMigration{}, fmt.Errorf("rewriting %s: %w", credPath, err)
	}
	drained, err := gitCredentialStoresEmpty(home)
	if err != nil {
		return GitMigration{}, err
	}

	replacedStore, _, err := configureGitHelper(cfgPath, drained)
	if err != nil {
		return GitMigration{}, err
	}

	if !cfgExisted && !cfgHandled {
		absCfg, err := filepath.Abs(cfgPath)
		if err != nil {
			return GitMigration{}, fmt.Errorf("resolving %s: %w", cfgPath, err)
		}
		if err := RecordCreatedFile(v.Root, absCfg); err != nil {
			return GitMigration{}, fmt.Errorf("recording created %s in the undo index: %w", cfgPath, err)
		}
		tracker.markCreated(cfgPath)
	}

	return GitMigration{
		Host:                host,
		CredentialsPath:     credPath,
		CredentialsBackup:   credBackup,
		ConfigPath:          cfgPath,
		ConfigBackup:        cfgBackup,
		HelperPath:          helperPath,
		VaultProfileName:    profileName,
		VaultProfilePath:    manifestPath,
		Variables:           []string{"PASSWORD", "USERNAME"},
		ReplacedStoreHelper: replacedStore,
	}, nil
}

// writeGitHelper writes the git-credential-jit executable, a two-line shell
// wrapper exec-ing this jit binary, since git discovers helpers strictly by
// executable name on $PATH and jit can't rename itself. Same shape and
// rationale as writeDockerHelper, including unconditional overwrite: the
// script is jit's own artifact, and a rebuilt/moved jit binary should refresh
// it on the next migrate rather than keep exec-ing a stale path.
func writeGitHelper(home string) (string, error) {
	jitPath, err := resolveJitExecutable()
	if err != nil {
		return "", fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	helperPath := GitHelperPath(home)
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(helperPath), err)
	}
	script := fmt.Sprintf("#!/bin/sh\n# Written by jit migrate, git credential helper. See `jit git-credential --help`.\nexec %s git-credential \"$@\"\n", singleQuote(jitPath))
	if err := os.WriteFile(helperPath, []byte(script), 0o700); err != nil { // #nosec G306 -- must be executable; helper runs as this same user
		return "", fmt.Errorf("writing %s: %w", helperPath, err)
	}
	return helperPath, nil
}
