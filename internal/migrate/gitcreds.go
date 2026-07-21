// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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
func upsertGitProfile(v *vault.Vault, host, username, password string) (name, manifestPath string, err error) {
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
		if err := v.Set(secretPath, []byte(value)); err != nil {
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
	_, _, err := upsertGitProfile(v, c.Host, c.Username, c.Password)
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
