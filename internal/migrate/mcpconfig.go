// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// mcpConfigFileNames mirrors internal/audit/mcpconfig.go's own list.
var mcpConfigFileNames = map[string]bool{
	"mcp.json":                   true,
	".mcp.json":                  true,
	"claude_desktop_config.json": true,
}

var mcpProfileNameSanitizer = regexp.MustCompile(`[^A-Za-z0-9_.\-]+`)

// mcpServerRaw is one server entry decoded as raw JSON fields, so
// ApplyMCPConfig can rewrite "command"/"args"/"env" while leaving every
// other field (cwd, type, url, disabled, alwaysAllow, ...) untouched —
// this ecosystem's schema is still moving, and a fixed struct would
// silently drop any field it doesn't know about.
type mcpServerRaw map[string]json.RawMessage

// MCPServerMigration describes what jit migrate did to one server entry.
type MCPServerMigration struct {
	ServerName  string
	ProfileName string
	ProfilePath string
	Variables   []string
	// NamespaceMovedFrom mirrors EnvFileMigration's field: the profile
	// name this server would have used had the global store's namespace
	// not already belonged to a same-named server from a DIFFERENT config
	// file (GAPS.md #56) — "" in the common case.
	NamespaceMovedFrom string
}

// MCPConfigMigration describes what jit migrate did to one MCP config
// file — one file can have multiple servers, each migrated independently
// into its own profile.
type MCPConfigMigration struct {
	FilePath   string
	BackupPath string
	Servers    []MCPServerMigration
}

// ClaudeDesktopConfigPath is exported (alongside AWSCredentialsPath,
// KubeconfigPath, GlobalNpmrcPath) so internal/cli can tell this one
// always-checked fixed path apart from a project-scoped mcp.json/.mcp.json
// finding in the same DiscoverMCPConfigs result — needed to group a
// migrate plan into "scoped to this run" vs "machine-wide" sections.
func ClaudeDesktopConfigPath(home string) string {
	return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
}

// DiscoverMCPConfigs mirrors audit's own file discovery (ScanMCPConfigs):
// project-scoped mcp.json/.mcp.json files under cwd — NOT a home-wide
// walk, matching DiscoverEnvFiles' own deliberately narrower blast radius
// for real (non-dry-run) mutation — plus, when includeClaudeDesktop is
// true, the fixed Claude Desktop path (a single well-known global file
// that lives under $HOME regardless of which project cwd is, so
// `jit migrate local` never includes it — only a `home` run does; see
// internal/cli's runMigrate). Only returns files with at least one server
// that actually has a non-empty env block to migrate.
func DiscoverMCPConfigs(home, cwd string, includeClaudeDesktop bool) ([]string, error) {
	var found []string
	seen := map[string]bool{}

	check := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		servers, err := parseMCPServers(path)
		if err != nil {
			return // malformed/unreadable, skip, matches audit's own tolerance
		}
		for _, entry := range servers {
			if hasNonEmptyEnv(entry) {
				found = append(found, path)
				return
			}
		}
	}

	if includeClaudeDesktop {
		claudePath := ClaudeDesktopConfigPath(home)
		if _, err := os.Stat(claudePath); err == nil {
			check(claudePath)
		}
	}

	err := filepath.WalkDir(cwd, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// See DiscoverEnvFiles' identical guard: a permission-denied
			// error partway through the tree (~/.Trash, app-sandboxed
			// ~/Library containers, etc. under a real $HOME — GAPS.md
			// #26's home-wide walk) must skip that path, not abort the
			// whole scan.
			if path == cwd {
				return err
			}
			return filepath.SkipDir
		}
		if d.IsDir() {
			if skipDiscoveryDir(path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if mcpConfigFileNames[d.Name()] {
			check(path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", cwd, err)
	}

	sort.Strings(found)
	return found, nil
}

// ApplyMCPConfig moves every server's env-block secrets in path into v's
// vault, one profile per server (named "mcp-<server>") stored in the
// home-rooted global profile store (profile.GlobalRoot) — an MCP host
// launches its server subprocess with an unpredictable working directory,
// so the rewritten command can't rely on a project-relative profile
// lookup the way jit run normally would. Each migrated server's
// "command"/"args" are rewritten to launch via jit run instead, using
// jit's own resolved executable path (not a bare "jit", since a
// GUI-launched MCP host's PATH often doesn't match an interactive shell's).
// Every other field on the server entry is preserved untouched. Order
// matters for safety, same as ApplyEnvFile/ApplyShellConfig: every vault
// write and profile manifest write happens before path itself is
// rewritten, and path is backed up first.
func ApplyMCPConfig(v *vault.Vault, path string) (MCPConfigMigration, error) {
	topLevel, serversKey, servers, err := loadMCPFile(path)
	if err != nil {
		return MCPConfigMigration{}, fmt.Errorf("reading %s: %w", path, err)
	}
	if serversKey == "" {
		return MCPConfigMigration{}, fmt.Errorf("%s has no mcpServers/servers block", path)
	}

	jitPath, err := resolveJitExecutable()
	if err != nil {
		return MCPConfigMigration{}, fmt.Errorf("resolving jit's own executable path: %w", err)
	}
	home, err := profile.GlobalRoot()
	if err != nil {
		return MCPConfigMigration{}, fmt.Errorf("resolving global profile root: %w", err)
	}

	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	result := MCPConfigMigration{FilePath: path}
	for _, name := range names {
		entry := servers[name]
		if !hasNonEmptyEnv(entry) {
			continue
		}

		serverMigration, err := migrateMCPServer(v, home, jitPath, path, name, entry)
		if err != nil {
			return MCPConfigMigration{}, fmt.Errorf("%s: server %q: %w", path, name, err)
		}
		result.Servers = append(result.Servers, serverMigration)
	}
	if len(result.Servers) == 0 {
		return MCPConfigMigration{}, fmt.Errorf("%s has no server with secrets to migrate", path)
	}

	serversJSON, err := marshalJSONNoEscape(servers, "")
	if err != nil {
		return MCPConfigMigration{}, err
	}
	topLevel[serversKey] = serversJSON

	backupPath, err := backupSecretFile(v, path)
	if err != nil {
		return MCPConfigMigration{}, fmt.Errorf("backing up %s: %w", path, err)
	}
	result.BackupPath = backupPath

	out, err := marshalJSONNoEscape(topLevel, "  ")
	if err != nil {
		return MCPConfigMigration{}, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return MCPConfigMigration{}, fmt.Errorf("writing %s: %w", path, err)
	}

	return result, nil
}

// migrateMCPServer mutates entry in place (moving its env block into the
// vault and rewriting command/args) and returns a summary of what moved.
// entry is a reference into the caller's servers map, so this mutation is
// visible to the subsequent json.Marshal(servers) call. sourcePath is the
// config file being migrated — MCP profile namespaces are claimed per
// source file (claimMCPNamespace, GAPS.md #56), so a same-named server in
// a different config can never silently overwrite this one's secrets.
func migrateMCPServer(v *vault.Vault, globalRoot, jitPath, sourcePath, serverName string, entry mcpServerRaw) (MCPServerMigration, error) {
	var env map[string]string
	if err := json.Unmarshal(entry["env"], &env); err != nil {
		return MCPServerMigration{}, fmt.Errorf("parsing env block: %w", err)
	}

	profileName, profilePath, entries, movedFrom, err := claimMCPNamespace(v, globalRoot, "mcp-"+sanitizeProfileName(serverName), sourcePath, env)
	if err != nil {
		return MCPServerMigration{}, err
	}

	varNames := make([]string, 0, len(env))
	for envKey := range env {
		varNames = append(varNames, envKey)
	}
	sort.Strings(varNames)

	for _, envKey := range varNames {
		secretPath := profileName + "/" + envKey
		if err := v.Set(secretPath, []byte(env[envKey])); err != nil {
			return MCPServerMigration{}, fmt.Errorf("storing %s in vault: %w", envKey, err)
		}
		entries[envKey] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return MCPServerMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}
	// Stamp ownership AFTER the manifest write: a crash in between leaves a
	// legacy-shaped (unstamped) profile, which the next run treats with the
	// cautious legacy rules rather than trusting a stamp for content that
	// never landed.
	if err := os.WriteFile(profileSourceSidecarPath(profilePath), []byte(sourcePath+"\n"), 0o600); err != nil {
		return MCPServerMigration{}, fmt.Errorf("recording profile source %s: %w", profilePath, err)
	}

	var command string
	if craw, ok := entry["command"]; ok {
		if err := json.Unmarshal(craw, &command); err != nil {
			return MCPServerMigration{}, fmt.Errorf("command is not a string")
		}
	}
	var args []string
	if araw, ok := entry["args"]; ok {
		if err := json.Unmarshal(araw, &args); err != nil {
			return MCPServerMigration{}, fmt.Errorf("args is not a string array")
		}
	}

	newArgs := make([]string, 0, len(args)+4)
	newArgs = append(newArgs, "run", "--profile", profileName, "--")
	if command != "" {
		newArgs = append(newArgs, command)
	}
	newArgs = append(newArgs, args...)

	commandJSON, err := marshalJSONNoEscape(jitPath, "")
	if err != nil {
		return MCPServerMigration{}, err
	}
	argsJSON, err := marshalJSONNoEscape(newArgs, "")
	if err != nil {
		return MCPServerMigration{}, err
	}
	entry["command"] = commandJSON
	entry["args"] = argsJSON
	delete(entry, "env")

	return MCPServerMigration{
		ServerName:         serverName,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

// profileSourceSidecarPath is where claimMCPNamespace records which config
// file owns a global-store MCP profile — a sibling of the manifest, not a
// field inside it: profile.Profile is a flat variable→vault-path map that
// every consumer (inject.Resolve, doctor) iterates in full, so a metadata
// key would be resolved as if it were a variable.
func profileSourceSidecarPath(profilePath string) string {
	return strings.TrimSuffix(profilePath, ".yaml") + ".source"
}

// claimMCPNamespace picks the profile name a server migration may safely
// write under: base, or the first free base-2/base-3/... when base already
// belongs to a same-named server from a DIFFERENT config file (GAPS.md
// #56). The global store can't use claimNamespace's per-store-manifest
// ownership test — every same-named server lands in the SAME store, so a
// foreign server's earlier migration looks exactly like a legitimate
// re-run of this one. Ownership is instead recorded per profile in a
// ".source" sidecar naming the config file that created it:
//
//   - sidecar matches sourcePath → this config's own profile; refresh
//     freely (the re-run/undo-then-remigrate case).
//   - sidecar names another file → foreign; bump.
//   - manifest exists with NO sidecar (migrated before this mechanism):
//     adopt it — and stamp it — only if every variable this server would
//     write already holds the IDENTICAL value (same token → same secret in
//     practice, and the write changes nothing); any difference means two
//     genuinely different servers are colliding, the exact silent
//     overwrite this exists to stop → bump.
//
// A vault path that exists without being claimed by the candidate's
// manifest is foreign regardless (claimNamespace's own rule).
func claimMCPNamespace(v *vault.Vault, globalRoot, base, sourcePath string, env map[string]string) (name, profilePath string, entries profile.Profile, movedFrom string, err error) {
	for i := 1; i <= maxNamespaceCandidates; i++ {
		name = base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		profilePath, err = profile.Path(globalRoot, name)
		if err != nil {
			return "", "", nil, "", err
		}

		entries = profile.Profile{}
		manifestExists := false
		switch existing, lerr := profile.LoadFile(profilePath); {
		case lerr == nil:
			manifestExists = true
			for k, p := range existing {
				entries[k] = p
			}
		case errors.Is(lerr, os.ErrNotExist):
			// fresh namespace, unless the vault disagrees below
		default:
			return "", "", nil, "", fmt.Errorf("loading existing profile %s: %w", profilePath, lerr)
		}

		recordedSource, srcErr := os.ReadFile(profileSourceSidecarPath(profilePath)) // #nosec G304 -- a fixed-suffix sibling of jit's own profile manifest
		legacy := manifestExists && srcErr != nil

		conflict := manifestExists && srcErr == nil && strings.TrimSpace(string(recordedSource)) != sourcePath
		if !conflict {
			for envKey, value := range env {
				secretPath := name + "/" + envKey
				if entries[envKey] == secretPath {
					if legacy {
						// Unstamped claim: only an identical stored value
						// proves this was "us" (or is indistinguishable
						// from us). Any read/compare failure errs toward
						// bump — reuse on a guess is the bug.
						existing, gerr := v.Get(secretPath)
						if gerr != nil || string(existing) != value {
							conflict = true
							break
						}
					}
					continue
				}
				exists, eerr := v.Exists(secretPath)
				if eerr != nil {
					return "", "", nil, "", fmt.Errorf("checking vault path %s: %w", secretPath, eerr)
				}
				if exists {
					conflict = true
					break
				}
			}
		}
		if !conflict {
			if i > 1 {
				movedFrom = base
			}
			return name, profilePath, entries, movedFrom, nil
		}
	}
	return "", "", nil, "", fmt.Errorf("no free vault namespace for %q after %d candidates", base, maxNamespaceCandidates)
}

// ProfileOwnerConfig returns the MCP config file recorded as owning a
// global-store profile (the .source sidecar claimMCPNamespace writes), or
// "" when there is none — a non-MCP global profile (shell config, AWS,
// kubeconfig, Terraform, the global npmrc) or one migrated before the
// sidecar mechanism existed. `jit migrate remove` uses this to tell a
// profile that belongs to the project's own mcp.json — global-store only
// because an MCP host's subprocess can't rely on a project-relative lookup
// — apart from a genuinely machine-level one: without it, removing a
// project stranded that profile and its vault secrets forever (a real E2E
// finding: `jit status` reported dangling references right after a
// "removed jit from this project" success).
func ProfileOwnerConfig(profilePath string) string {
	data, err := os.ReadFile(profileSourceSidecarPath(profilePath)) // #nosec G304 -- a fixed-suffix sibling of jit's own profile manifest
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// RemoveOwnedProfile deletes a global-store profile manifest together with
// its .source ownership sidecar. Idempotent: an already-missing file is
// success, matching every other cleanup on `jit migrate remove`'s path.
func RemoveOwnedProfile(profilePath string) error {
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(profileSourceSidecarPath(profilePath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// mcpWrapperProfile extracts the profile name from a server entry whose
// args are jit's own `run --profile <name> -- ...` wrapper shape
// (migrateMCPServer's rewrite), or "" for anything else.
func mcpWrapperProfile(entry mcpServerRaw) string {
	var args []string
	if araw, ok := entry["args"]; ok {
		if err := json.Unmarshal(araw, &args); err != nil {
			return ""
		}
	}
	if len(args) < 4 || args[0] != "run" || args[1] != "--profile" || args[3] != "--" {
		return ""
	}
	return args[2]
}

// WrappedMCPProfiles reports which profile names path's servers currently
// launch through jit's wrapper — the plan-time (no vault, no auth) half of
// UnwrapMCPConfig. A missing or malformed file is an empty result, not an
// error: planning must stay tolerant of a config the user deleted or
// hand-edited since migration.
func WrappedMCPProfiles(path string) map[string]bool {
	_, _, servers, err := loadMCPFile(path)
	if err != nil {
		return nil
	}
	wrapped := map[string]bool{}
	for _, entry := range servers {
		if name := mcpWrapperProfile(entry); name != "" {
			wrapped[name] = true
		}
	}
	return wrapped
}

// MCPServerRestore describes one server entry UnwrapMCPConfig rewrote back
// to a plaintext env block.
type MCPServerRestore struct {
	ServerName  string
	ProfileName string
	Variables   []string
}

// UnwrapMCPConfig is ApplyMCPConfig's inverse, for `jit migrate remove`:
// every server in path still launching through jit's `run --profile <name>
// --` wrapper — for one of the given owned profiles only — gets its
// original command/args back and a plaintext env block resolved from the
// CURRENT vault values (unmount's semantics, matching the rest of remove,
// so `jit vault set` edits since migration survive). owned maps profile
// name → manifest path, from the .source sidecars naming this config file
// as the owner; a wrapper referencing any other profile is left alone. An
// empty result with a nil error means nothing in the file was jit's, and
// the file wasn't rewritten at all.
func UnwrapMCPConfig(v *vault.Vault, path string, owned map[string]string) ([]MCPServerRestore, error) {
	topLevel, serversKey, servers, err := loadMCPFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if serversKey == "" {
		return nil, nil
	}

	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	var restored []MCPServerRestore
	for _, name := range names {
		entry := servers[name]
		profileName := mcpWrapperProfile(entry)
		manifestPath, ok := owned[profileName]
		if profileName == "" || !ok {
			continue
		}
		p, err := profile.LoadFile(manifestPath)
		if err != nil {
			return nil, fmt.Errorf("%s: server %q: loading profile %s: %w", path, name, manifestPath, err)
		}
		values, err := inject.Resolve(v, p)
		if err != nil {
			return nil, fmt.Errorf("%s: server %q: resolving secrets: %w", path, name, err)
		}

		var args []string
		_ = json.Unmarshal(entry["args"], &args) // shape already validated by mcpWrapperProfile
		rest := args[4:]
		if len(rest) > 0 {
			commandJSON, err := marshalJSONNoEscape(rest[0], "")
			if err != nil {
				return nil, err
			}
			entry["command"] = commandJSON
		} else {
			delete(entry, "command")
		}
		if len(rest) > 1 {
			argsJSON, err := marshalJSONNoEscape(rest[1:], "")
			if err != nil {
				return nil, err
			}
			entry["args"] = argsJSON
		} else {
			delete(entry, "args")
		}
		envJSON, err := marshalJSONNoEscape(values, "")
		if err != nil {
			return nil, err
		}
		entry["env"] = envJSON

		varNames := make([]string, 0, len(values))
		for k := range values {
			varNames = append(varNames, k)
		}
		sort.Strings(varNames)
		restored = append(restored, MCPServerRestore{ServerName: name, ProfileName: profileName, Variables: varNames})
	}
	if len(restored) == 0 {
		return nil, nil
	}

	serversJSON, err := marshalJSONNoEscape(servers, "")
	if err != nil {
		return nil, err
	}
	topLevel[serversKey] = serversJSON
	out, err := marshalJSONNoEscape(topLevel, "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", path, err)
	}
	return restored, nil
}

func parseMCPServers(path string) (map[string]mcpServerRaw, error) {
	_, _, servers, err := loadMCPFile(path)
	return servers, err
}

// loadMCPFile decodes path's top level into raw JSON fields (preserving
// anything besides the servers block untouched) and its "mcpServers" (or
// "servers", VS Code's schema) block into per-server raw fields.
func loadMCPFile(path string) (topLevel map[string]json.RawMessage, serversKey string, servers map[string]mcpServerRaw, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from DiscoverMCPConfigs' own fixed/cwd-scoped walk, never external input
	if err != nil {
		return nil, "", nil, err
	}

	if err := json.Unmarshal(data, &topLevel); err != nil {
		return nil, "", nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	serversKey = "mcpServers"
	raw, ok := topLevel[serversKey]
	if !ok {
		serversKey = "servers"
		raw, ok = topLevel[serversKey]
	}
	if !ok {
		return topLevel, "", nil, nil
	}
	if err := json.Unmarshal(raw, &servers); err != nil {
		return nil, "", nil, fmt.Errorf("parsing %s: %s block: %w", path, serversKey, err)
	}
	return topLevel, serversKey, servers, nil
}

func hasNonEmptyEnv(entry mcpServerRaw) bool {
	raw, ok := entry["env"]
	if !ok {
		return false
	}
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		return false
	}
	return len(env) > 0
}

func sanitizeProfileName(name string) string {
	return mcpProfileNameSanitizer.ReplaceAllString(name, "-")
}

// resolveJitExecutable returns jit's own resolved binary path, mirroring
// internal/cli/agent.go's install logic (os.Executable + EvalSymlinks) —
// needed because a GUI-launched MCP host's PATH often doesn't match an
// interactive shell's, so a bare "jit" in the rewritten command could
// fail to launch even though it works fine from a terminal.
func resolveJitExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
