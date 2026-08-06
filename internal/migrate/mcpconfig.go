// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

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

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/inject"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

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
	// EnvFiles are the --env-file paths absorbed into this profile and
	// replaced with pointer files. Callers must surface these: the user
	// named a config file, and a second file on disk was rewritten.
	EnvFiles []string
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
// that has something to migrate — a non-empty env block, or an --env-file
// naming a readable file (hasMigratableCredentials).
func DiscoverMCPConfigs(home, cwd string, includeClaudeDesktop bool) ([]string, error) {
	return discoverMCPConfigFiles(home, cwd, includeClaudeDesktop, hasMigratableCredentials)
}

// discoverMCPConfigFiles is DiscoverMCPConfigs' walk with the "is this file
// interesting" test left to the caller. Two callers want the same file set
// under two different questions — "has something to migrate" (an env block)
// and "has something jit already wrote" (a run --profile wrapper, see
// DiscoverWrappedMCPEntries) — and the part worth sharing is not the
// predicate but the walk: which directories are pruned, which filenames
// count, and that the fixed Claude Desktop path is probed separately because
// no home walk reaches ~/Library. Those three facts drifting between two
// copies is exactly the failure SkipNoiseDir's doc comment describes.
func discoverMCPConfigFiles(home, cwd string, includeClaudeDesktop bool, accept func(configPath string, entry mcpServerRaw) bool) ([]string, error) {
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
			if accept(path, entry) {
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
			if skipDiscoveryDir(cwd, path, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		// Regular files only, same rule as audit's walk (fsutil.go).
		if !d.Type().IsRegular() {
			return nil
		}
		if audit.IsMCPConfigFileName(d.Name()) {
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

// MCPEnvFilePreview reports the --env-file paths ApplyMCPConfig would absorb
// from path, across every server in it.
//
// It exists for `jit migrate`'s PLAN, for the same reason EnvFilePreview
// does: the plan is the moment the user consents to a credential-touching
// mutation, so it has to be honest about scope. A user naming one .mcp.json
// has no way to know a SECOND file elsewhere on disk is about to be rewritten
// into a pointer, and "1 change planned" said nothing about it.
//
// Best-effort: an unreadable or malformed config previews nothing rather than
// failing, since a plan must still render for a file apply will fail on for
// its own reasons.
func MCPEnvFilePreview(path string) []string {
	_, _, servers, err := loadMCPFile(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	var found []string
	seen := map[string]bool{}
	for _, name := range names {
		for _, target := range migratableEnvFiles(path, servers[name]) {
			if !seen[target] {
				seen[target] = true
				found = append(found, target)
			}
		}
	}
	return found
}

// ApplyMCPConfig moves every server's secrets in path into v's vault — both
// the env block and any file it reads via --env-file — one profile per server (named "mcp-<server>") stored in the
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

	// Every --env-file target is read ONCE, before any of them is rewritten.
	// Neutralizing inside the per-server loop was a silent corruption when two
	// servers shared one file: the first vaulted the real values and replaced
	// the file with a pointer, and the second then parsed that pointer and
	// stored "jit://vault/mcp-alpha/TOKEN" as its own credential. Reading up
	// front also moves the unparseable-line hard stop ahead of every mutation.
	envCache, err := readMCPEnvFiles(path, servers, names)
	if err != nil {
		return MCPConfigMigration{}, err
	}

	result := MCPConfigMigration{FilePath: path}
	pointers := newEnvFilePointerSet()
	for _, name := range names {
		entry := servers[name]
		if !hasMigratableCredentials(path, entry) {
			continue
		}

		serverMigration, err := migrateMCPServer(v, home, jitPath, path, name, entry, envCache, pointers)
		if err != nil {
			return MCPConfigMigration{}, fmt.Errorf("%s: server %q: %w", path, name, err)
		}
		result.Servers = append(result.Servers, serverMigration)
	}
	if len(result.Servers) == 0 {
		return MCPConfigMigration{}, fmt.Errorf("%s has no server with secrets to migrate", path)
	}

	// Now that every value is in the vault and every manifest is written, the
	// source files can be neutralized -- once each, whatever number of servers
	// read them.
	if err := pointers.replaceAll(v); err != nil {
		return MCPConfigMigration{}, err
	}

	serversJSON, err := marshalJSONNoEscape(servers, "")
	if err != nil {
		return MCPConfigMigration{}, err
	}
	topLevel[serversKey] = serversJSON

	// Linked, so `jit migrate undo <config>` brings the absorbed .env files
	// back in the same run. Restoring the config alone re-adds --env-file
	// pointing at a file that is now a pointer, which starts the server with
	// "jit://vault/..." strings as its credentials.
	var absorbed []string
	for _, sm := range result.Servers {
		absorbed = append(absorbed, sm.EnvFiles...)
	}
	backupPath, err := backupSecretFileLinking(v, path, absorbed)
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
func migrateMCPServer(v *vault.Vault, globalRoot, jitPath, sourcePath, serverName string, entry mcpServerRaw, envCache map[string]*mcpEnvFile, pointers *envFilePointerSet) (MCPServerMigration, error) {
	// Absent, not merely empty: with the widened discovery gate a server can
	// reach here carrying an --env-file and no env block at all, and
	// json.Unmarshal(nil, ...) fails with "unexpected end of JSON input".
	env := map[string]string{}
	if raw, ok := entry["env"]; ok && len(raw) > 0 {
		if err := json.Unmarshal(raw, &env); err != nil {
			return MCPServerMigration{}, fmt.Errorf("parsing env block: %w", err)
		}
	}

	// Absorb every --env-file this server reads into the same profile, from
	// the up-front cache (see readMCPEnvFiles). The env BLOCK wins a name
	// collision: it is set by the host on the child process, which is the
	// more explicit and more local of the two, and silently preferring the
	// file would change what the server sees.
	envFiles := migratableEnvFiles(sourcePath, entry)
	fileVars := map[string][]string{}
	for _, target := range envFiles {
		cached, ok := envCache[target]
		if !ok {
			continue
		}
		for _, name := range cached.order {
			if _, taken := env[name]; taken {
				continue
			}
			env[name] = cached.values[name]
			fileVars[target] = append(fileVars[target], name)
		}
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

	meta, err := newProvenance(vault.ClassMCP, sourcePath)
	if err != nil {
		return MCPServerMigration{}, err
	}
	for _, envKey := range varNames {
		secretPath := profileName + "/" + envKey
		if err := v.SetWithMeta(secretPath, []byte(env[envKey]), meta); err != nil {
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

	// Record where this server's copy of each file variable landed. The file
	// itself is rewritten later, once, by ApplyMCPConfig -- see the pointer
	// set's own doc comment for why not here.
	for _, target := range envFiles {
		pointers.record(target, fileVars[target], entries)
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

	// The flag goes with the file. Leaving it would point the launcher at a
	// pointer file whose "KEY=jit://vault/..." lines it would happily set as
	// literal values, which is worse than either outcome on its own: the
	// server starts, and every credential it holds is a fake string.
	if len(envFiles) > 0 {
		args = stripEnvFileArgs(args)
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
		EnvFiles:           envFiles,
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

// WrappedMCPEntry is one server entry that jit itself rewrote to launch
// through `jit run --profile`. It carries the three things that entry
// depends on and that nothing revalidates after the rewrite: the absolute
// jit binary it invokes, the profile it names, and the command it wraps.
type WrappedMCPEntry struct {
	ConfigPath string
	ServerName string
	// JitPath is the entry's "command" — migrateMCPServer deliberately
	// writes jit's own resolved executable path rather than a bare "jit",
	// since a GUI-launched MCP host's PATH often doesn't match a shell's.
	// That is the right call and it is also why this can go stale: the
	// path is pinned at migration time and survives jit moving.
	JitPath     string
	ProfileName string
	// Command is the wrapped tool — args[4], the first token after the
	// "--" separator. Empty for an entry that wrapped a bare env block
	// with no command of its own.
	Command string
}

// DiscoverWrappedMCPEntries returns every server entry under cwd (plus, when
// includeClaudeDesktop, the fixed Claude Desktop config) that currently
// launches through jit's wrapper.
//
// This exists for `jit doctor`. A migrated entry hard-codes an absolute path
// to the jit binary and a profile name, and nothing ever checks either again:
// move the binary, switch install methods, or copy a workspace between
// machines, and every wrapped server fails to launch with the host reporting
// only "server failed" — a silent failure of jit's own rewrite, in a file the
// user has no reason to re-read. Dogfooding found exactly this: two entries
// pointing at /usr/local/bin/jit on a machine whose jit lives in ~/.local/bin.
func DiscoverWrappedMCPEntries(home, cwd string, includeClaudeDesktop bool) ([]WrappedMCPEntry, error) {
	paths, err := discoverMCPConfigFiles(home, cwd, includeClaudeDesktop, func(_ string, entry mcpServerRaw) bool {
		return mcpWrapperProfile(entry) != ""
	})
	if err != nil {
		return nil, err
	}

	var entries []WrappedMCPEntry
	for _, path := range paths {
		_, _, servers, err := loadMCPFile(path)
		if err != nil {
			continue // discovery already tolerated it; don't fail the check on it
		}
		names := make([]string, 0, len(servers))
		for name := range servers {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			entry := servers[name]
			profileName := mcpWrapperProfile(entry)
			if profileName == "" {
				continue
			}
			var command string
			_ = json.Unmarshal(entry["command"], &command) // "" for a malformed/absent command, which the caller reports
			var args []string
			_ = json.Unmarshal(entry["args"], &args) // shape already validated by mcpWrapperProfile
			var wrapped string
			if len(args) > 4 {
				wrapped = args[4]
			}
			entries = append(entries, WrappedMCPEntry{
				ConfigPath:  path,
				ServerName:  name,
				JitPath:     command,
				ProfileName: profileName,
				Command:     wrapped,
			})
		}
	}
	return entries, nil
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

// hasMigratableCredentials reports whether a server entry has anything
// migrate can move into the vault: a non-empty env block, or an --env-file
// naming a readable file.
//
// The second half is what this gate was missing. Discovery tested the env
// block alone, so a server delivering its credentials by `uv run --env-file
// secrets.env` was not merely skipped, it made its whole config invisible to
// `jit migrate` -- the file never appeared in a plan, and the user was told
// nothing. Two real servers on a dogfooding machine were in exactly that
// state.
func hasMigratableCredentials(configPath string, entry mcpServerRaw) bool {
	if hasNonEmptyEnv(entry) {
		return true
	}
	return len(migratableEnvFiles(configPath, entry)) > 0
}

// migratableEnvFiles returns the --env-file targets on this entry that exist
// and are regular files. A dangling pointer is not migratable: there is
// nothing to read, and rewriting the entry around a file that isn't there
// would strip a flag the user still needs when they fix the path.
func migratableEnvFiles(configPath string, entry mcpServerRaw) []string {
	var args []string
	if raw, ok := entry["args"]; ok {
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil
		}
	}
	var cwd string
	if raw, ok := entry["cwd"]; ok {
		_ = json.Unmarshal(raw, &cwd)
	}
	var found []string
	for _, target := range audit.MCPEnvFileArgs(configPath, cwd, args) {
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		// An already-neutralized target holds vault PATHS, not values.
		// Migrating it again would store "jit://vault/mcp-alpha/TOKEN" as this
		// server's credential. readMCPEnvFiles stops that happening within one
		// config; this covers a file a DIFFERENT config already converted.
		//
		// Skipped rather than resolved back to the existing vault paths: the
		// values are already protected, and re-pointing a second server at
		// another profile's secrets is a sharing decision jit should not make
		// silently. Such a server keeps its --env-file and is left alone.
		if LooksLikePointerContent(target) {
			continue
		}
		found = append(found, target)
	}
	return found
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

// stripEnvFileArgs removes every "--env-file <path>" pair and
// "--env-file=<path>" token, mirroring audit.MCPEnvFileArgs' own two
// spellings. Anything else is left byte-for-byte: this rewrites one flag out
// of a command line jit does not otherwise understand.
func stripEnvFileArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--env-file" && i+1 < len(args):
			i++ // skip the path that follows
		case args[i] == "--env-file":
			// Trailing flag with no value: drop it, there is nothing to skip.
		case strings.HasPrefix(args[i], "--env-file="):
		default:
			out = append(out, args[i])
		}
	}
	return out
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

// mcpEnvFile is one --env-file target read before anything was rewritten:
// its parsed values, and its variable names in source-file order.
type mcpEnvFile struct {
	values map[string]string
	order  []string
}

// readMCPEnvFiles reads every distinct --env-file target named by any server
// in servers, ONCE, before any of them is rewritten.
//
// Reading per-server was a silent corruption when two servers shared a file
// (a realistic shape: one .env, several servers). The first server vaulted
// the real values and replaced the file with a pointer; the second then
// parsed that pointer and stored "jit://vault/mcp-alpha/TOKEN" as its own
// credential, so its server would receive that string as a token. Nothing
// reported a problem.
//
// It also puts the unparseable-line hard stop ahead of EVERY mutation rather
// than partway through the server loop, so a config with one bad file leaves
// nothing half-migrated.
func readMCPEnvFiles(configPath string, servers map[string]mcpServerRaw, names []string) (map[string]*mcpEnvFile, error) {
	cache := map[string]*mcpEnvFile{}
	for _, name := range names {
		for _, target := range migratableEnvFiles(configPath, servers[name]) {
			if _, done := cache[target]; done {
				continue
			}
			values, order, unparsed, err := parseEnvFile(target)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", target, err)
			}
			// ApplyEnvFile's hard stop, for its reason: this file is about to
			// be rewritten, so "I silently dropped what I could not parse"
			// turns straight into a variable the server loses with nothing
			// saying why.
			if len(unparsed) > 0 {
				return nil, fmt.Errorf(
					"%s: %s could not be parsed as KEY=value (%s %s), stopping before touching anything so nothing is silently dropped; fix or comment out %s and re-run",
					target, countWord(len(unparsed), "line", "lines"),
					pluralWord(len(unparsed), "line", "lines"), joinLineNumbers(unparsed),
					pluralWord(len(unparsed), "that line", "those lines"))
			}
			cache[target] = &mcpEnvFile{values: values, order: order}
		}
	}
	return cache, nil
}

// envFilePointerSet accumulates which vault path each --env-file variable
// ended up at, so every target can be replaced with a pointer file exactly
// once after all servers are migrated.
//
// One file, one rewrite, whatever number of servers read it. A variable
// claimed by two servers keeps the FIRST server's vault path (servers are
// migrated in sorted order, so that is deterministic): the pointer file is a
// human-readable note about where the values went, and naming one real
// location beats naming none.
type envFilePointerSet struct {
	vars  map[string]profile.Profile
	order map[string][]string
	paths []string
}

func newEnvFilePointerSet() *envFilePointerSet {
	return &envFilePointerSet{vars: map[string]profile.Profile{}, order: map[string][]string{}}
}

// record notes that names from target were stored at the vault paths in
// entries. Variables already recorded for target are left as they were.
func (s *envFilePointerSet) record(target string, names []string, entries profile.Profile) {
	if _, seen := s.vars[target]; !seen {
		s.vars[target] = profile.Profile{}
		s.paths = append(s.paths, target)
	}
	for _, name := range names {
		if _, taken := s.vars[target][name]; taken {
			continue
		}
		s.vars[target][name] = entries[name]
		s.order[target] = append(s.order[target], name)
	}
}

// replaceAll backs up each recorded target and replaces it with a pointer
// file. Called only after every vault write and profile manifest has landed,
// the same ordering ApplyEnvFile and ApplyShellConfig use: a failure partway
// through never leaves the plaintext gone with nothing usable in its place.
//
// A pointer rather than a live mount, because the rewritten entries no longer
// pass --env-file: nothing reads this path for these servers any more, and a
// FIFO nobody opens is just a dead pipe. A pointer file is readable, git-safe,
// and says where the values went. A project that wants the file live can
// migrate it in its own right.
func (s *envFilePointerSet) replaceAll(v *vault.Vault) error {
	for _, target := range s.paths {
		if _, err := backupSecretFile(v, target); err != nil {
			return fmt.Errorf("backing up %s: %w", target, err)
		}
		if err := ReplaceWithPointerFile(target, s.vars[target], s.order[target]); err != nil {
			return err
		}
	}
	return nil
}
