// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// envFileNamePattern and envTemplateSuffixes mirror internal/audit's own
// detection rules (envfile.go) — kept as separate, small copies rather
// than an awkward cross-package reuse of audit's unexported symbols, since
// this package's job (deciding what to actually migrate) is deliberately
// narrower than audit's (deciding what to report).
var envFileNamePattern = regexp.MustCompile(`^\.env(\..+)?$`)

var envTemplateSuffixes = map[string]bool{
	"example": true, "sample": true, "template": true, "dist": true,
}

// envBackupOnlySuffixes mark an .env-family file as a manual backup
// copy, never a live source anything actually reads (GAPS.md #34) —
// distinct from envTemplateSuffixes (which mark a file as fake
// placeholder content, skipped from discovery entirely) since a backup
// file typically holds REAL secret values and must still be migrated;
// it just never becomes a live mount, since there's no live reader to
// serve. See IsEnvBackupOnlySuffix.
var envBackupOnlySuffixes = map[string]bool{
	"bak": true, "old": true, "orig": true, "backup": true,
}

// IsEnvBackupOnlySuffix reports whether name's own variant suffix (the
// part after ".env" — see envFileVariantSuffix) marks it as a manual
// backup that nothing reads live, e.g. ".env.bak" -> true, ".env.local"
// -> false. Checked against the LAST dot-segment only, matching
// envTemplateSuffixes' own ext-based check — ".env.local.bak" is still
// a backup (of a .env.local), so "bak" being the final segment is what
// matters, not the full variant suffix string.
func IsEnvBackupOnlySuffix(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return envBackupOnlySuffixes[ext]
}

// jitPointerFileSuffix is PointerFilePath's own suffix (pointerfile.go),
// duplicated as a literal here rather than imported, matching this
// file's existing "small independent copy" convention for
// envFileNamePattern itself.
//
// jitBackupMarker is backupFile's own marker (shellconfig.go) — the
// literal component of "<path>.jit-bak-<unix-timestamp>", checked as a
// substring rather than a suffix since the timestamp varies.
//
// DiscoverEnvFiles' pattern is a wildcard suffix match (`^\.env(\..+)?$`,
// meant to catch `.env.local`/`.env.production`) that ALSO matches any
// jit-generated artifact whose name happens to start with ".env" — a
// `.pointers` companion (`.env.pointers`) or, once .env migration
// started writing its own backup too (GAPS.md #32), a backup file
// itself (`.env.jit-bak-<ts>`). Both are jit's own artifacts, never
// user-authored `.env` content. A real, reported incident (GAPS.md #30):
// running `jit migrate local` a second time re-discovered a `.pointers`
// file from the first run as a "new .env finding," parsed its
// `KEY=jit://vault/...` lines as if they were real secrets, and
// converted the file itself into a live-mounted FIFO — destroying the
// plain-text, git-safe companion it's supposed to always stay as. Adding
// .env's own backup (GAPS.md #32) surfaced the exact same class of bug a
// second time immediately, caught by this package's own test suite
// before it ever shipped: TestDiscoverEnvFilesSkipsAlreadyMounted and
// TestDiscoverEnvFilesSkipsPointerFiles both started finding the new
// `.env.jit-bak-<ts>` file the moment the backup was added, since
// nothing excluded it yet. isJitGeneratedEnvArtifact centralizes both
// checks in one place specifically so a THIRD jit-generated `.env`-
// prefixed artifact, whenever one gets added, only needs one new line
// here instead of a third ad-hoc suffix check discovered the same way.
// Must be checked before envTemplateSuffixes — these are jit's own
// artifacts, not user-authored templates, and folding them into that
// map would misdescribe why they're skipped.
const jitPointerFileSuffix = ".pointers"
const jitBackupMarker = ".jit-bak-"

func isJitGeneratedEnvArtifact(name string) bool {
	return strings.HasSuffix(name, jitPointerFileSuffix) || strings.Contains(name, jitBackupMarker)
}

var envLinePattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

var migrateNoiseDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".jit": true,
}

// goModCacheDir resolves the Go module cache root the way the go tool does:
// $GOMODCACHE, else the first $GOPATH element + /pkg/mod, else ~/go/pkg/mod.
// Deliberately not cached — tests re-point $GOMODCACHE/$HOME per test, and
// an env lookup per walked directory is nothing next to the ReadDir beside it.
func goModCacheDir() string {
	if c := os.Getenv("GOMODCACHE"); c != "" {
		return filepath.Clean(c)
	}
	gopath := os.Getenv("GOPATH")
	if gopath != "" {
		gopath = filepath.SplitList(gopath)[0]
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gopath = filepath.Join(home, "go")
	}
	return filepath.Join(gopath, "pkg", "mod")
}

// skipDiscoveryDir is the shared per-directory gate every Discover* walk in
// this package uses: the always-irrelevant noise directories, plus the Go
// module cache. The module cache holds read-only, checksum-verified copies of
// PUBLIC module source — a `.env` there is some dependency's test fixture,
// never this machine's secret, and rewriting it would corrupt the cache
// (`go mod verify` starts failing) on a tree the go tool treats as immutable.
// A real `jit migrate home` plan on this repo's own dev machine included
// gotenv's .env fixtures — exactly the rewrite this exists to prevent.
func skipDiscoveryDir(path, name string) bool {
	if migrateNoiseDirs[name] {
		return true
	}
	cache := goModCacheDir()
	return cache != "" && path == cache
}

// EnvFileMigration describes one .env file converted into a profile and
// vault secrets, plus — unless it's a backup-suffixed file, see Mounted
// — a live mount.
type EnvFileMigration struct {
	EnvPath     string
	ProfileName string
	ProfilePath string
	Variables   []string
	BackupPath  string
	// NamespaceMovedFrom is the profile name this file WOULD have used had
	// the vault not already held another migration's secret at one of its
	// paths (claimNamespace, GAPS.md #55) — "" in the common case where
	// ProfileName is the derived name itself. Callers should surface a
	// non-empty value loudly: a vault namespace that doesn't match the
	// project's own name is exactly the kind of surprise that reads as a
	// bug when it goes unexplained.
	NamespaceMovedFrom string
	// Mounted is false for a backup-suffixed file (GAPS.md #34) — its
	// secrets still moved into the vault above, but EnvPath was replaced
	// with a pointer file instead of a live-mounted FIFO, since nothing
	// reads a .bak/.old/.orig/.backup file live. Callers must skip
	// mount.AddMount/the reveal-hook wiring/the separate .pointers
	// companion when this is false — EnvPath already IS the pointer
	// file at that point.
	Mounted bool
}

// DiscoverEnvFiles walks root (a project directory, not the whole home
// directory — real mutation is scoped narrower than jit audit/jit
// migrate --dry-run's whole-machine preview, deliberately: rewriting .env
// files across every unrelated project under $HOME in one command would be
// a much bigger blast radius than "fix the project I'm standing in").
// Skips template files (same convention as jit audit) and anything
// already a named pipe (an earlier migration's mount — reading it would
// block forever waiting for a writer that only jit agent provides).
func DiscoverEnvFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A permission-denied (or similar) error partway through a
			// tree — never the root itself failing outright — must not
			// abort the whole scan. This is routine under a real $HOME:
			// ~/.Trash and various macOS-TCC-protected app-sandbox
			// directories under ~/Library return EPERM without Full Disk
			// Access, and jit migrate home walks all of $HOME (GAPS.md
			// #26). SkipDir tells WalkDir not to descend further into
			// whatever this path was; every other branch keeps going.
			if path == root {
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
		name := d.Name()
		if !envFileNamePattern.MatchString(name) {
			return nil
		}
		if isJitGeneratedEnvArtifact(name) {
			return nil
		}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
		if envTemplateSuffixes[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			// Same tolerance as above, for a single file's own stat
			// failing (e.g. a race with deletion) — skip just this file.
			return nil
		}
		if info.Mode()&fs.ModeNamedPipe != 0 {
			return nil // already mounted
		}
		// A backup-suffixed file (.env.bak etc.) that an earlier migrate
		// replaced in place with pointer content keeps its original name, so
		// the name check above can't skip it — recognize it by content and
		// leave it alone, or a second run would migrate its jit://vault/...
		// pointers as if they were real secrets (GAPS.md #66). Safe to read:
		// the FIFO guard above already ruled out a live mount.
		if LooksLikePointerContent(path) {
			return nil
		}
		found = append(found, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	sort.Strings(found)
	return found, nil
}

// ApplyEnvFile converts one real .env file into a profile manifest (every
// variable mapped to a vault path), moves each value into v's vault, then
// replaces the physical file with a FIFO (mount.CreateFIFO) — literally
// RFC.md Pillar III Tier 3's own description of what jit migrate does to
// a .env file. Order matters for safety: every vault write and the profile
// manifest write happen BEFORE the original file is destroyed, so a
// failure partway through never leaves the source file gone with nothing
// usable in its place.
func ApplyEnvFile(v *vault.Vault, profilesRoot, envPath string) (EnvFileMigration, error) {
	values, varNames, unparsed, err := parseEnvFile(envPath)
	if err != nil {
		return EnvFileMigration{}, fmt.Errorf("parsing %s: %w", envPath, err)
	}
	// A line this parser doesn't understand is a hard stop, never a skip:
	// migration's next step destroys the original file, so "I silently
	// dropped what I couldn't parse" turns directly into data loss (a
	// variable the app depended on missing from the vault, the profile,
	// and the mount, with nothing saying why). Line numbers only — a
	// line that failed to parse may still contain a real secret, and this
	// error lands in terminal scrollback.
	if len(unparsed) > 0 {
		return EnvFileMigration{}, fmt.Errorf(
			"%s: %d line(s) could not be parsed as KEY=value (line %s), stopping before touching this file so nothing is silently dropped; fix or comment out those lines and re-run",
			envPath, len(unparsed), joinLineNumbers(unparsed))
	}
	if len(values) == 0 {
		return EnvFileMigration{}, fmt.Errorf("%s has no active KEY=value lines to migrate", envPath)
	}

	// claimNamespace both loads whatever the target profile already holds
	// (merge, never overwrite outright — matching ApplyShellConfig/
	// ApplyMCPConfig's convention: even a legitimate re-run must never
	// silently drop an earlier variable's entry, which is exactly how a
	// real vault secret got orphaned in the incident deriveProfileName's
	// doc comment recounts) AND guards against the machine-global vault
	// hazard a per-store manifest merge can't see: another project whose
	// files derived the same profile name already owning one of these
	// vault paths (GAPS.md #55). In that case the whole file moves to the
	// first free "<name>-2"/"-3" namespace instead of silently
	// overwriting a live secret.
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveProfileName(profilesRoot, envPath), varNames)
	if err != nil {
		return EnvFileMigration{}, err
	}

	for _, name := range varNames {
		secretPath := profileName + "/" + name
		if err := v.Set(secretPath, []byte(values[name])); err != nil {
			return EnvFileMigration{}, fmt.Errorf("storing %s in vault: %w", name, err)
		}
		entries[name] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, varNames); err != nil {
		return EnvFileMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	// Backup before rewrite, matching every other category in this
	// package (GAPS.md #32) — .env used to be the one exception, on the
	// reasoning that git history is the safety net instead (RFC.md B7).
	// That reasoning only holds if the file was ever actually committed;
	// a .env that never was (a common, even recommended practice, since
	// these files usually hold real secrets) had NO recovery path at all
	// if parseEnvFile missed a line, a value needed correcting, or the
	// FIFO swap failed partway. A real incident made the gap concrete: a
	// migrate discovery bug (GAPS.md #30) destroyed several files with
	// no way to recover their exact original content short of git
	// history that, in that case, happened to exist — it wouldn't have
	// for an untracked .env. Backed up into the vault, not a plaintext
	// sibling file (GAPS.md #33) — see backupSecretFile's own doc
	// comment for why a plaintext backup of a secret defeats the point
	// of migrating it off disk in the first place.
	backupPath, err := backupSecretFile(v, envPath)
	if err != nil {
		return EnvFileMigration{}, fmt.Errorf("backing up %s: %w", envPath, err)
	}

	// A backup-suffixed file (.bak/.old/.orig/.backup, GAPS.md #34) is
	// never read live by anything — nothing loads DATABASE_URL from
	// ".env.bak". Converting it into a FIFO the same way as .env itself
	// gains nothing and just creates a dead pipe that hangs any editor
	// or tool that tries to open it (a real, reported problem — closing
	// VS Code hung on "discarding backups" with one of these open,
	// since named pipes block on read with no writer connected). Its
	// secrets still move into the vault above like any other .env
	// finding; the file itself gets replaced with a safe, readable
	// pointer file instead of becoming a mount at all.
	mounted := !IsEnvBackupOnlySuffix(filepath.Base(envPath))
	if mounted {
		if err := mount.CreateFIFO(envPath); err != nil {
			return EnvFileMigration{}, fmt.Errorf("mounting %s: %w", envPath, err)
		}
	} else if err := ReplaceWithPointerFile(envPath, entries, varNames); err != nil {
		return EnvFileMigration{}, fmt.Errorf("replacing %s with a pointer file: %w", envPath, err)
	}

	return EnvFileMigration{
		EnvPath:            envPath,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          varNames,
		BackupPath:         backupPath,
		Mounted:            mounted,
		NamespaceMovedFrom: movedFrom,
	}, nil
}

// deriveProfileName names the resulting profile after envPath's location
// relative to profilesRoot, e.g. "services/api/.env" -> "services-api",
// or after profilesRoot's own directory name for a root ".env" — a
// project at ~/Documents/notion derives "notion" — PLUS envPath's own
// variant suffix when it has one, e.g. "services/api/.env.local" ->
// "services-api-local", notion's ".env.bak" -> "notion-bak".
//
// The directory-basename rule replaced a literal "root" fallback
// (GAPS.md #55): a project's root .env is the overwhelmingly common
// case, and since the vault is machine-global while this name prefixes
// every vault path, EVERY project migrated from its own root used to
// pile into one flat, shared root/<VAR> namespace — illegible in
// `jit vault list` (whose secret came from where?) and one shared
// variable name away from one project's migration silently overwriting
// another's live secret. Profiles named "root" that already exist keep
// working untouched (manifests store full vault paths; nothing
// re-derives a name for an already-migrated file). Two directories can
// still share a basename — ApplyEnvFile's claimNamespace call is the
// layer that catches what a naming rule alone can't.
//
// The variant suffix is not cosmetic — dropping it was a real, reported
// incident. Before it was added, EVERY .env-family file in the same
// directory (.env, .env.local, .env.bak, ...) derived the exact same
// profile name and therefore the exact same vault path per variable
// name, even though each becomes its own independent live-mounted FIFO.
// writeProfileManifest overwrites rather than merges (see ApplyEnvFile's
// own merge fix below, added for the same incident), so migrating a
// second file in that directory silently erased the first file's
// profile entries for any variable name it didn't also define, and
// SILENTLY OVERWROTE THE VAULT VALUE for any variable name the two files
// happened to share — even though the two FIFOs are supposed to serve
// each file's own distinct content. Confirmed on a real machine: a
// directory with .env/.env.bak/.env.local ended up with one shared
// profile whose vault entries no longer matched what any individual
// mount's own original file used to contain, and a leftover
// `root/API_KEY.enc` vault secret was orphaned entirely (correctly
// written once, then silently dropped from the profile manifest by a
// later file's write). A bare ".env" keeps its unsuffixed name for full
// backward compatibility with anything already migrated.
func deriveProfileName(profilesRoot, envPath string) string {
	rel, err := filepath.Rel(profilesRoot, filepath.Dir(envPath))
	dirPart := ""
	if err == nil && rel != "." {
		dirPart = sanitizeNamePart(strings.ReplaceAll(filepath.ToSlash(rel), "/", "-"))
	}
	if dirPart == "" {
		dirPart = sanitizeNamePart(filepath.Base(profilesRoot))
	}
	if dirPart == "" {
		// A degenerate profilesRoot ("/", a name that's all symbols) —
		// keep the old literal as the last-resort fallback.
		dirPart = "root"
	}
	if suffix := envFileVariantSuffix(filepath.Base(envPath)); suffix != "" {
		return dirPart + "-" + suffix
	}
	return dirPart
}

// envFileVariantSuffix returns the part of an .env-family filename after
// ".env" itself, sanitized into a profile-name-safe token — "" for a
// bare ".env" (envFileNamePattern guarantees name is always ".env" or
// ".env.<something>", so TrimPrefix always succeeds). E.g.
// ".env.local" -> "local", ".env.bak" -> "bak", ".env.local.bak" ->
// "local-bak".
func envFileVariantSuffix(name string) string {
	suffix := strings.TrimPrefix(strings.TrimPrefix(name, ".env"), ".")
	return strings.ReplaceAll(suffix, ".", "-")
}

// envExportPrefix matches dotenv's optional `export ` prefix — both
// python-dotenv and godotenv accept `export KEY=value` in a .env file, and
// real files use it (it lets the same file be `source`d by a shell). The
// old parser didn't, which silently DROPPED the variable from the vault,
// the profile, and the mount: the app lost it with no warning, on a
// command whose next step destroys the original file.
var envExportPrefix = regexp.MustCompile(`^export\s+`)

// parseEnvFile parses path's KEY=value entries, returning alongside them
// the 1-based line numbers of every non-empty, non-comment line it could
// NOT parse. Callers on a destructive path (ApplyEnvFile) must treat a
// non-empty unparsed list as a hard stop: this parser deciding it "didn't
// understand" a line while migration proceeds anyway is exactly how a real
// value gets silently dropped or corrupted (multiline PEM blocks in .env
// files were the concrete case — the first line was stored as a corrupt
// fragment and the rest discarded).
//
// Understood syntax, matching the common ground between python-dotenv and
// godotenv: optional `export ` prefix; bare values (kept verbatim);
// single-quoted values (literal, no escapes); double-quoted values with
// \" \\ \n \r \t escapes; and quoted values spanning multiple lines
// (newlines inside the quotes preserved). Content after a closing quote
// on the same line (e.g. an inline comment) is ignored, matching those
// loaders' own tolerance.
// It also returns the variable names in source-file order (first
// occurrence for a name assigned twice — dotenv's last-wins applies to
// the value only), which is what lets the live mount and the manifest
// keep the file's own order instead of alphabetizing (issue #4).
func parseEnvFile(path string) (map[string]string, []string, []int, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from DiscoverEnvFiles' own filesystem walk, not external input
	if err != nil {
		return nil, nil, nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	values := make(map[string]string)
	var names []string
	var unparsed []int
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		startLine := i + 1

		m := envLinePattern.FindStringSubmatch(envExportPrefix.ReplaceAllString(line, ""))
		if m == nil {
			unparsed = append(unparsed, startLine)
			continue
		}

		value, consumed, ok := parseEnvValue(strings.TrimSpace(m[2]), lines[i+1:])
		if !ok {
			// An opening quote with no closing quote anywhere below it —
			// report the line that opened it, not everything it swallowed.
			unparsed = append(unparsed, startLine)
			continue
		}
		i += consumed
		if _, dup := values[m[1]]; !dup {
			names = append(names, m[1])
		}
		values[m[1]] = value
	}
	return values, names, unparsed, nil
}

// parseEnvValue interprets raw (everything after the "=" on an entry's
// first line). rest is the raw lines below, for a quoted value that spans
// several; consumed reports how many of them the value used up. ok is
// false only for an unterminated quote.
func parseEnvValue(raw string, rest []string) (value string, consumed int, ok bool) {
	if raw == "" {
		return "", 0, true
	}
	quote := raw[0]
	if quote != '"' && quote != '\'' {
		// Bare value: kept verbatim to the end of the line, matching the
		// old parser exactly (including any '#" — inline-comment stripping
		// for bare values varies between loaders, and guessing wrong here
		// silently truncates a real value).
		return raw, 0, true
	}

	var b strings.Builder
	body := raw[1:]
	for {
		if end, found := findClosingQuote(body, quote); found {
			b.WriteString(body[:end])
			v := b.String()
			if quote == '"' {
				v = unescapeDoubleQuoted(v)
			}
			return v, consumed, true
		}
		if consumed >= len(rest) {
			return "", 0, false // unterminated quote, EOF before it closed
		}
		b.WriteString(body)
		b.WriteByte('\n')
		body = rest[consumed]
		consumed++
	}
}

// findClosingQuote returns the index of the first closing quote in s. A
// single-quoted value has no escape syntax (first ' always closes it); in
// a double-quoted value a backslash escapes the next character, so \" does
// not close.
func findClosingQuote(s string, quote byte) (int, bool) {
	if quote == '\'' {
		i := strings.IndexByte(s, '\'')
		return i, i >= 0
	}
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		switch s[i] {
		case '\\':
			escaped = true
		case '"':
			return i, true
		}
	}
	return -1, false
}

// unescapeDoubleQuoted expands the escape sequences double-quoted dotenv
// values support (\" \\ \n \r \t) — an unknown sequence is kept literal,
// backslash included, rather than guessed at.
func unescapeDoubleQuoted(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// joinLineNumbers renders unparsed-line numbers for an error message,
// e.g. "3" or "3, 7, 12".
func joinLineNumbers(nums []int) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ", ")
}

func unquoteEnvValue(v string) string {
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}

// order is the source file's own variable order, persisted into the
// manifest so the mount can serve it back faithfully (issue #4) — see
// profile.MarshalOrdered. nil means alphabetical, the old behavior every
// non-.env category keeps.
func writeProfileManifest(path string, p profile.Profile, order []string) error {
	data, err := profile.MarshalOrdered(p, order)
	if err != nil {
		return err
	}
	// Atomic + fsynced, same as every vault write: the manifest is what
	// maps a rewritten file's variables back to their vault paths, so a
	// half-written one at the moment the source file is destroyed would
	// orphan every secret it covered.
	return vault.AtomicWriteFile(path, data)
}
