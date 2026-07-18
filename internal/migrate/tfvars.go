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

	"github.com/jitpass/jit/internal/audit"
	"github.com/jitpass/jit/internal/vault"
)

// Terraform tfvars migration: the automated-fix half of jit audit's IaC
// variable-file finding (internal/audit/iac.go, FindingTypeIACVariableFile),
// for the Terraform side only — the Kubernetes secret(s).yaml side stays
// detection-only, since that file's consumer is a cluster/CI pipeline no
// local rewrite can serve.
//
// The mechanism leans on Terraform's own variable precedence (verified
// against developer.hashicorp.com/terraform/language/values/variables,
// 2026-07-18): TF_VAR_<name> environment variables rank below every tfvars
// file but above a variable's default. So moving a secret value into the
// vault and DELETING its assignment from the file is exactly what activates
// env-var delivery — `jit run --profile <p> -- terraform apply` injects the
// values and terraform picks them up as if the file still held them, while
// a bare `terraform apply` prompts for the missing variable (a loud,
// recoverable failure) instead of silently using a wrong value. Terraform
// also ignores TF_VAR_ vars with no matching variable block, so injecting a
// whole profile is harmless even when some entries go stale.
//
// Unlike shellconfig's per-file profiles, all tfvars files in one directory
// feed the SAME terraform root and resolve a doubly-assigned variable by
// file precedence (terraform.tfvars lowest, then *.auto.tfvars in lexical
// order). ApplyTfvarsDir therefore migrates a whole directory into one
// profile, processing files in ascending precedence so the value terraform
// would actually have used is what lands in the vault.
//
// v1 scope, deliberately narrow: only top-level, one-line
// `name = "simple string"` assignments migrate. Heredocs, multi-line
// strings, maps, lists, numbers, and .tfvars.json stay untouched, and a
// secret-shaped name whose value has one of those shapes is reported as
// skipped rather than failing the file — complex types would need JSON
// encoding on the env side anyway (Terraform's own documented rule), and
// silently mangling a value this parser only half-understands is the
// failure mode every parser in this package is built to refuse.

// tfvarsFileName mirrors internal/audit/iac.go's own detection predicate —
// kept as a small copy, matching this package's existing convention for
// audit detection constants (see apply.go's envFileNamePattern comment).
func tfvarsFileName(name string) bool {
	return name == "terraform.tfvars" || strings.HasSuffix(name, ".auto.tfvars")
}

// tfvarsAssignPattern matches a top-level HCL assignment's name and raw
// right-hand side. HCL identifiers may contain hyphens; tfvarsEnvSafeName
// below is what gates which of those can actually become an env var.
var tfvarsAssignPattern = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$`)

// tfvarsSimpleString matches a right-hand side that is one complete
// double-quoted string (backslash escapes allowed inside), optionally
// followed by a trailing # or // comment.
var tfvarsSimpleString = regexp.MustCompile(`^"((?:[^"\\]|\\.)*)"(?:\s*(?:#|//).*)?$`)

// tfvarsEnvSafeName gates which variable names can be delivered as
// TF_VAR_<name> through a shell: a hyphenated name is legal HCL but can't
// survive `export TF_VAR_a-b=...`, so it's skipped, not migrated.
var tfvarsEnvSafeName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tfvarsHeredocPattern spots a heredoc opener (<<EOT / <<-EOT) on an
// assignment's right-hand side, outside any string.
var tfvarsHeredocPattern = regexp.MustCompile(`<<-?([A-Za-z_][A-Za-z0-9_]*)`)

// TfvarsEnvPrefix is Terraform's own env-var convention for variable
// values: TF_VAR_<variable name>, case-sensitive.
const TfvarsEnvPrefix = "TF_VAR_"

// TfvarsMigration describes what jit migrate did to one directory's
// tfvars files (one profile per directory — see the package comment above
// on why the directory, not the file, is the migration unit).
type TfvarsMigration struct {
	Dir         string
	Files       []string
	Backups     []string // vault backup path per entry of Files, same order
	ProfileName string
	ProfilePath string
	// Variables are the profile's env-var names (TF_VAR_<name>), sorted.
	Variables []string
	// SkippedComplex lists secret-shaped assignments left in place because
	// their value isn't a simple one-line string this migration handles
	// ("<name> in <file>"), so the caller can say so out loud.
	SkippedComplex []string
	// NamespaceMovedFrom mirrors EnvFileMigration's field: non-empty when
	// claimNamespace had to bump the profile name off its derived base.
	NamespaceMovedFrom string
}

// tfvarsMatch is one migratable assignment, keyed by its 0-based line
// index so the rewrite step removes exactly that line without re-parsing.
type tfvarsMatch struct {
	Index int
	Name  string
	Value string // unescaped, the value terraform would have seen
}

// DiscoverTfvarsFiles walks root for terraform.tfvars / *.auto.tfvars
// files containing at least one migratable secret-shaped assignment. Same
// walk tolerances as DiscoverEnvFiles: a permission error below root skips
// that branch, noise directories and the Go module cache are skipped, and
// a named pipe is left alone. Idempotent by construction: a file whose
// secret assignments were already migrated has none left to match, so it
// simply isn't returned again.
func DiscoverTfvarsFiles(root string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
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
		if !tfvarsFileName(d.Name()) {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil // race with deletion — skip just this file
		}
		if info.Mode()&fs.ModeNamedPipe != 0 {
			return nil // reading a FIFO would block forever
		}
		lines, rerr := readLines(path)
		if rerr != nil {
			return nil // unreadable file — skip it, don't fail the whole walk
		}
		matches, _ := parseTfvarsLines(lines)
		if len(matches) > 0 {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", root, err)
	}
	sort.Strings(found)
	return found, nil
}

// GroupTfvarsByDir groups discovered tfvars paths by their directory,
// preserving first-seen directory order — the caller-facing shape of "one
// terraform root, one migration".
func GroupTfvarsByDir(paths []string) (dirs []string, byDir map[string][]string) {
	byDir = map[string][]string{}
	for _, p := range paths {
		dir := filepath.Dir(p)
		if _, seen := byDir[dir]; !seen {
			dirs = append(dirs, dir)
		}
		byDir[dir] = append(byDir[dir], p)
	}
	return dirs, byDir
}

// ApplyTfvarsDir migrates every secret-shaped simple assignment across
// dir's tfvars files into one vault profile, then redacts those lines from
// each file. Order matters for safety, same as every Apply* here: all
// vault writes and the profile manifest land before any source file is
// touched, and each file is backed up (encrypted, into the vault) before
// its rewrite.
func ApplyTfvarsDir(v *vault.Vault, profilesRoot, dir string, files []string) (TfvarsMigration, error) {
	ordered := sortTfvarsByPrecedence(files)

	type parsedFile struct {
		path    string
		lines   []string
		matches []tfvarsMatch
	}
	var parsed []parsedFile
	values := map[string]string{}
	var skipped []string
	for _, path := range ordered {
		lines, err := readLines(path)
		if err != nil {
			return TfvarsMigration{}, fmt.Errorf("reading %s: %w", path, err)
		}
		matches, skippedNames := parseTfvarsLines(lines)
		for _, name := range skippedNames {
			skipped = append(skipped, fmt.Sprintf("%s in %s", name, filepath.Base(path)))
		}
		if len(matches) == 0 {
			continue
		}
		parsed = append(parsed, parsedFile{path: path, lines: lines, matches: matches})
		// ordered is ascending terraform precedence, so a later file's
		// value overwriting an earlier one's here reproduces exactly which
		// value terraform itself would have used.
		for _, m := range matches {
			values[m.Name] = m.Value
		}
	}
	if len(values) == 0 {
		return TfvarsMigration{}, fmt.Errorf("%s has no migratable secret-shaped variable assignments", dir)
	}

	envNames := make([]string, 0, len(values))
	for name := range values {
		envNames = append(envNames, TfvarsEnvPrefix+name)
	}
	sort.Strings(envNames)

	// claimNamespace treats "manifest already maps this var to this exact
	// vault path" as the re-run case, so the vault leaf and the manifest
	// key must be the same string — hence TF_VAR_<name> on both sides.
	profileName, profilePath, entries, movedFrom, err := claimNamespace(v, profilesRoot, deriveTfvarsProfileName(profilesRoot, dir), envNames)
	if err != nil {
		return TfvarsMigration{}, err
	}

	for _, envName := range envNames {
		secretPath := profileName + "/" + envName
		if err := v.Set(secretPath, []byte(values[strings.TrimPrefix(envName, TfvarsEnvPrefix)])); err != nil {
			return TfvarsMigration{}, fmt.Errorf("storing %s in vault: %w", envName, err)
		}
		entries[envName] = secretPath
	}

	if err := writeProfileManifest(profilePath, entries, nil); err != nil {
		return TfvarsMigration{}, fmt.Errorf("writing profile %s: %w", profilePath, err)
	}

	result := TfvarsMigration{
		Dir:                dir,
		ProfileName:        profileName,
		ProfilePath:        profilePath,
		Variables:          envNames,
		SkippedComplex:     skipped,
		NamespaceMovedFrom: movedFrom,
	}
	for _, pf := range parsed {
		backupPath, err := backupSecretFile(v, pf.path)
		if err != nil {
			return TfvarsMigration{}, fmt.Errorf("backing up %s: %w", pf.path, err)
		}
		rewritten := rewriteTfvarsLines(pf.lines, pf.matches, profileName)
		if err := os.WriteFile(pf.path, []byte(strings.Join(rewritten, "\n")), 0o600); err != nil {
			return TfvarsMigration{}, fmt.Errorf("writing %s: %w", pf.path, err)
		}
		result.Files = append(result.Files, pf.path)
		result.Backups = append(result.Backups, backupPath)
	}
	return result, nil
}

// sortTfvarsByPrecedence orders dir-mates in ascending terraform
// precedence: terraform.tfvars first, then *.auto.tfvars in lexical order
// (Terraform's own documented resolution order for these files).
func sortTfvarsByPrecedence(files []string) []string {
	out := append([]string(nil), files...)
	sort.Slice(out, func(i, j int) bool {
		bi, bj := filepath.Base(out[i]), filepath.Base(out[j])
		if (bi == "terraform.tfvars") != (bj == "terraform.tfvars") {
			return bi == "terraform.tfvars"
		}
		return bi < bj
	})
	return out
}

// deriveTfvarsProfileName mirrors deriveProfileName's directory naming
// (services/api -> "services-api", the root itself -> its basename), plus
// a fixed "-tfvars" suffix so a project's tfvars profile can never collide
// with the same project's .env profile — without the suffix both would
// derive the identical base and claimNamespace would bump one of them to a
// confusing "-2" name.
func deriveTfvarsProfileName(profilesRoot, dir string) string {
	rel, err := filepath.Rel(profilesRoot, dir)
	dirPart := ""
	if err == nil && rel != "." {
		dirPart = sanitizeNamePart(strings.ReplaceAll(filepath.ToSlash(rel), "/", "-"))
	}
	if dirPart == "" {
		dirPart = sanitizeNamePart(filepath.Base(profilesRoot))
	}
	if dirPart == "" {
		dirPart = "root"
	}
	return dirPart + "-tfvars"
}

// parseTfvarsLines scans lines for migratable assignments: top-level (not
// inside a { } / [ ] value or a heredoc), secret-shaped name
// (audit.LooksLikeSecretKey, the same gate shellconfig uses), env-safe
// name, and a simple one-line double-quoted string value. A secret-shaped
// top-level assignment failing the value or name gate is returned in
// skipped so callers can surface it; everything else is left alone
// silently. Only lines this parser fully understands are ever removed, so
// a wrong guess here can't corrupt a value — it can only leave one behind.
func parseTfvarsLines(lines []string) (matches []tfvarsMatch, skipped []string) {
	depth := 0
	heredocTerm := ""
	for i, line := range lines {
		if heredocTerm != "" {
			if strings.TrimSpace(line) == heredocTerm {
				heredocTerm = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if depth == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") && !audit.IsAlreadyMasked(trimmed) {
			if m := tfvarsAssignPattern.FindStringSubmatch(line); m != nil && audit.LooksLikeSecretKey(m[1]) {
				name, rhs := m[1], m[2]
				if sm := tfvarsSimpleString.FindStringSubmatch(rhs); sm != nil && tfvarsEnvSafeName.MatchString(name) {
					if value, ok := unescapeTfvarsString(sm[1]); ok {
						if value != "" {
							matches = append(matches, tfvarsMatch{Index: i, Name: name, Value: value})
						}
						// A matched simple-string line can't open a brace,
						// bracket, or heredoc — no state to update.
						continue
					}
				}
				skipped = append(skipped, name)
			}
		}
		depth, heredocTerm = scanTfvarsLineState(line, depth)
	}
	return matches, skipped
}

// scanTfvarsLineState updates the brace/bracket depth and heredoc state
// after one line: braces and brackets count only outside double-quoted
// strings and comments, and a heredoc opener swallows the rest of the
// line. Single quotes are not string delimiters in HCL.
func scanTfvarsLineState(line string, depth int) (int, string) {
	inString := false
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case '#':
			return depth, ""
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return depth, ""
			}
		case '<':
			if m := tfvarsHeredocPattern.FindStringSubmatch(line[i:]); m != nil && strings.HasPrefix(line[i:], m[0]) {
				return depth, m[1]
			}
		}
	}
	return depth, ""
}

// unescapeTfvarsString expands the escapes a migratable HCL string may
// contain (\" \\ \n \r \t). Anything else — \uXXXX, template
// interpolation (${...} / %{...}), an unknown escape — reports not-ok, and
// the assignment is skipped rather than half-understood.
func unescapeTfvarsString(s string) (string, bool) {
	if strings.Contains(s, "${") || strings.Contains(s, "%{") {
		return "", false
	}
	if !strings.ContainsRune(s, '\\') {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(s) {
			return "", false
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
			return "", false
		}
	}
	return b.String(), true
}

// rewriteTfvarsLines removes each match's line and inserts, at the first
// removed position, a comment block naming what moved and how to run
// terraform now. The block is informational (nothing parses it), so a
// rare second migration of the same file simply adds its own accurate
// block rather than trying to merge into a stale one.
func rewriteTfvarsLines(lines []string, matches []tfvarsMatch, profileName string) []string {
	removeIdx := make(map[int]bool, len(matches))
	var names []string
	for _, m := range matches {
		removeIdx[m.Index] = true
		names = append(names, m.Name)
	}
	out := make([]string, 0, len(lines))
	inserted := false
	for i, line := range lines {
		if removeIdx[i] {
			if !inserted {
				out = append(out,
					"# jit migrate moved the secret value(s) below into the jit vault:",
					"#   "+strings.Join(names, ", "),
					"# terraform now reads them as TF_VAR_ environment variables, so run it through jit:",
					fmt.Sprintf("#   jit run --profile %s -- terraform apply", profileName),
				)
				inserted = true
			}
			continue
		}
		out = append(out, line)
	}
	return out
}
