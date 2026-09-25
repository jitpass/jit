// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jitpass/jit/internal/launchers"
	"github.com/jitpass/jit/internal/termtext"
	"github.com/jitpass/jit/internal/vault"
)

// Ignoring a doctor finding (design/doctor-repair.md, "Ignore").
//
// Some findings describe a state the user has decided to keep: a clisso app
// they never log into, a config they know is gone. Without a way to say so,
// doctor exits 2 on every run and the one new problem hides among the ones
// the reader stopped reading. `jit doctor ignore` takes a finding out of the
// counts — the exit code, ok, --strict, the "N problems found" line — and
// folds it into one [ignored] line at the end of the report.
//
// The unit is (kind, name): the JSON kind, and the subject a row leads with
// as the user sees it (ignoreName). Every finding of one kind that shares a
// name is one unit, so a profile's five [missing] rows are ignored together.
//
// An ignore records a fingerprint of what the unit says (ignoreFingerprinter).
// When that changes — the ~/.aws/config entry is edited, another secret goes
// missing — the entry no longer matches, and the finding shows and counts
// again, with a └ line saying it was ignored. Nothing is pruned: an entry
// whose finding went away stays harmless until `unignore` removes it, since
// a finding this run can't see (another directory's project profile, the
// --1password sweep) is not a finding that stopped existing.
//
// Doctor stays read-only: it reads ~/.jit/doctor-ignore.json and never
// writes it. `jit doctor ignore` and `jit doctor unignore` are the writers.

const doctorIgnoreStoreVersion = 1

// doctorIgnorePath is the store: under ~/.jit beside wrap.json, since what
// is ignored is a per-user decision about this home, not vault state.
func doctorIgnorePath(home string) string {
	return filepath.Join(home, ".jit", "doctor-ignore.json")
}

// doctorIgnoreEntry is one ignored unit.
type doctorIgnoreEntry struct {
	Kind        checkKind `json:"kind"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	// Since is the local date it was ignored, or last re-ignored after it
	// changed.
	Since string `json:"since"`
}

type doctorIgnoreStore struct {
	Version int                 `json:"version"`
	Entries []doctorIgnoreEntry `json:"entries"`
}

// doctorIgnoreNow is the clock `ignore` stamps Since with; a var for tests.
var doctorIgnoreNow = time.Now

// loadDoctorIgnores reads the store. A missing file is an empty store; an
// unreadable or malformed one is an error, which the writers refuse on
// rather than overwrite.
func loadDoctorIgnores(home string) (doctorIgnoreStore, error) {
	st := doctorIgnoreStore{Version: doctorIgnoreStoreVersion}
	path := doctorIgnorePath(home)
	data, err := os.ReadFile(path) // #nosec G304 -- fixed name under the user's own ~/.jit
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return doctorIgnoreStore{}, fmt.Errorf("%s won't parse: %w", shortPath(path), err)
	}
	if st.Version > doctorIgnoreStoreVersion {
		return doctorIgnoreStore{}, fmt.Errorf("%s was written by a newer jit (version %d)", shortPath(path), st.Version)
	}
	return st, nil
}

// saveDoctorIgnores writes the store atomically at 0600, entries sorted so
// the file diffs cleanly.
func saveDoctorIgnores(home string, st doctorIgnoreStore) error {
	st.Version = doctorIgnoreStoreVersion
	if st.Entries == nil {
		st.Entries = []doctorIgnoreEntry{}
	}
	sort.SliceStable(st.Entries, func(i, j int) bool {
		if st.Entries[i].Kind != st.Entries[j].Kind {
			return st.Entries[i].Kind < st.Entries[j].Kind
		}
		return st.Entries[i].Name < st.Entries[j].Name
	})
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return vault.AtomicWriteFile(doctorIgnorePath(home), append(data, '\n'))
}

// doctorIgnoreEntriesForReport is the report's lenient read: a store that
// won't load ignores nothing — the report then shows more, never less —
// and says so on stderr, which keeps a --format json stdout clean.
func doctorIgnoreEntriesForReport(errOut io.Writer) []doctorIgnoreEntry {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	st, err := loadDoctorIgnores(home)
	if err != nil {
		fmt.Fprintf(errOut, "jit doctor: nothing is ignored this run: %v\n", err)
		return nil
	}
	return st.Entries
}

// doctorIgnoreRef is a finding's `ignore` field: the unit, and the argv
// that ignores it.
type doctorIgnoreRef struct {
	Kind checkKind `json:"kind"`
	Name string    `json:"name"`
	Argv []string  `json:"argv"`
}

// doctorUnignoreRef is an ignored finding's `unignore` field.
type doctorUnignoreRef struct {
	Argv []string `json:"argv"`
}

// ignoreName is the name a finding is ignored by: the profile for the
// profile and record kinds, the file for a pointer, mount or recorded jit
// path, the check for a wrap row, and the section for a section whose rows
// have no subject of their own ([backup], [orphan], [storage format]).
func ignoreName(f checkFinding) string {
	switch f.Kind {
	case kindParse, kindNotFound, kindMissing, kindCorrupt, kindBadPath, kindVaultError,
		kindShadowed, kindMCP, kindMCPNested, kindProfileMissing, kindNotLoggedIn,
		kindConfigDeleted, kindConfigNotRecorded, kindNoKnownTool:
		if f.Profile != "" {
			return f.Profile
		}
	case kindPointerMissing:
		if f.File != "" {
			return shortPath(f.File)
		}
	case kind1PasswordLink:
		if f.Path != "" {
			return f.Path
		}
	case kindOriginGone, kindInstall, kindJitPath, kindJitPathUpgrade, kindMount, kindMountStale, kindMountMoved, kindMountUnregistered:
		if f.Path != "" {
			return shortPath(f.Path)
		}
	case kindWrap, kindWrapEnv:
		// wrapFindings writes "<check>: <detail>"; the check is the tool
		// or the shim-dir/PATH/rc-file line the row is about.
		if name, _, ok := strings.Cut(f.Detail, ": "); ok && name != "" {
			return name
		}
	}
	return ignoreSectionName(f.Kind)
}

// ignoreSectionName is a section as a name: its header without brackets,
// hyphenated ("[storage format]" is storage-format).
func ignoreSectionName(k checkKind) string {
	return normalizeIgnoreWord(findingLabel(checkFinding{Kind: k}))
}

// normalizeIgnoreWord folds the ways a section or kind can be typed —
// "[config deleted]", "config deleted", config_deleted, Config-Deleted —
// to one hyphenated form.
func normalizeIgnoreWord(s string) string {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "[]"))
	s = strings.NewReplacer(":", " ", "_", " ", "-", " ").Replace(s)
	return strings.Join(strings.Fields(s), "-")
}

// dashKind is a kind as a --kind value in text: config-deleted.
func dashKind(k checkKind) string { return strings.ReplaceAll(string(k), "_", "-") }

// ignoreKindText is a kind as the success and ambiguity lines name it: its
// header without brackets.
func ignoreKindText(k checkKind) string {
	return strings.Trim(findingLabel(checkFinding{Kind: k}), "[]")
}

// parseIgnoreKind reads --kind: the JSON kind with _ or -, or the section.
func parseIgnoreKind(s string) (checkKind, error) {
	n := normalizeIgnoreWord(s)
	for _, k := range allCheckKinds {
		if n == dashKind(k) || n == ignoreSectionName(k) {
			return k, nil
		}
	}
	return "", fmt.Errorf("--kind %q is not a doctor finding kind", s)
}

// ignoreNameMatches reports whether input names the unit (kind, name): the
// name itself, a file in ~/ or absolute form, or a section however typed.
func ignoreNameMatches(kind checkKind, name, input string) bool {
	if input == name {
		return true
	}
	if strings.HasPrefix(name, "~/") || strings.HasPrefix(name, "/") {
		return expandIgnorePath(input) == expandIgnorePath(name)
	}
	if name == ignoreSectionName(kind) {
		n := normalizeIgnoreWord(input)
		return n == name || n == dashKind(kind)
	}
	return false
}

func expandIgnorePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		switch {
		case p == "~":
			p = home
		case strings.HasPrefix(p, "~/"):
			p = filepath.Join(home, p[2:])
		}
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	return filepath.Clean(p)
}

func ignoreKey(k checkKind, name string) string { return string(k) + "\x00" + name }

// ignoreUnit is one (kind, name) and the findings that make it up.
type ignoreUnit struct {
	kind        checkKind
	name        string
	findings    []checkFinding
	fingerprint string
}

func (u *ignoreUnit) key() string { return ignoreKey(u.kind, u.name) }

// doctorIgnoreUnits groups findings into units, in the order first seen.
func doctorIgnoreUnits(findings []checkFinding) []*ignoreUnit {
	var units []*ignoreUnit
	byKey := map[string]*ignoreUnit{}
	for _, f := range findings {
		name := ignoreName(f)
		k := ignoreKey(f.Kind, name)
		u := byKey[k]
		if u == nil {
			u = &ignoreUnit{kind: f.Kind, name: name}
			byKey[k] = u
			units = append(units, u)
		}
		u.findings = append(u.findings, f)
	}
	fp := newIgnoreFingerprinter()
	for _, u := range units {
		u.fingerprint = fp.unit(u)
	}
	return units
}

// applyDoctorIgnores splits findings into what the report shows and what
// it has been told to ignore. A unit whose entry's fingerprint no longer
// matches is shown, marked IgnoreChanged; everything else keeps its order.
func applyDoctorIgnores(findings []checkFinding, entries []doctorIgnoreEntry) (shown, ignored []checkFinding) {
	if len(entries) == 0 {
		return findings, nil
	}
	byKey := make(map[string]doctorIgnoreEntry, len(entries))
	for _, e := range entries {
		byKey[ignoreKey(e.Kind, e.Name)] = e
	}
	fingerprints := map[string]string{}
	for _, u := range doctorIgnoreUnits(findings) {
		fingerprints[u.key()] = u.fingerprint
	}
	for _, f := range findings {
		k := ignoreKey(f.Kind, ignoreName(f))
		e, ok := byKey[k]
		switch {
		case !ok:
			shown = append(shown, f)
		case e.Fingerprint == fingerprints[k]:
			f.IgnoredSince = e.Since
			ignored = append(ignored, f)
		default:
			f.IgnoreChanged = true
			shown = append(shown, f)
		}
	}
	return shown, ignored
}

// withIgnoreRefs fills the JSON-only ignore field, and for ignored
// findings severity and unignore.
func withIgnoreRefs(findings []checkFinding, ignored bool) []checkFinding {
	for i := range findings {
		f := &findings[i]
		name := ignoreName(*f)
		f.Ignore = &doctorIgnoreRef{
			Kind: f.Kind,
			Name: name,
			Argv: []string{"jit", "doctor", "ignore", "--kind", string(f.Kind), name},
		}
		if ignored {
			f.Severity = "problem"
			if f.Kind.warning() {
				f.Severity = "warning"
			}
			f.Unignore = &doctorUnignoreRef{
				Argv: []string{"jit", "doctor", "unignore", "--kind", string(f.Kind), name},
			}
		}
	}
	return findings
}

// ignoreFingerprinter hashes what a unit says. Only what identifies the
// finding goes in: its subject, files, configs, record, launchers, secret
// references and, for kinds whose detail is their only identity, the
// detail with digit runs folded — so a date, a count or a version number
// in the prose doesn't bring a finding back. Order never matters, and
// counts, origins, "used by" evidence and actions stay out: they change
// with state the finding isn't about, or with jit's own wording.
type ignoreFingerprinter struct {
	files map[string][]string
}

func newIgnoreFingerprinter() *ignoreFingerprinter {
	return &ignoreFingerprinter{files: map[string][]string{}}
}

var ignoreDigitRuns = regexp.MustCompile(`[0-9]+`)

// ignoreDetailIdentifies reports whether a kind's Detail is part of what
// it says. False where the structured fields carry it all, or where the
// only thing Detail adds is a count.
func ignoreDetailIdentifies(k checkKind) bool {
	switch k {
	case kindMissing, kindOrphan, kindOriginGone, kindProfileMissing, kindNotLoggedIn,
		kindPointerMissing, kindConfigDeleted, kindConfigNotRecorded, kindNoKnownTool,
		kindVaultKey, kindVaultRestore, kindLegacyEnvelope:
		return false
	default:
		return true
	}
}

func (fp *ignoreFingerprinter) unit(u *ignoreUnit) string {
	var keys []string
	for _, f := range u.findings {
		keys = append(keys, fp.finding(f))
	}
	sort.Strings(keys)
	keys = slices.Compact(keys)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00", u.kind, u.name)
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (fp *ignoreFingerprinter) finding(f checkFinding) string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	add("profile", f.Profile)
	add("scope", f.Scope)
	add("variable", f.Variable)
	add("path", f.Path)
	add("file", f.File)
	add("config", f.Config)
	for _, list := range []struct {
		key  string
		vals []string
	}{{"configs", f.Configs}, {"owner", f.Owners}, {"group", f.Groups}} {
		vals := slices.Clone(list.vals)
		sort.Strings(vals)
		for _, v := range vals {
			add(list.key, v)
		}
	}
	// A per-secret finding's launchers are context (which tools start the
	// profile), not what it says: a tool added or removed must not bring
	// an ignored [missing] back.
	var ls []string
	for _, l := range f.Launchers {
		if perSecretKind(f.Kind) {
			break
		}
		k := strings.Join([]string{string(l.Kind), l.File, l.Detail, l.Profile, l.VaultPath, strconv.Itoa(l.Layer)}, "|")
		if l.Kind == launchers.KindAWS {
			k += "|" + strings.Join(fp.awsSection(l.File, l.Detail), "\n")
		}
		ls = append(ls, k)
	}
	sort.Strings(ls)
	for _, l := range ls {
		add("launcher", l)
	}
	if ignoreDetailIdentifies(f.Kind) {
		add("detail", ignoreDigitRuns.ReplaceAllString(f.Detail, "#"))
	}
	return strings.Join(parts, "\x1f")
}

// awsSection is the body of one ~/.aws/config section, the lines between
// its header and the next (blank lines and comments dropped), parsed the
// way the launcher discovery parses it. The launcher carries only which
// profile the section names, so this is what makes an edit to the entry
// — a region, a role, a different jit path — bring its finding back.
func (fp *ignoreFingerprinter) awsSection(file, detail string) []string {
	lines, ok := fp.files[file]
	if !ok {
		data, err := os.ReadFile(file) // #nosec G304 -- ~/.aws/config, the file this launcher was discovered in
		if err == nil {
			lines = strings.Split(string(data), "\n")
		}
		fp.files[file] = lines
	}
	var body []string
	in := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = "["+strings.TrimSpace(t[1:len(t)-1])+"]" == detail
			continue
		}
		if in {
			body = append(body, t)
		}
	}
	return body
}

// --- the text report ---

// writeIgnoreChanged is the └ line under a row whose ignore no longer
// matches: why a finding the reader dismissed is back.
func writeIgnoreChanged(out io.Writer, f checkFinding) {
	if !f.IgnoreChanged {
		return
	}
	lead := strings.Repeat(" ", findingIndent)
	fmt.Fprint(out, lead+glyphBranch+" ")
	wrapBody(out, findingIndent+2, lead+"  ", "was ignored; "+ignoreChangedNoun(f.Kind)+" changed since")
}

// ignoreChangedNoun names what changed, in the unit's own terms.
func ignoreChangedNoun(k checkKind) string {
	switch k {
	case kindProfileMissing, kindNotLoggedIn:
		return "that entry"
	case kindPointerMissing:
		return "that pointer"
	case kindConfigDeleted, kindConfigNotRecorded, kindNoKnownTool:
		return "its record"
	default:
		return "it"
	}
}

// ignoredRow is one ignored unit as the [ignored] group lists it.
type ignoredRow struct {
	kind  checkKind
	name  string
	since string
}

func ignoredRows(ignored []checkFinding) []ignoredRow {
	var rows []ignoredRow
	seen := map[string]bool{}
	for _, f := range ignored {
		name := ignoreName(f)
		if k := ignoreKey(f.Kind, name); !seen[k] {
			seen[k] = true
			rows = append(rows, ignoredRow{kind: f.Kind, name: name, since: f.IgnoredSince})
		}
	}
	return rows
}

// writeIgnoredGroup closes the findings with the [ignored] group: a count
// and the flag that lists them, or with show, each unit and when it was
// ignored. Nothing when nothing is ignored.
func writeIgnoredGroup(out io.Writer, ignored []checkFinding, show, precededBy bool) bool {
	rows := ignoredRows(ignored)
	if len(rows) == 0 {
		return precededBy
	}
	if precededBy {
		fmt.Fprintln(out)
	}
	_, _ = cBold.Fprint(out, "[ignored]")
	if len(rows) > 1 {
		_, _ = fmt.Fprintf(out, "  %d", len(rows))
	}
	fmt.Fprintln(out)
	action := "`jit doctor --show-ignored`"
	if show {
		for _, r := range rows {
			glyph, c := glyphWarn, cWarn
			if !r.kind.warning() {
				glyph, c = glyphRisk, cRisk
			}
			writeGroupRow(out, glyph, c, fmt.Sprintf("%s · %s · since %s", r.name, ignoreKindText(r.kind), r.since))
		}
		action = "`jit doctor unignore <name>`"
		if len(rows) == 1 {
			action = "`jit doctor unignore " + shellQuoteArg(rows[0].name) + "`"
		}
	}
	arrow := strings.Repeat(" ", findingArrow)
	fmt.Fprint(out, arrow)
	_, _ = cPath.Fprint(out, glyphAction+" ")
	wrapBody(out, findingIndent, arrow+"  ", hlCmds(action))
	return true
}

// --- what ignore and unignore say ---

// ignoreUnitSummary is the unit after its name, for the ambiguity list:
// "OKTA_ORG_URL, OKTA_SCOPES", "tool okta-mcp-server".
func ignoreUnitSummary(u *ignoreUnit) string {
	first := u.findings[0]
	switch u.kind {
	case kindMissing, kindCorrupt, kindBadPath, kindVaultError:
		var vars []string
		for _, f := range u.findings {
			if f.Variable != "" && !slices.Contains(vars, f.Variable) {
				vars = append(vars, f.Variable)
			}
		}
		sort.Strings(vars)
		if len(vars) > 0 {
			return strings.Join(vars, ", ")
		}
	case kindProfileMissing, kindNotLoggedIn:
		var where []string
		for _, f := range u.findings {
			for _, l := range f.Launchers {
				if w := launcherWhere(l); !slices.Contains(where, w) {
					where = append(where, w)
				}
			}
		}
		if len(where) > 0 {
			return strings.Join(where, ", ")
		}
	case kindConfigDeleted, kindConfigNotRecorded:
		var ls []launchers.Launcher
		for _, f := range u.findings {
			ls = append(ls, f.Launchers...)
		}
		if tools := mcpToolNames(ls); len(tools) > 0 {
			return "tool " + strings.Join(tools, ", ")
		}
	case kindNoKnownTool:
		return secretsPhrase(first.Secrets, first.SecretsMissing)
	}
	body := strings.TrimPrefix(formatFinding(first), u.name+" · ")
	return termtext.TruncTail(body, 60)
}

// ignoreStillFails is the honest line for an ignored PROBLEM: what stays
// broken, in the unit's own terms.
func ignoreStillFails(u *ignoreUnit) string {
	first := u.findings[0]
	switch u.kind {
	case kindProfileMissing:
		if len(first.Launchers) > 0 {
			l := first.Launchers[0]
			switch l.Kind {
			case launchers.KindAWS:
				return awsProfileCommand(l.Detail) + " still fails"
			case launchers.KindMCP:
				return "that MCP server still fails to start"
			case launchers.KindKube:
				return "kubectl still fails as that user"
			case launchers.KindShellRC:
				return "that line still fails in every new shell"
			}
		}
	case kindMissing, kindCorrupt, kindBadPath:
		return "jit run --profile " + u.name + " still fails"
	case kindVaultError:
		if first.Profile != "" {
			return "jit run --profile " + u.name + " still fails"
		}
	case kindParse:
		return "profile " + u.name + " still won't load"
	case kindNotFound:
		return "profile " + u.name + " still doesn't exist"
	case kindPointerMissing:
		return u.name + " still points at a secret the vault doesn't hold"
	case kindMCP:
		return "that MCP server still fails to start"
	case kindWrap:
		return "that wrap check still fails"
	case kindJitPath:
		return u.name + " still runs a jit that isn't there"
	case kindVaultKey:
		return "the vault still can't be decrypted"
	case kindRekey, kindVaultMove, kindRekeyUnknown:
		return "vault writes are still refused"
	case kindVaultRestore:
		return "some secrets still can't be opened"
	case kindVaultKeyCopy:
		return "the vault key can still be read from your keychain"
	case kind1Password:
		return "linked secrets still can't resolve"
	case kind1PasswordLink:
		return u.name + " still doesn't resolve"
	}
	return "it still fails"
}

// ignoreComesBack is the clause after "comes back if": what change brings
// the unit back.
func ignoreComesBack(u *ignoreUnit) string {
	switch u.kind {
	case kindProfileMissing, kindNotLoggedIn:
		var files []string
		for _, f := range u.findings {
			for _, l := range f.Launchers {
				if !slices.Contains(files, l.File) {
					files = append(files, l.File)
				}
			}
		}
		if len(files) == 1 {
			return "its " + shortPath(files[0]) + " entry changes"
		}
		return "its config entries change"
	case kindPointerMissing:
		return "its pointers change"
	case kindMissing, kindCorrupt, kindBadPath:
		return "its secrets change"
	case kindConfigDeleted, kindConfigNotRecorded:
		return "its record or configs change"
	case kindNoKnownTool:
		return "its record changes"
	case kindOriginGone:
		return "its groups change"
	}
	return "what it reports changes"
}
