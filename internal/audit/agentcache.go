// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/pointerfile"
)

// AI coding agents keep local copies of the files and text they work on, and
// those copies are where credentials go to be forgotten. Claude Code alone
// keeps four kinds on a real machine (measured 2026-08-06, 3,813 files /
// 300 MB): verbatim snapshots of every file it edited (file-history/), the
// text of everything pasted into a prompt (paste-cache/), a dump of the
// exported shell environment (shell-snapshots/), and the full conversation
// (projects/*.jsonl). Other agents keep the equivalents under their own dot
// directories.
//
// The obvious way to scan them is to point the vendor patterns at the tree,
// and it is the wrong way. Measured on that same machine: 100 seconds — 26x
// the entire rest of the scan — producing 2,164 matches over 201 distinct
// values, essentially all of them synthetic. Agent transcripts are prose
// ABOUT code, so they are full of documentation examples, generated
// fixtures, and the tool's own scan output. It is the worst
// signal-to-noise environment in the product, and no amount of pattern
// tuning fixes a corpus whose subject matter is credentials.
//
// So this runs the search in the other direction. jit has just finished
// confirming a set of real credentials in structured stores — ~/.aws/
// credentials, .env files, kubeconfig, MCP configs, shell history. Those
// values are facts, not guesses. Searching the agent caches for those exact
// strings costs one pass of fixed-string matching, and every hit is a real
// credential by construction: there is no pattern to be wrong about, no
// confidence to calibrate, and nothing to suppress. The same machine that
// produced 2,164 pattern matches produces 16 of these, and all 16 are the
// user's own live credentials sitting in a cache they did not know existed.
//
// It also reaches where the pattern sweep cannot. Exact-string matching does
// not care whether the file is prose, minified JSON, or a SQLite database,
// so an agent that keeps its history in a binary store is covered by the
// same code — the NUL sniff that (correctly) protects the line-oriented
// scanners is not needed here.
//
// What this deliberately does NOT find is a credential that exists ONLY in
// an agent cache: something typed straight into a prompt and never stored in
// a file jit scans. There is no known value to search for, so this phase is
// structurally blind to it. That gap is real and is covered separately, for
// the small file-shaped caches where pattern matching still behaves (see
// agentCacheSweepDirs).
//
// And one case is invisible to `jit scan` by construction: a credential that
// has ALREADY been migrated. Once the .env holds a jit://vault/ pointer, no
// scanner can see the value, so nothing can search for it — while the copy
// in file-history/ keeps the plaintext. Closing that needs the vault, which
// needs authentication, which `jit scan` deliberately does not have. It
// belongs to `jit migrate` (which holds the plaintext at vault time) and to
// an authenticated `jit doctor` check.

// cacheNeedle is one confirmed credential to hunt copies of, plus enough of
// its origin to explain the copy: the variable it was stored under and the
// finding that established it is real.
type cacheNeedle struct {
	value  string
	key    string
	origin Finding
}

// agentCacheRoot is one AI agent's local state directory.
//
// Roots are home-relative and existence-gated, so a machine without a given
// agent pays one Lstat. Skip is a list of root-relative subdirectories never
// read: vendored plugin trees, bundled browsers and binary blob caches, which
// are large and cannot hold a credential the USER is responsible for — the
// same test noiseDirs applies.
type agentCacheRoot struct {
	dir   string // relative to HomeDir
	label string // human name for evidence, e.g. "Claude Code"
	skip  []string
}

// agentCacheRoots are the agent directories searched for copies.
//
// Only home-level directories are listed. The agents' Electron caches under
// ~/Library/Application Support (Claude Desktop, Cursor's workspaceStorage
// SQLite) hold the same class of content and are reachable by exactly this
// mechanism, but they are measured in gigabytes of unrelated blob cache and
// want their own skip lists; they are the next increment, not a silent gap.
var agentCacheRoots = []agentCacheRoot{
	{
		dir:   ".claude",
		label: "Claude Code",
		// plugins/ is a vendored marketplace checkout, chrome/ a bundled
		// browser, image-cache/ decoded screenshots — none of them the
		// user's content. file-history/, paste-cache/, shell-snapshots/
		// and projects/ are the point of this scanner and are NOT skipped.
		skip: []string{"plugins", "chrome", "image-cache"},
	},
	{dir: ".cursor", label: "Cursor", skip: []string{"extensions"}},
	{dir: ".codeium", label: "Codeium"},
	{dir: ".continue", label: "Continue"},
	{dir: ".copilot", label: "GitHub Copilot CLI"},
	{dir: ".codex", label: "Codex CLI"},
	{dir: ".gemini", label: "Gemini CLI"},
	{dir: ".windsurf", label: "Windsurf"},
	// Verified by running the tool, 2026-08-06: `cline auth` writes the
	// provider API key to ~/.cline/settings/providers.json, and the CLI's
	// own --data-dir flag documents ~/.cline as its state root.
	{dir: ".cline", label: "Cline"},
	// Verified by running the tool, 2026-08-06: `opencode auth list` prints
	// "Credentials ~/.local/share/opencode/auth.json" itself.
	{dir: filepath.Join(".local", "share", "opencode"), label: "OpenCode"},
	{dir: filepath.Join(".config", "github-copilot"), label: "GitHub Copilot"},
}

// maxAgentCacheFileSize bounds a single file read. Unlike the content sweep's
// 5 MiB ceiling, this one is not about cost — fixed-string matching is linear
// and cheap — but about not allocating an unbounded buffer for one
// pathological file. It sits far above anything an agent writes (the largest
// transcript measured was 22 MiB), and crossing it is REPORTED as a degraded
// scanner, never a silent skip: "we could not look" must not render as
// "there is nothing there".
const maxAgentCacheFileSize = 64 << 20

// substrIndex matches many fixed strings against a buffer in one pass.
//
// Bucketed by first byte: at each position only the needles beginning with
// that byte are tested, so the per-byte cost on non-matching data is one
// slice lookup. Deliberately not Aho-Corasick — that is the textbook answer
// and it would be a new dependency or ~200 lines of trie for a needle set
// measured in dozens, where this measures fast enough to disappear into the
// walk (+0.4s over a 306 MB tree, measured 2026-08-06).
type substrIndex struct {
	needles []string
	byFirst [256][]int
	maxLen  int
}

func newSubstrIndex(needles []string) *substrIndex {
	s := &substrIndex{needles: needles}
	for i, n := range needles {
		if n == "" {
			continue
		}
		s.byFirst[n[0]] = append(s.byFirst[n[0]], i)
		if len(n) > s.maxLen {
			s.maxLen = len(n)
		}
	}
	return s
}

// findAll reports, for each needle present in data, the offset of its first
// occurrence and how many times it occurs. A needle absent from data is
// absent from both maps.
// name maps a needle to the variable it was assigned to, taken from the first
// occurrence in this file that offers one — NOT necessarily the first
// occurrence. A credential pasted into a prompt and later used in a command
// appears twice in one transcript: bare the first time, named the second. The
// bare sighting is the one `first` records, so keying the name off it threw
// away the only thing that identified the credential (measured 2026-08-09 on
// a live Homebrew-tap token). The extraction runs only on a confirmed match
// and reads a bounded prefix, so it costs nothing on the scanning path.
func (s *substrIndex) findAll(data []byte) (first map[int]int, count map[int]int, name map[int]string) {
	first = map[int]int{}
	count = map[int]int{}
	name = map[int]string{}
	if len(s.needles) == 0 {
		return first, count, name
	}
	for i := 0; i < len(data); i++ {
		for _, idx := range s.byFirst[data[i]] {
			n := s.needles[idx]
			if len(data)-i < len(n) {
				continue
			}
			// string(...) == n rather than bytes.Equal(..., []byte(n)): the
			// []byte(n) conversion allocates on every candidate position, and
			// a needle starting with a common byte ("s" for sk_live_, "e" for
			// eyJ) hits millions of positions across a 300 MB tree. The string
			// comparison form is guaranteed allocation-free.
			if string(data[i:i+len(n)]) != n {
				continue
			}
			if _, seen := first[idx]; !seen {
				first[idx] = i
			}
			if name[idx] == "" {
				lo := bytes.LastIndexByte(data[:i], '\n') + 1
				if i-lo > credentialNameLead {
					lo = i - credentialNameLead
				}
				if n := assignedCredentialName(string(data[lo:i]), i-lo); n != "" {
					name[idx] = n
				}
			}
			count[idx]++
		}
	}
	return first, count, name
}

// eligibleNeedle reports whether a confirmed credential value is distinctive
// enough to search for by exact match.
//
// The bar is not "is this a credential" — the caller already established
// that — but "would finding this string somewhere else mean anything". A
// short or word-shaped value fails that test: a database password of
// "hunter2" occurs in prose about passwords, and reporting every transcript
// that discusses it would rebuild the noise problem this scanner exists to
// avoid, with the added insult of being right about the value and wrong
// about the meaning.
//
// The rules, and the false negative each accepts:
//
//   - 12 bytes minimum. A shorter real credential is missed. That is the
//     safer direction here, and only here: the usual rule in this package is
//     that a false negative on a live credential is worse than an extra
//     finding (LooksLikeBareURL's doc comment), but that weighs one extra
//     LINE in a report. This weighs a needle that can match thousands of
//     times across 300 MB of prose.
//   - No whitespace. Every span the scanners hand back is a single token;
//     a value with a space in it is a parse artifact, and a common phrase
//     makes a catastrophic needle.
//   - Not placeholder filler, by the same test MatchKnownTokenPattern uses,
//     so a template's "ghp_xxxxxxxx…" cannot become a needle that matches
//     every other template on the machine.
//   - Not all-lowercase-letters and not all-digits: those are words and
//     numbers. A real credential that happens to be either is missed.
//   - Not one of jit's own jit://vault/ pointers. Those are not secrets,
//     they are what a migrated file holds INSTEAD of a secret — and they are
//     designed to be copied around, so they match everywhere.
//
// EligibleNeedle reports whether a confirmed credential is distinctive enough
// to search agent caches for by exact match. Exported so internal/migrate's
// cleanup sweep applies the identical bar the scanner does — a value too short
// or word-shaped to be a good scan needle is just as bad a redaction needle,
// and the two must not drift.
func EligibleNeedle(v string) bool { return eligibleNeedle(v) }

func eligibleNeedle(v string) bool {
	if len(v) < 12 {
		return false
	}
	if strings.HasPrefix(v, pointerValuePrefix) {
		return false
	}
	letters, digits := 0, 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c == 0x7f {
			return false
		}
		switch {
		case c >= 'a' && c <= 'z':
			letters++
		case c >= '0' && c <= '9':
			digits++
		}
	}
	if letters == len(v) || digits == len(v) {
		return false
	}
	return !isPlaceholderToken(v, false)
}

// pointerValuePrefix is what a migrated file holds where the credential was.
// Duplicated from internal/migrate rather than imported: this package is the
// read-only scanner and must not depend on the package that writes.
const pointerValuePrefix = pointerfile.ValuePrefix

// crossReferenceAgentCaches searches every present AI agent cache for verbatim
// copies of the credentials findings already confirmed, and returns one
// finding per (file, credential).
//
// The returned findings carry the SAME rawValue as the finding that supplied
// the needle, so annotateCauseGroups puts them in one cause group: a secret
// in a .env plus nine copies in file-history is one secret in ten places, not
// ten secrets. That is what keeps the ledger honest without any new
// arithmetic (see ComputeCoverage).
//
// Files that already carry a finding of their own are skipped. Without that,
// ~/.gemini/oauth_creds.json — an agent root AND a store the self-rotating
// scanner already reports — would be reported twice, once properly and once
// as a copy of itself.
func crossReferenceAgentCaches(cfg Config, findings []Finding) ([]Finding, []ScannerFailure) {
	var pins []cacheNeedle
	seen := map[string]bool{}
	reported := map[string]bool{}
	for _, f := range findings {
		if f.FilePath != "" {
			reported[f.FilePath] = true
		}
		// CountedAsSecret is the needle gate, and it is doing two jobs that
		// both showed up the first time this ran on a real machine. It drops
		// TEST FIXTURES: jit's own tokenpatterns_test.go is full of synthetic
		// credentials, and without this the scanner's proudest output was 51
		// copies of its own test data (the match was real, the credential was
		// nobody's). And it drops LOW/INFO findings: those are jit saying
		// "could be, probably isn't", and a value jit will not stand behind is
		// not a value worth hunting copies of — a bare CAIDO_URL was the case
		// in hand.
		if !CountedAsSecret(f) {
			continue
		}
		add := func(key, value string) {
			if value == "" || seen[value] || !eligibleNeedle(value) {
				return
			}
			seen[value] = true
			pins = append(pins, cacheNeedle{value: value, key: key, origin: f})
		}
		if f.KeyName != nil {
			add(*f.KeyName, f.rawValue)
		}
		for _, cv := range f.claimedRawValues {
			add(cv.Key, cv.Value)
		}
	}
	if len(pins) == 0 {
		return nil, nil
	}
	needles := make([]string, len(pins))
	for i, p := range pins {
		needles[i] = p.value
	}

	index := newSubstrIndex(needles)
	var out []Finding
	var failures []ScannerFailure

	for _, root := range agentCacheRoots {
		dir := filepath.Join(cfg.HomeDir, root.dir)
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			continue
		}
		if cfg.Progress != nil {
			cfg.Progress(root.label + " cache")
		}
		skip := map[string]bool{}
		for _, s := range root.skip {
			skip[filepath.Join(dir, s)] = true
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skip[path] || (path != dir && SkipNoiseDir(dir, path, d.Name())) {
					return filepath.SkipDir
				}
				return nil
			}
			// Same regular-file-only rule as walkHomeDir, for the same
			// reasons: a symlink would silently widen scope, and a FIFO
			// would block the read.
			if !d.Type().IsRegular() || reported[path] {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if info.Size() > maxAgentCacheFileSize {
				failures = append(failures, ScannerFailure{
					Scanner: "AI agent stores",
					Error: fmt.Sprintf("%s is %d bytes, above the %d-byte bound; not read",
						ShortenHome(cfg.HomeDir, path), info.Size(), int64(maxAgentCacheFileSize)),
				})
				return nil
			}
			data, rerr := readAgentCacheFile(path)
			if rerr != nil {
				return nil // unreadable — skip, never fail the scan
			}
			first, count, named := index.findAll(data)
			if len(first) == 0 {
				return nil
			}
			// Binary content has no meaningful line number; an offset into a
			// SQLite page would be a coordinate the reader cannot use.
			textual := !bytes.Contains(headOf(data), []byte{0})
			// Iterated over pins, not over the map: Go randomises map order,
			// and scan.go's contract is that findings come out in a stable
			// order so NDJSON is byte-comparable across runs.
			for idx := range pins {
				at, hit := first[idx]
				if !hit {
					continue
				}
				f := cfg.agentCachedSecretFinding(
					path, root.label, pins[idx], data, at, count[idx], textual)
				f.AssignedName = named[idx]
				out = append(out, f)
			}
			return nil
		})
	}
	return out, failures
}

// headOf returns the first block of data, for the binary sniff.
func headOf(data []byte) []byte {
	if len(data) > 512 {
		return data[:512]
	}
	return data
}

// ReadCacheFileGuarded reads path through the no-follow, no-FIFO-hang,
// regular-file-only, size-bounded guards every scanner in this package uses.
// Exported so internal/migrate's cleanup sweep reads agent cache files with
// exactly the same protection the scan side does — the write side must not
// re-open by bare path and reintroduce the open(2)-on-a-FIFO hang that
// readAgentCacheFile's own comment documents.
func ReadCacheFileGuarded(path string) ([]byte, error) {
	return readAgentCacheFile(path)
}

// readAgentCacheFile reads a cache file through the same openFile guards every
// scanner uses (no symlink follow, no blocking on a FIFO, regular files only).
//
// Read from the DESCRIPTOR openFile validated, never by re-opening the path.
// An earlier version called os.ReadFile(f.Name()), which checked one inode and
// then read whatever the path pointed at a moment later: a FIFO swapped in
// between the two opens blocks the whole scan in open(2) forever (jit creates
// FIFOs for a living, so this is jit's own shape of file), a symlink swapped
// in is followed straight past the walk's guards, and the size bound checked
// against the earlier stat stops bounding anything. That is precisely the race
// openFile's doc comment exists to close, reintroduced one layer up.
//
// The limit is maxAgentCacheFileSize+1 so a file that GREW past the bound
// after its stat is still caught by the caller rather than read unbounded —
// transcripts are appended to while the scan runs.
func readAgentCacheFile(path string) ([]byte, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAgentCacheFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAgentCacheFileSize {
		return nil, fmt.Errorf("%s grew past the %d-byte bound while being read", path, int64(maxAgentCacheFileSize))
	}
	return data, nil
}

// agentCachedSecretFinding builds the finding for one credential found in one
// agent cache file.
//
// Deliberately NOT built through ValueFinding. That function's job is to judge
// a value it has just been handed — mask it, test it for production and public
// -IP signals, match it against the vendor patterns — and every one of those
// judgments was already made, on this exact value, by the finding that
// supplied the needle. Re-deriving them here would let the copy disagree with
// the original about what the secret IS, which is precisely the thing this
// scanner exists to assert is the same. So severity, preview and the
// production flag are INHERITED from the origin finding, and only the location
// changes.
func (c Config) agentCachedSecretFinding(path, agent string, pin cacheNeedle, data []byte, at, count int, textual bool) Finding {
	origin := pin.origin
	f := c.baseFinding()
	f.FindingType = FindingTypeAgentCachedSecret
	f.FilePath = path
	key := pin.key
	f.KeyName = &key
	preview := MaskValue(pin.value)
	f.ValuePreview = &preview
	f.Severity = origin.Severity
	f.Confidence = ConfidenceHigh // an exact match is not a judgment call
	f.ProductionIndicatorMatch = origin.ProductionIndicatorMatch
	f.PublicIPMatch = origin.PublicIPMatch
	// Carried so annotateCauseGroups folds the copy into the origin's group.
	// Digested from the needle rather than copied off the origin: a file-level
	// finding (env_file_present) carries no digest of its own, and its several
	// claimed values are several different secrets.
	f.rawValue = pin.value
	f.OriginPath = origin.FilePath
	digest := sha256.Sum256([]byte(pin.value))
	f.rawValueDigest = hex.EncodeToString(digest[:])

	if textual {
		line := 1 + bytes.Count(data[:at], []byte{'\n'})
		f.Line = &line
	}

	where := ShortenHome(c.HomeDir, origin.FilePath)
	f.Evidence = fmt.Sprintf("a verbatim copy of the credential from %s, kept by %s", where, agent)
	if count > 1 {
		f.Evidence = fmt.Sprintf("%s (%d occurrences in this file)", f.Evidence, count)
	}
	// Manual as a SCAN verdict, and deliberately so, even though `jit migrate`
	// (its automatic sweep) and `jit migrate caches` (the whole-vault sweep)
	// now do clean these. The finding exists precisely for the copy those
	// sweeps could not reach in the moment: an agent that was mid-write, a
	// binary store jit will not rewrite, or a secret not yet in the vault at
	// scan time. A scan cannot know which copies a future migrate will get, so
	// it reports the honest present-tense fact — this copy is here now, and
	// only you can be sure it is gone — and leaves the coverage projection to
	// the migrate command that is actually about to act. Set here rather than
	// left to annotateRemedies so the whole finding type carries one answer.
	f.Remedy = RemedyManual
	f.RecordID = RecordID(f.FindingType, f.FilePath, f.KeyName)
	return f
}

// --- Agent credential stores and file-shaped caches ---
//
// The cross-reference above finds COPIES of credentials confirmed elsewhere.
// Two things it structurally cannot find, both covered here by ordinary
// content scanning:
//
//   - A credential that lives ONLY in an agent's own credential store.
//     ~/.cline/settings/providers.json holds the API key `cline auth` was
//     given and nothing else on the machine has it, so there is no needle.
//     These files are reached by FIXED PATH rather than by the walk's name
//     gate, because "providers.json" and "hosts.json" announce nothing —
//     credentialFileNameHints would never open either.
//
//   - A credential typed straight into a prompt and never stored in a file.
//     It reaches disk anyway, in the agent's own record of what you typed.
//
// The second is why this sweeps a SHORT list of cache directories with the
// vendor patterns after all — the thing agentcache.go's opening comment says
// not to do. The distinction is what the files hold. paste-cache/ is verbatim
// pasted text, shell-snapshots/ is a dump of the exported environment, and
// history.jsonl is the list of prompts: file-shaped content where a vendor
// match means what it usually means. projects/ is prose ABOUT code, where it
// does not — and projects/ is 231 MB of the 300 MB, so leaving it out is what
// keeps this affordable as well as accurate.
var agentCredentialStores = []struct{ path, agent string }{
	// Verified by running the tool, 2026-08-06.
	{filepath.Join(".cline", "settings", "providers.json"), "Cline"},
	{filepath.Join(".local", "share", "opencode", "auth.json"), "OpenCode"},
	// Path from the tool's own documentation; absent here, so an Lstat that
	// finds nothing is all it costs. A content sweep claims nothing about the
	// file's SCHEMA, which is the part that would be a guess — detection is a
	// claim about bytes, not about a program's behavior.
	{filepath.Join(".config", "github-copilot", "hosts.json"), "GitHub Copilot"},
	{filepath.Join(".copilot", "config.json"), "GitHub Copilot CLI"},
	{filepath.Join(".codex", "auth.json"), "Codex CLI"},
	{filepath.Join(".codeium", "config.json"), "Codeium"},
	{filepath.Join(".continue", "config.json"), "Continue"},
}

// agentCacheSweepDirs are the file-shaped caches swept with the vendor
// patterns. Small by nature (~1.2 MB across all of them on the machine this
// was measured on) and high-signal; see the note above for why projects/ is
// deliberately not among them.
var agentCacheSweepDirs = []string{
	filepath.Join(".claude", "paste-cache"),
	filepath.Join(".claude", "shell-snapshots"),
	filepath.Join(".claude", "backups"),
}

// agentCacheSweepFiles are single files swept the same way. history.jsonl is
// Claude Code's record of every prompt typed at it — the AI-era shell history,
// and worth exactly what ~/.zsh_history is worth.
var agentCacheSweepFiles = []string{
	filepath.Join(".claude", "history.jsonl"),
}

// ScanAgentStores reports vendor-format credentials in AI agents' own
// credential files and in their file-shaped caches.
//
// Read-only like everything else here. A store that does not exist is not an
// error; a store that exists and cannot be read IS reported, so an unreadable
// file never passes as an empty one.
func ScanAgentStores(cfg Config) ([]Finding, error) {
	var findings []Finding
	var failures []string

	sweep := func(path, label string) {
		fs, err := scanFileContentForTokens(cfg, path)
		if err != nil {
			if !os.IsNotExist(err) {
				failures = append(failures, fmt.Sprintf("%s: %v", ShortenHome(cfg.HomeDir, path), err))
			}
			return
		}
		for i := range fs {
			fs[i].Evidence = fmt.Sprintf("%s (found in %s local store)", fs[i].Evidence, possessive(label))
		}
		findings = append(findings, fs...)
	}

	for _, store := range agentCredentialStores {
		path := filepath.Join(cfg.HomeDir, store.path)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		sweep(path, store.agent)
	}
	for _, f := range agentCacheSweepFiles {
		path := filepath.Join(cfg.HomeDir, f)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		sweep(path, "Claude Code")
	}
	for _, dir := range agentCacheSweepDirs {
		root := filepath.Join(cfg.HomeDir, dir)
		if info, err := os.Lstat(root); err != nil || !info.IsDir() {
			continue
		}
		_ = walkHomeDir(root, func(path string, d fs.DirEntry) error {
			sweep(path, "Claude Code")
			return nil
		})
	}
	if len(failures) > 0 {
		return findings, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return findings, nil
}

// --- Naming an agent cache for the report ---

// agentCacheAreas maps a cache subtree to what it HOLDS, in the reader's
// terms rather than the agent's. "file-history" is a directory name; "edit
// history" is what a person has to be told in order to understand why their
// Stripe key is in it. Longest prefix wins, so the single-file entries below
// beat the directory they sit in.
var agentCacheAreas = []struct{ suffix, label string }{
	{filepath.Join(".claude", "file-history"), "edit history"},
	{filepath.Join(".claude", "projects"), "transcripts"},
	{filepath.Join(".claude", "paste-cache"), "pasted text"},
	{filepath.Join(".claude", "shell-snapshots"), "shell snapshots"},
	{filepath.Join(".claude", "backups"), "backups"},
	{filepath.Join(".claude", "history.jsonl"), "prompt history"},
}

// AgentCacheArea names what an agent cache path holds, or "" for a path that
// is not in one. Exported for the report layer, which describes a group of
// copies by WHERE they sit rather than by listing hash-named files nobody can
// read.
func AgentCacheArea(home, path string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, home), string(filepath.Separator))
	best := ""
	for _, a := range agentCacheAreas {
		if (rel == a.suffix || strings.HasPrefix(rel, a.suffix+string(filepath.Separator))) &&
			len(a.suffix) > len(best) {
			best = a.suffix
		}
	}
	for _, a := range agentCacheAreas {
		if a.suffix == best {
			return a.label
		}
	}
	return ""
}

// AgentLabelForPath names the agent whose cache path sits in, or "".
func AgentLabelForPath(home, path string) string {
	rel := strings.TrimPrefix(strings.TrimPrefix(path, home), string(filepath.Separator))
	label, best := "", ""
	for _, r := range agentCacheRoots {
		if (rel == r.dir || strings.HasPrefix(rel, r.dir+string(filepath.Separator))) &&
			len(r.dir) > len(best) {
			best, label = r.dir, r.label
		}
	}
	return label
}

// AgentCopyBreakdown summarises where a group's copies live: "9 copies: 4 in
// edit history, 5 in transcripts".
//
// Counting by AREA rather than listing files is the whole point. The files
// are named by content hash (93eb694cdfee2a45@v2), so a list of them tells a
// reader nothing they can act on, while "4 in edit history" tells them the
// agent kept their file when they changed it.
func AgentCopyBreakdown(home string, files []string) string {
	counts := map[string]int{}
	var order []string
	for _, f := range files {
		area := AgentCacheArea(home, f)
		if area == "" {
			area = "its cache"
		}
		if counts[area] == 0 {
			order = append(order, area)
		}
		counts[area]++
	}
	if len(order) == 0 {
		return ""
	}
	parts := make([]string, 0, len(order))
	for _, a := range order {
		parts = append(parts, fmt.Sprintf("%d in %s", counts[a], a))
	}
	return fmt.Sprintf("%s: %s", countWord(len(files), "copy", "copies"), strings.Join(parts, ", "))
}

// WalkAgentCaches calls fn for every regular file in every AI agent cache
// present under home, applying the same root list and skip rules the
// cross-reference uses.
//
// Exported for internal/migrate, whose cleanup sweep must visit exactly the
// files this package reports on. The two once-drifting lists that SkipNoiseDir
// exists to prevent are the precedent: "which files are an agent's cache" gets
// one definition, here, or scan and migrate will disagree about what they are
// looking at.
func WalkAgentCaches(home string, fn func(path string, d fs.DirEntry) error) error {
	for _, root := range agentCacheRoots {
		dir := filepath.Join(home, root.dir)
		if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
			continue
		}
		skip := map[string]bool{}
		for _, s := range root.skip {
			skip[filepath.Join(dir, s)] = true
		}
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skip[path] || (path != dir && SkipNoiseDir(dir, path, d.Name())) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			return fn(path, d)
		})
		if err != nil {
			return err
		}
	}
	return nil
}
