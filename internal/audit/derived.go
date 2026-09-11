// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DerivedCredential is a credential-bearing file a TOOL wrote for itself,
// downstream of anything jit hands out — an STS session the AWS CLI cached
// after using a migrated key, an SSO token `aws sso login` stored.
//
// These are not findings and never become findings. A finding is something
// jit can offer to fix; these are outside its model by construction, because
// the value was minted by the tool rather than stored by the user, and it will
// be minted again the next time the tool runs. Migrating them would be a lie,
// and jit deliberately does not manage, clean or decoy them.
//
// What jit was doing wrong was not failing to protect them — it was saying
// nothing. They are hex-named, so the content sweep's filename hints walk past
// without opening them; `.terraform` and `Library` are pruned outright. So a
// user could migrate ~/.aws/credentials, watch `jit scan` come back clean, and
// still have a live plaintext session token sitting in the very directory jit
// had just tidied. An advisory costs nothing and closes that gap: the boundary
// becomes documented and visible rather than merely true.
type DerivedCredential struct {
	// Path is the file or directory holding the derived credential.
	Path string
	// What it is, in the user's terms — not a severity, not an instruction.
	What string
	// Advice is the one thing worth doing about it, if anything.
	Advice string
	// Status, when non-empty, is a pre-rendered freshness line read from the
	// cached credentials' own expiry timestamps: "2 live, soonest expires in
	// 47m; 3 expired" or "all 5 expired". Empty when jit could not read any
	// expiry (then only What/Advice show). StatusLive is true when at least
	// one cached credential is still usable right now — the report renders
	// that with the amber ○ state glyph; expired-only residue gets no glyph,
	// because a dead token is not an active state.
	Status     string
	StatusLive bool
}

// ScanDerivedCredentials reports the derived artifacts jit knows how to
// recognize. It only ever reports things that actually exist: an advisory that
// lists hypothetical paths is noise, and noise is what stops people reading
// advisories.
//
// Cheap by design — a couple of stats and one small file read, no walking. It
// runs on every scan, including the ones that find nothing, because "nothing
// found" is exactly the report these artifacts are most likely to be hiding
// behind.
func ScanDerivedCredentials(cfg Config) []DerivedCredential {
	var out []DerivedCredential

	now := time.Now()
	if dir := filepath.Join(cfg.HomeDir, ".aws", "cli", "cache"); countFilesIn(dir) > 0 {
		d := DerivedCredential{
			Path:   dir,
			What:   "STS session credentials the AWS CLI cached for itself, in plaintext",
			Advice: "they expire on their own; delete the directory to clear them now",
		}
		d.Status, d.StatusLive = cacheFreshness(dirCacheExpiries(dir), now)
		out = append(out, d)
	}
	if dir := filepath.Join(cfg.HomeDir, ".aws", "sso", "cache"); countFilesIn(dir) > 0 {
		d := DerivedCredential{
			Path:   dir,
			What:   "SSO access tokens and role credentials, in plaintext",
			Advice: "`aws sso logout` clears them",
		}
		d.Status, d.StatusLive = cacheFreshness(dirCacheExpiries(dir), now)
		out = append(out, d)
	}
	if hasAssumeRoleProfile(filepath.Join(cfg.HomeDir, ".aws", "config")) {
		out = append(out, DerivedCredential{
			Path:   filepath.Join(cfg.HomeDir, ".aws", "config"),
			What:   "assume-role profiles, which jit does not migrate (they carry no stored key of their own — only a role to assume with someone else's)",
			Advice: "migrating the source profile still protects the long-lived key; the session minted from it is cached by the CLI",
		})
	}
	// gcloud's access-token cache: the ~1h tokens minted from the refresh
	// token in credentials.db, one row per account. The refresh token
	// itself is a finding (scanGcloudCLICredentials); this cache is the
	// derived layer below it — rewritten by gcloud whenever a cached token
	// nears expiry, so the same doctrine as ~/.aws/cli/cache applies.
	if p := filepath.Join(cfg.HomeDir, ".config", "gcloud", "access_tokens.db"); isRegularFile(p) {
		d := DerivedCredential{
			Path:   p,
			What:   "access tokens gcloud cached for itself (about an hour each), in plaintext",
			Advice: "they expire on their own; delete the file to clear them now (gcloud rewrites it in use)",
		}
		// A SQLite file, not JSON: gcloud stores token_expiry as a plain
		// timestamp in the row, so the bytes carry it verbatim (best-effort —
		// see fileCacheExpiries). No expiry read means the plain line, never
		// a wrong one.
		d.Status, d.StatusLive = cacheFreshness(fileCacheExpiries(p), now)
		out = append(out, d)
	}
	// clisso's opt-in credential_process cache (its --cache-path default):
	// live temporary AWS credentials in AWS INI format, at a path nothing
	// else looks in — not even ~/.aws/credentials sweeps, since the name
	// doesn't match. Rewritten by clisso on every cached fetch, so it's
	// derived, not a finding.
	if p := filepath.Join(cfg.HomeDir, ".aws", "credentials-cache"); isRegularFile(p) {
		d := DerivedCredential{
			Path:   p,
			What:   "temporary AWS session credentials clisso cached for credential_process use, in plaintext",
			Advice: "they expire on their own; delete the file to clear them now (clisso's cache-enable option keeps writing it)",
		}
		d.Status, d.StatusLive = cacheFreshness(fileCacheExpiries(p), now)
		out = append(out, d)
	}
	// clisso logs to stderr by default; this file exists only if someone
	// turned on file logging — and at `--log-level trace` clisso writes the
	// secret key and session token of every minted session into it. The
	// advisory doesn't read the file to check (see countFilesIn's principle):
	// existence of opt-in logging is the claim, the trace risk is the advice.
	if isRegularFile(filepath.Join(cfg.HomeDir, ".clisso.log")) {
		out = append(out, DerivedCredential{
			Path:   filepath.Join(cfg.HomeDir, ".clisso.log"),
			What:   "clisso's log file — at trace level it records the secret key and session token of every minted AWS session",
			Advice: "if it was ever written at trace level, treat the sessions in it as exposed; delete the file if in doubt",
		})
	}

	return out
}

// maxCacheReadSize bounds how much of a cached-credential file jit reads to
// find expiry timestamps. These are small by nature (one session's JSON, a
// few-KB SQLite page); the cap keeps a surprise large file from being slurped.
const maxCacheReadSize = 1 << 20

// cacheExpiryPattern matches the timestamp shapes these caches store: RFC3339
// ("2026-09-11T12:34:56Z", "...+00:00"), which the AWS caches write, and the
// space-separated Python form ("2026-09-11 12:34:56.789012"), which gcloud's
// sqlite3 layer writes for token_expiry. Time zone is optional; a bare form is
// read as UTC (see parseCacheExpiry), matching what both tools mean by it.
var cacheExpiryPattern = regexp.MustCompile(
	`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)

// parseCacheExpiry parses one matched timestamp, trying the time-zoned forms
// first and falling back to a zone-less form read as UTC. Returns ok=false for
// anything it can't place, so a stray timestamp-shaped string is ignored
// rather than counted as a bogus expiry.
func parseCacheExpiry(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05.999999", "2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// fileCacheExpiries returns every credential-expiry timestamp jit can read
// from one cache file's raw bytes. Best-effort by design: it is an advisory,
// so a timestamp it cannot parse (or a format it has never seen) yields fewer
// entries and a plainer line, never a wrong verdict or an error.
func fileCacheExpiries(path string) []time.Time {
	data, err := readCappedFile(path)
	if err != nil {
		return nil
	}
	var out []time.Time
	for _, m := range cacheExpiryPattern.FindAllString(string(data), -1) {
		if t, ok := parseCacheExpiry(m); ok {
			out = append(out, t)
		}
	}
	return out
}

// dirCacheExpiries reads one expiry per cache file in dir — each file in
// ~/.aws/cli/cache or ~/.aws/sso/cache is a single cached credential, so its
// FIRST timestamp is that credential's expiry. A file with no readable
// timestamp contributes nothing, so the count reflects only what jit could
// actually place.
func dirCacheExpiries(dir string) []time.Time {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []time.Time
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if ts := fileCacheExpiries(filepath.Join(dir, e.Name())); len(ts) > 0 {
			out = append(out, ts[0])
		}
	}
	return out
}

// readCappedFile reads up to maxCacheReadSize bytes of a regular file through
// the package's hardened opener (no symlink follow, no FIFO block).
func readCappedFile(path string) ([]byte, error) {
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxCacheReadSize)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

// cacheFreshness renders the advisory's freshness line from a set of expiry
// timestamps and reports whether any are still live. It returns ("", false)
// for an empty set, so a cache whose expiries jit could not read shows only
// its plain existence line — the freshness claim is made only when it can be
// backed.
func cacheFreshness(expiries []time.Time, now time.Time) (status string, live bool) {
	if len(expiries) == 0 {
		return "", false
	}
	var liveExp []time.Time
	expired := 0
	for _, e := range expiries {
		if e.After(now) {
			liveExp = append(liveExp, e)
		} else {
			expired++
		}
	}
	if len(liveExp) == 0 {
		return fmt.Sprintf("all %s expired", countWord(expired, "cached credential", "cached credentials")), false
	}
	sort.Slice(liveExp, func(i, j int) bool { return liveExp[i].Before(liveExp[j]) })
	soonest := humanUntil(liveExp[0].Sub(now))
	if expired == 0 {
		return fmt.Sprintf("%d live, soonest expires in %s", len(liveExp), soonest), true
	}
	return fmt.Sprintf("%d live, soonest expires in %s; %d expired", len(liveExp), soonest, expired), true
}

// humanUntil renders a positive duration coarsely — the reader wants "about
// how long", not seconds. Under a minute reads as "under a minute" rather
// than "0m", which would look like it already expired.
func humanUntil(d time.Duration) string {
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return "under a minute"
	}
}

// isRegularFile reports whether path is a regular file. Lstat, not Stat,
// for the same reason scanGlobalNpmrc uses it: a path jit itself has
// turned into a FIFO mount must never be opened (blocking) or reported as
// an exposure — and a symlink pointing elsewhere isn't the file this
// advisory is about either.
func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// countFilesIn returns how many regular files sit directly in dir. Contents
// are never opened: existence is the entire claim being made, and a scanner
// that reads a credential to report that a credential exists has defeated its
// own purpose.
func countFilesIn(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n
}

// hasAssumeRoleProfile reports whether ~/.aws/config declares any role_arn.
//
// Deliberately a line scan rather than a real INI parse: the question is only
// whether this machine has the shape of setup whose credentials jit's own
// discovery skips (DiscoverAWSProfiles selects on aws_secret_access_key, which
// an assume-role profile does not have), and a false positive costs one honest
// advisory line.
func hasAssumeRoleProfile(path string) bool {
	f, err := openFile(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := newLineScanner(f)
	// A hand-edited config has short lines, but a machine-generated or
	// corrupt one can exceed the default 64KB token and stop the scan early.
	// Raising the cap keeps a long line from quietly ending the search before
	// it reaches a role_arn further down.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "role_arn") {
			return true
		}
	}
	// Falling out of the loop means either "no role_arn" or "the read failed
	// partway" — and both answer false, deliberately. An advisory exists to be
	// believed, so it reports only what was actually seen; a guess made from a
	// failed read is exactly the kind of line that teaches people to skip
	// these blocks.
	return false
}
