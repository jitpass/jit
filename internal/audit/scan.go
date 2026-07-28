// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jitpass/jit/internal/mount"
)

// category is one RFC.md §4 scan category, split into its two independent
// halves:
//
//	fixed     probes known locations directly (~/.aws/credentials, ~/.ssh,
//	          the wrap catalog's own source files). No discovery needed —
//	          the paths are the definition of the category.
//	classify  is handed every regular file a home-directory walk turns up
//	          and decides, by name, whether the file is this category's
//	          business. Its files can live anywhere, so they must be found.
//
// Most categories have exactly one half. Credential files and MCP configs
// have both: a known store plus files that can sit in any project.
//
// The split exists so Scan can discover ONCE. Every classify half used to
// run its own full walkHomeDir, and on a real machine those redundant
// traversals measured as more than half of `jit scan`'s total runtime —
// several passes over the same ~47k-file tree to answer questions that all
// fit in a single pass. The name is also what Config.Progress reports as
// each fixed half runs, kept next to the function so the label and the
// scanner can't drift apart the way a parallel []string would.
type category struct {
	name     string
	fixed    func(Config) ([]Finding, error)
	classify func(cfg Config, path, name string) []Finding
}

// categories lists every RFC.md §4 category, in the same order as
// AllFindingTypes. Scan emits findings in this order so output (and NDJSON in
// particular) is deterministic across runs, even though record_id — not list
// position — is the documented dedup key.
var categories = []category{
	{name: "shell configs", fixed: ScanShellConfigs},
	{name: ".env files", classify: classifyEnvFile},
	{name: "credential files", fixed: scanKnownCredentialFiles, classify: classifyCredentialWalkFile},
	{name: "MCP configs", fixed: scanClaudeDesktopMCPConfig, classify: classifyMCPFile},
	{name: "private keys", fixed: ScanPrivateKeys},
	{name: "IaC files", classify: classifyIACFile},
	{name: "wrappable CLI tokens", fixed: ScanWrappableCLITokens},
	{name: "SOPS age keys", fixed: ScanSOPSAgeKeys},
}

// Scan runs every category and returns the individual findings plus the
// aggregate summary (RFC.md §4).
func Scan(cfg Config) ([]Finding, ScanSummary, error) {
	start := time.Now()

	// The one traversal, up front, feeding every category's classify half at
	// once. Findings land in per-category buckets rather than one flat slice
	// so the assembly loop below still emits them grouped by category, in
	// walk order within each — identical output to the days when each
	// category walked for itself.
	if cfg.Progress != nil {
		cfg.Progress("home directory")
	}
	discovered := discoverByWalk(cfg)

	var all []Finding
	for i, c := range categories {
		// Every category reports, including the pure-discovery ones whose work
		// the walk above already did (their step settles instantly). The trail
		// is an inventory of what jit looked at, not a profile of where the
		// time went, and dropping four categories from it just because they
		// now share a traversal would leave a user unable to see that .env
		// files and IaC files were covered at all.
		if cfg.Progress != nil {
			cfg.Progress(c.name)
		}
		var fixed []Finding
		if c.fixed != nil {
			var ferr error
			fixed, ferr = c.fixed(cfg)
			if ferr != nil {
				return all, ScanSummary{}, ferr
			}
			all = append(all, fixed...)
		}
		all = append(all, dropAlreadyReported(fixed, discovered[i])...)
	}

	// Tag findings under archived/backup-looking directories centrally
	// (not per scanner): `jit migrate home` skips exactly these by default,
	// and the report renderers surface the tag so that skip is legible from
	// the audit side of the funnel too.
	for i := range all {
		all[i].Archived = LooksArchived(all[i].FilePath)
	}

	summary := buildScanSummary(cfg, all, countProtectedMounts(cfg.MountRegistryPath), time.Since(start))
	return all, summary, nil
}

// dropAlreadyReported returns walked without any finding the same category's
// fixed half already produced, matched on record_id. Exactly one file needs
// this today — the global ~/.npmrc, probed directly by scanGlobalNpmrc and
// also reachable by the walk that finds project-local ones — and handling it
// at this seam is what lets the classifier stay honest for `jit scan <dir>`,
// where no fixed half runs and a path exclusion inside the classifier would
// mean the file is reported by nobody at all.
//
// Deliberately NOT a blanket dedupe of every finding in the scan: record_id is
// (finding_type, file_path, key_name), so two exports of the same key name on
// different lines of one shell config share one — and those are two real
// findings, not a duplicate. Only the fixed/walk seam, where the same scanner
// genuinely read the same file twice, is collapsed.
func dropAlreadyReported(fixed, walked []Finding) []Finding {
	if len(fixed) == 0 || len(walked) == 0 {
		return walked
	}
	seen := make(map[string]bool, len(fixed))
	for _, f := range fixed {
		seen[f.RecordID] = true
	}
	out := make([]Finding, 0, len(walked))
	for _, f := range walked {
		if !seen[f.RecordID] {
			out = append(out, f)
		}
	}
	return out
}

// walkConcurrency bounds how many directories discoverByWalk reads at once. A
// home-directory walk is syscall-latency-bound, not CPU-bound — a sequential
// one measured ~20% CPU, the rest spent waiting on the filesystem — so the
// useful number sits above GOMAXPROCS: the extra goroutines are parked in
// readdir, not competing for a core.
var walkConcurrency = max(4, runtime.NumCPU()*2)

// discoverByWalk runs the single shared home-directory walk, offering each
// file to every category's classify half. It returns one bucket per category,
// indexed by position in categories — a category with no classify half simply
// gets an empty one, which keeps the caller's indexing trivial. It cannot
// fail: every per-entry error (a permission-denied directory, a file deleted
// mid-walk) is a skip, because one unreadable file must not take down an
// audit.
//
// Per-file cost is a handful of string comparisons against the DirEntry name
// already in hand: no stat, no open, nothing beyond what the traversal itself
// pays. On a real machine the name gates select ~0.2% of walked files, so
// everything expensive (opening, parsing, content matching) still happens only
// for the handful of files a category actually claims.
//
// Directories are read concurrently. Each goroutine classifies into buckets it
// alone owns and merges them once, at the end, under the mutex — so the
// per-file hot path never touches a lock. Findings are sorted by path
// afterwards, since concurrent traversal has no inherent order; the sort is
// stable, so several findings from one file keep the order their classifier
// emitted them in.
func discoverByWalk(cfg Config) [][]Finding {
	newBuckets := func() [][]Finding { return make([][]Finding, len(categories)) }

	var (
		mu     sync.Mutex
		merged = newBuckets()
		sem    = make(chan struct{}, walkConcurrency)
		wg     sync.WaitGroup
	)
	mergeInto := func(src [][]Finding) {
		mu.Lock()
		defer mu.Unlock()
		for i := range src {
			merged[i] = append(merged[i], src[i]...)
		}
	}

	// walkDir reads one directory: files are classified into local (this
	// goroutine's own buckets), subdirectories are handed to the pool. When
	// every slot is taken it recurses inline instead of queueing the work,
	// which is what makes the fan-out deadlock-free without an unbounded
	// queue — a saturated pool degrades to a plain sequential walk rather
	// than to a goroutine waiting on a slot it can only get by finishing.
	var walkDir func(dir string, local [][]Finding) [][]Finding
	walkDir = func(dir string, local [][]Finding) [][]Finding {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return local
		}
		for _, e := range entries {
			path := filepath.Join(dir, e.Name())
			if e.IsDir() {
				if SkipNoiseDir(cfg.HomeDir, path, e.Name()) {
					continue
				}
				wg.Add(1)
				select {
				case sem <- struct{}{}:
					go func(sub string) {
						defer wg.Done()
						defer func() { <-sem }()
						mergeInto(walkDir(sub, newBuckets()))
					}(path)
				default:
					local = walkDir(path, local)
					wg.Done()
				}
				continue
			}
			// Only regular files reach a classifier — see walkHomeDir for why
			// a symlink and a named pipe are both skipped here.
			if !e.Type().IsRegular() {
				continue
			}
			for i, c := range categories {
				if c.classify != nil {
					local[i] = append(local[i], c.classify(cfg, path, e.Name())...)
				}
			}
		}
		return local
	}

	// The root itself is never tested against SkipNoiseDir: a home directory
	// that happens to be named "build" is still the directory we were asked
	// to scan.
	mergeInto(walkDir(cfg.HomeDir, newBuckets()))
	wg.Wait()

	for i := range merged {
		sort.SliceStable(merged[i], func(a, b int) bool {
			return merged[i][a].FilePath < merged[i][b].FilePath
		})
	}
	return merged
}

// walkForCategory is the one-category form of discoverByWalk, backing the
// exported per-category scanners (ScanEnvFiles, ScanIACFiles, …). Those keep
// working standalone — for tests, and for anyone consuming this package one
// category at a time — while dispatching to the very same classify function
// the machine-wide walk uses. "Which files does this category claim" therefore
// has exactly one definition, so the standalone and unified paths cannot
// drift; an earlier version of this package had two such lists, and they did.
func walkForCategory(cfg Config, classify func(cfg Config, path, name string) []Finding) ([]Finding, error) {
	var findings []Finding
	err := walkHomeDir(cfg.HomeDir, func(path string, d fs.DirEntry) error {
		findings = append(findings, classify(cfg, path, d.Name())...)
		return nil
	})
	return findings, err
}

// countProtectedMounts returns how many of the mount registry's entries are
// currently live (a named pipe occupies the registered path). Purely
// informational — walkHomeDir's regular-file guard is what actually keeps
// scanners away from pipes, registry or no registry — so any failure here
// (no registry, unreadable, malformed) is a 0, never an error: this
// package's read-only scan must not fail because jit's own bookkeeping is
// absent or damaged. A registered path that is a regular file again (e.g.
// someone replaced the pipe by hand) is deliberately NOT counted: whatever
// is in that file now is plaintext at rest, and the scanners will judge it
// like any other file.
func countProtectedMounts(registryPath string) int {
	if registryPath == "" {
		return 0
	}
	entries, err := mount.LoadRegistry(registryPath)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if info, statErr := os.Lstat(e.MountPath); statErr == nil && info.Mode()&os.ModeNamedPipe != 0 {
			n++
		}
	}
	return n
}

func buildScanSummary(cfg Config, findings []Finding, protectedMounts int, duration time.Duration) ScanSummary {
	byCategory := map[string]int{}
	for _, ft := range AllFindingTypes {
		byCategory[ft] = 0 // RFC.md §4: "all seven keys always present"
	}

	prodCount := 0
	ipCount := 0
	for _, f := range findings {
		byCategory[f.FindingType]++
		if f.ProductionIndicatorMatch {
			prodCount++
		}
		if f.PublicIPMatch != nil {
			ipCount++
		}
	}

	return ScanSummary{
		RecordType:               RecordTypeScanSummary,
		RecordID:                 nil, // always null — run_id is already unique per run
		SchemaVersion:            SchemaVersion,
		ScannerName:              ScannerName,
		ScannerVersion:           cfg.ScannerVersion,
		RunID:                    cfg.RunID,
		ScanTime:                 nowISO8601(),
		Endpoint:                 cfg.Endpoint,
		TotalFindings:            len(findings),
		FindingsByCategory:       byCategory,
		RiskLevel:                ComputeRiskLevel(findings),
		ExposureScore:            ComputeExposureScore(findings),
		ProductionIndicatorCount: prodCount,
		PublicIPCount:            ipCount,
		ScanDurationMs:           duration.Milliseconds(),
		JitProtectedCount:        protectedMounts,
	}
}

// ComputeRiskLevel implements RFC.md §4's risk-level table, aggregating
// across every finding from a scan:
//
//	Critical: any production-indicator match or public IP found
//	High:     unencrypted SSH key, a loose key/cert file outside a
//	          protected directory, any shell-config plaintext export,
//	          any MCP-embedded secret, or >=5 total findings
//	Medium:   >=3 total findings
//	Low:      1-2 total findings
//	Clean:    0 findings
//
// Rather than hardcoding which finding_types can produce a High-severity
// finding (RFC.md §4's own list — unencrypted SSH key, loose key/cert file,
// shell-config export, MCP-embedded secret — happens to be exactly the set
// of categories that assign Severity: High today), this checks
// Finding.Severity directly. That is behaviorally identical for those
// categories, and it fixes a real gap the hardcoded version had: a single
// FindingTypeCredentialFile finding (a real AWS/kubeconfig/GCP credential,
// always Severity: High per credfile.go) was NOT escalating the aggregate
// risk level, because credential_file was missing from the hardcoded list.
// It also means a future category that starts assigning Severity: High
// (e.g. envfile.go's secret-shaped-variable-name escalation) is covered
// automatically instead of needing a second place to remember to update.
func ComputeRiskLevel(findings []Finding) string {
	for _, f := range findings {
		if f.ProductionIndicatorMatch || f.PublicIPMatch != nil {
			return RiskLevelCritical
		}
	}

	highTriggered := false
	for _, f := range findings {
		if f.Severity == SeverityHigh {
			highTriggered = true
			break
		}
	}

	switch {
	case highTriggered || len(findings) >= 5:
		return RiskLevelHigh
	case len(findings) >= 3:
		return RiskLevelMedium
	case len(findings) >= 1:
		return RiskLevelLow
	default:
		return RiskLevelClean
	}
}
