// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// WriteTriageReport is `jit scan`'s default human output: the coverage-first,
// action-first view. It answers, in order, the only three questions a user
// has — how covered am I, what will jit do for me, what must I do myself —
// and deliberately shows NO scanner vocabulary: no categories, no severity
// labels, no finding counts as headline numbers. All of that still exists,
// unchanged, behind `jit scan --full` (WriteHumanReport) and NDJSON; this
// view is the funnel, not the inventory.
//
// Layout rules, each one earned in design review (2026-07-28):
//   - Distinct SECRETS are the only counted unit. Findings are how scanners
//     talk; nobody triages 39 findings that are 3 secrets in 13 copies.
//   - Paths appear in full where the user is about to act on those files
//     (the migrate manifest — consent needs detail) and compress to one
//     exemplar + count where they merely describe a problem.
//   - Low/Info sightings cost one dim line, never sections. What jit does
//     not stand behind, it does not spend the user's attention on.
func WriteTriageReport(w io.Writer, findings []Finding, summary ScanSummary, home string, cov Coverage) {
	dim := color.New(color.Faint)
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	greenBold := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	yellowBold := color.New(color.FgYellow, color.Bold)

	// --- header: who, where, how much, how fast ---
	where := "~/"
	if home == "" {
		where = "scan targets"
	}
	sizeNote := ""
	if summary.FilesScanned > 0 {
		sizeNote = fmt.Sprintf(" (%s files)", groupDigits(summary.FilesScanned))
	}
	dim.Fprintf(w, "jit scan — %s@%s — scanned %s%s — %s\n\n",
		summary.Endpoint.Username, summary.Endpoint.Hostname, where, sizeNote,
		formatDuration(summary.ScanDurationMs))

	migratable := triageGroupMigratable(findings)
	manual := triageGroupManual(findings, home)

	// --- the coverage ledger ---
	pct := cov.Percent()
	after := cov.PercentAfterMigrate()
	fmt.Fprint(w, "  ")
	bold.Fprintf(w, "YOUR SECRETS: %d — ", cov.Total())
	green.Fprintf(w, "%d protected by jit (%d%%)\n", cov.Protected, pct)
	fmt.Fprint(w, "  ")
	writeBar(w, pct)
	if cov.Total() > 0 && (cov.Migratable > 0 || len(manual) > 0) {
		dim.Fprint(w, "  to 100%:")
		if cov.Migratable > 0 {
			dim.Fprint(w, " one command ")
			if after == pct {
				// 1 migratable of 200 rounds to +0%, which reads as
				// "pointless" — it isn't.
				greenBold.Fprint(w, "+<1%")
			} else {
				greenBold.Fprintf(w, "+%d%%", after-pct)
			}
		}
		if len(manual) > 0 {
			if cov.Migratable > 0 {
				dim.Fprint(w, " ·")
			}
			manualSecrets := 0
			for _, g := range manual {
				manualSecrets += g.secrets
			}
			dim.Fprintf(w, " %d thing(s) only you can fix ", len(manual))
			yellow.Fprintf(w, "+%d%%", pctOf(manualSecrets, cov.Total()))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	// --- green: what jit will do ---
	if len(migratable) > 0 {
		fmt.Fprint(w, "  ")
		greenBold.Fprint(w, "jit will protect these")
		dim.Fprintf(w, " — %d secret(s) in %d file(s), ", cov.Migratable, len(migratable))
		greenBold.Fprintf(w, "%d%% → %d%%\n", pct, after)
		fmt.Fprint(w, "      ")
		green.Fprintln(w, "→ jit migrate")
		wraps := 0
		for _, m := range migratable {
			if m.wrapTool != "" {
				wraps++
			}
		}
		intro := fmt.Sprintf("one command; it vaults the values and rewrites %d file(s)", len(migratable)-wraps)
		if wraps > 0 {
			intro += fmt.Sprintf(" and wraps %d CLI(s)", wraps)
		}
		dim.Fprintf(w, "        %s —\n        every tool that reads them keeps working:\n", intro)
		pathW := 0
		for _, m := range migratable {
			pathW = max(pathW, len(ShortenHome(home, m.file)))
		}
		for _, m := range migratable {
			p := ShortenHome(home, m.file)
			dim.Fprintf(w, "        %-*s  %s", pathW, p, m.label)
			if m.wrapTool != "" {
				green.Fprintf(w, " · wraps %s", m.wrapTool)
			}
			fmt.Fprintln(w)
		}
		dim.Fprintln(w, "      these sat in plaintext until now — rotating after vaulting is")
		dim.Fprintln(w, "      the gold standard · every change is reversible: jit migrate undo")
		fmt.Fprintln(w)
	}

	// --- red: what only the user can do ---
	if len(manual) > 0 {
		fmt.Fprint(w, "  ")
		red.Fprint(w, "only you can protect these")
		manualSecrets := 0
		for _, g := range manual {
			manualSecrets += g.secrets
		}
		dim.Fprintf(w, " — %d secret(s), ", manualSecrets)
		yellowBold.Fprintf(w, "%d%% → 100%%\n", after)
		for _, g := range manual {
			fmt.Fprint(w, "    ")
			if g.critical {
				red.Fprint(w, "!")
			} else {
				yellowBold.Fprint(w, "!")
			}
			fmt.Fprint(w, " ")
			bold.Fprint(w, g.title)
			dim.Fprintf(w, "  (%d)\n", g.secrets)
			if g.detail != "" {
				dim.Fprintf(w, "      %s\n", g.detail)
			}
			yellow.Fprintf(w, "      → %s\n", g.action)
		}
		fmt.Fprintln(w)
	}

	if len(migratable) == 0 && len(manual) == 0 {
		if cov.Protected > 0 {
			green.Fprintln(w, "  Nothing exposed. Every secret jit knows about is already protected.")
		} else {
			green.Fprintln(w, "  Nothing exposed. This machine looks clean.")
		}
		fmt.Fprintln(w)
	}

	// --- the honesty line: what jit saw and does not charge for ---
	quiet := 0
	archived := 0
	for _, f := range findings {
		if !CountedAsSecret(f) {
			quiet++
		} else if f.Archived && f.Remedy != RemedyManual {
			archived++
		}
	}
	if archived > 0 {
		dim.Fprintf(w, "  %d finding(s) sit in archived/backup folders — jit migrate skips those\n", archived)
		dim.Fprintln(w, "  by default; name one explicitly (jit migrate <path>) to protect it")
	}
	if quiet > 0 {
		dim.Fprintf(w, "  jit also saw %d low-confidence sighting(s) it does not judge to be\n", quiet)
		dim.Fprintln(w, "  secrets — review them with jit scan --full · ndjson for machines")
	} else {
		dim.Fprintln(w, "  full inventory: jit scan --full · ndjson for machines")
	}
	dim.Fprintln(w, "  No secret values are ever printed in full.")
}

// triageFile is one row of the migrate manifest: a file jit will rewrite (or
// a CLI it will wrap) and a human label for what's inside it.
type triageFile struct {
	file     string
	label    string
	wrapTool string
}

// triageGroupMigratable folds counted, non-archived, jit-actionable findings
// into one manifest row per file. The label is the key names the scanners
// reported, deduplicated, capped at two — the row is consent ("what will
// this command touch"), not the inventory.
func triageGroupMigratable(findings []Finding) []triageFile {
	type agg struct {
		keys     []string
		seen     map[string]bool
		wrapTool string
	}
	byFile := map[string]*agg{}
	var order []string
	for _, f := range findings {
		if f.Remedy == RemedyManual || f.Remedy == "" || !CountedAsSecret(f) || f.Archived {
			continue
		}
		a, ok := byFile[f.FilePath]
		if !ok {
			a = &agg{seen: map[string]bool{}}
			byFile[f.FilePath] = a
			order = append(order, f.FilePath)
		}
		if f.Remedy == RemedyWrap {
			a.wrapTool = strings.TrimPrefix(f.FixCommand, "jit wrap ")
		}
		key := ""
		if f.KeyName != nil {
			key = *f.KeyName
		}
		if key != "" && !a.seen[key] {
			a.seen[key] = true
			a.keys = append(a.keys, key)
		}
	}
	sort.Strings(order)
	out := make([]triageFile, 0, len(order))
	for _, file := range order {
		a := byFile[file]
		label := "secret-shaped values"
		switch {
		case len(a.keys) == 1:
			label = a.keys[0]
		case len(a.keys) == 2:
			label = a.keys[0] + ", " + a.keys[1]
		case len(a.keys) > 2:
			label = fmt.Sprintf("%s + %d more", a.keys[0], len(a.keys)-1)
		}
		out = append(out, triageFile{file: file, label: label, wrapTool: a.wrapTool})
	}
	return out
}

// triageManualGroup is one red-section item: a problem the user must fix,
// possibly spanning many files (copies collapse on cause group).
type triageManualGroup struct {
	title    string
	detail   string
	action   string
	secrets  int
	critical bool
	sortKey  int // lower renders first
}

// triageCause is one distinct manual secret: every finding sharing its
// cause id, the files it was seen in, and the worst-severity sample.
type triageCause struct {
	files    []string
	seenFile map[string]bool
	sample   Finding
}

// triageGroupManual folds counted manual findings into problems. Causes
// sharing an identical file SET are one problem with several secrets (the
// copied-report case: 13 files × 3 values reads as one item, "(3)"), which
// is exactly how a person describes it: "my export reports leak three
// credentials", not thirty-nine findings.
func triageGroupManual(findings []Finding, home string) []triageManualGroup {
	byCause := map[string]*triageCause{}
	var causeOrder []string
	for _, f := range findings {
		if f.Remedy != RemedyManual || !CountedAsSecret(f) {
			continue
		}
		id := f.CauseGroup
		if id == "" {
			id = f.RecordID
		}
		c, ok := byCause[id]
		if !ok {
			c = &triageCause{seenFile: map[string]bool{}, sample: f}
			byCause[id] = c
			causeOrder = append(causeOrder, id)
		}
		if !c.seenFile[f.FilePath] {
			c.seenFile[f.FilePath] = true
			c.files = append(c.files, f.FilePath)
		}
		if rankOf(f.Severity) < rankOf(c.sample.Severity) {
			c.sample = f
		}
	}

	// Merge causes living in the same file set into one problem.
	type problem struct {
		causes []*triageCause
		files  []string
	}
	byFileSet := map[string]*problem{}
	var setOrder []string
	for _, id := range causeOrder {
		c := byCause[id]
		sort.Strings(c.files)
		sig := strings.Join(c.files, "\x00")
		p, ok := byFileSet[sig]
		if !ok {
			p = &problem{files: c.files}
			byFileSet[sig] = p
			setOrder = append(setOrder, sig)
		}
		p.causes = append(p.causes, c)
	}

	var out []triageManualGroup
	for _, sig := range setOrder {
		p := byFileSet[sig]
		worst := p.causes[0].sample
		for _, c := range p.causes {
			if rankOf(c.sample.Severity) < rankOf(worst.Severity) {
				worst = c.sample
			}
		}
		out = append(out, triageManualGroup{
			secrets:  len(p.causes),
			critical: worst.Severity == SeverityCritical,
			sortKey:  rankOf(worst.Severity),
			title:    manualTitle(p.causes, p.files, worst),
			detail:   manualDetail(p.files, worst, home),
			action:   manualAction(worst, len(p.causes) > 1, home),
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].sortKey < out[b].sortKey })
	return out
}

// manualTitle names the problem in the user's terms: what it is and, when
// it spans copies, how wide it spread. It never says "finding" or a
// severity word — the noun is the secret, the number is the file spread.
func manualTitle(causes []*triageCause, files []string, worst Finding) string {
	noun := manualNoun(worst)
	if len(causes) > 1 {
		noun = fmt.Sprintf("%d credentials", len(causes))
	}
	if len(files) > 1 {
		return fmt.Sprintf("%s in %d copies of a file", noun, len(files))
	}
	return noun
}

// manualNoun is the one-line "what is this" for a single manual secret.
func manualNoun(f Finding) string {
	switch {
	case f.FindingType == FindingTypePrivateKeyRisk:
		return "An at-risk private key"
	case strings.Contains(f.FilePath, string(filepath.Separator)+mcpAuthDir+string(filepath.Separator)):
		return "A remote-MCP OAuth token (rotates itself)"
	case f.FindingType == FindingTypeIACVariableFile:
		return "A Kubernetes Secret manifest with real values"
	case f.ProductionIndicatorMatch:
		if k := shortSecretLabel(f.KeyName); k != "" {
			return fmt.Sprintf("A production %s", k)
		}
		return "A production credential"
	case f.KeyName != nil && *f.KeyName != "":
		return fmt.Sprintf("An exposed %s", shortSecretLabel(f.KeyName))
	default:
		return "An exposed credential"
	}
}

// shortSecretLabel turns a scanner's vendor label into title-sized language:
// "Database connection string with embedded credentials (scheme-less)" is a
// pattern's name for its own precision, not something a problem title should
// carry. Unknown labels pass through.
func shortSecretLabel(key *string) string {
	if key == nil {
		return ""
	}
	k := *key
	switch {
	case strings.Contains(k, "connection string"):
		return "database password"
	case strings.Contains(k, "JSON Web Token"):
		return "JWT"
	default:
		return k
	}
}

// manualDetail is the dim second line: where, compressed — one exemplar
// path plus a count, never the full list (that's --full's job; the red
// section describes, it doesn't ask the user to run anything on these
// exact paths).
func manualDetail(files []string, worst Finding, home string) string {
	if len(files) == 0 {
		return ""
	}
	first := worst.FilePath
	if first == "" {
		first = files[0]
	}
	if len(files) == 1 {
		return ShortenHome(home, first)
	}
	return fmt.Sprintf("%s … and %d more", ShortenHome(home, first), len(files)-1)
}

// manualAction is the arrow line: the user-world verb for this problem.
func manualAction(f Finding, plural bool, home string) string {
	them := "it"
	if plural {
		them = "them"
	}
	switch {
	case f.FindingType == FindingTypePrivateKeyRisk:
		return "add a passphrase (ssh-keygen -p) or move the key somewhere safer"
	case strings.Contains(f.FilePath, string(filepath.Separator)+mcpAuthDir+string(filepath.Separator)):
		return "revoke at the provider if exposed; reset with rm -rf ~/.mcp-auth"
	case f.FindingType == FindingTypeIACVariableFile:
		return "seal it (sealed-secrets/SOPS) or move it to a real secret store"
	case f.ProductionIndicatorMatch:
		return fmt.Sprintf("rotate %s now, then delete every copy", them)
	default:
		// A mixed-content file bare migrate skips on purpose: offer the
		// in-place protection that DOES exist, alongside the honest fix.
		return fmt.Sprintf("protect in place: jit migrate %s --mount · or move the secret out, then rotate",
			shellSafePath(home, f.FilePath))
	}
}

func formatDuration(ms int64) string {
	if ms >= 1000 {
		return fmt.Sprintf("%.1fs", float64(ms)/1000)
	}
	return fmt.Sprintf("%dms", ms)
}

// groupDigits renders 47312 as "47,312" — the walk size is a credibility
// number and unbroken digit runs read poorly past four digits.
func groupDigits(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func pctOf(part, total int) int {
	if total == 0 {
		return 0
	}
	return part * 100 / total
}

// writeBar renders the ten-cell coverage bar.
func writeBar(w io.Writer, pct int) {
	filled := pct / 10
	color.New(color.FgGreen).Fprint(w, strings.Repeat("▰", filled))
	color.New(color.Faint).Fprint(w, strings.Repeat("▱", 10-filled))
}
