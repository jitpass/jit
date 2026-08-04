// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/termtext"
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
	// cmd is the house color for anything the reader can type, and for the
	// arrow that introduces it — the same cyan `jit status` and every hlCmds
	// call site use. See design/output-style.md, "Colour means one thing".
	cmd := color.New(color.FgCyan)

	// --- header: who, where, how much, how fast ---
	where := "~/"
	if home == "" {
		where = "scan targets"
	}
	sizeNote := ""
	if summary.FilesScanned > 0 {
		sizeNote = fmt.Sprintf(" (%s files)", groupDigits(summary.FilesScanned))
	}
	termtext.Wrap(w, 0, "", dim.Sprintf("jit scan — %s@%s — scanned %s%s — %s",
		summary.Endpoint.Username, summary.Endpoint.Hostname, where, sizeNote,
		formatDuration(summary.ScanDurationMs)))
	fmt.Fprintln(w)

	// A partial scan must never be able to look like a complete one. This sits
	// ABOVE the ledger, not in a footnote, because it changes what every number
	// below it means: "0 secrets" from a run that could not read ~/.aws
	// is not the same claim as "0 secrets", and the difference is exactly the
	// one a user reading a clean report will not think to ask about.
	if len(summary.DegradedScanners) > 0 {
		fmt.Fprint(w, "  ")
		noun := "categories"
		if len(summary.DegradedScanners) == 1 {
			noun = "category"
		}
		termtext.Wrap(w, 2, "  ", yellowBold.Sprintf("INCOMPLETE SCAN — %d %s could not be read", len(summary.DegradedScanners), noun))
		for _, d := range summary.DegradedScanners {
			fmt.Fprint(w, triageNoteIndent)
			// Home shortened, and an em-dash rather than a colon separator:
			// the underlying error is already of the form "open <path>: reason",
			// so a colon here stacked three deep on one line. Both are what the
			// rest of this report does with a path.
			termtext.Wrap(w, len(triageNoteIndent), triageNoteIndent,
				yellow.Sprintf("%s — %s", d.Scanner, oneLine(shortenHomeInText(home, d.Error))))
		}
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ", dim.Sprint("Counts below cover everything else; secrets in the unread categories are not included."))
		fmt.Fprintln(w)
	}

	migratable := triageGroupMigratable(findings)
	manual := triageGroupManual(findings, home)

	// --- the coverage ledger ---
	pct := cov.Percent()
	after := cov.PercentAfterMigrate()
	fmt.Fprint(w, "  ")
	termtext.Wrap(w, 2, "  ",
		bold.Sprintf("YOUR SECRETS: %d — ", cov.Total())+
			green.Sprintf("%d protected by jit (%d%%)", cov.Protected, pct))
	fmt.Fprint(w, "  ")
	writeBar(w, pct)
	if cov.Total() > 0 && (cov.Migratable > 0 || len(manual) > 0) {
		// Assembled first, then wrapped: the bar is a fixed 10 columns and the
		// clause beside it is prose, so at a narrow width the clause has to
		// break under itself rather than push the line past the edge.
		clause := dim.Sprint("  to 100%:")
		if cov.Migratable > 0 {
			clause += dim.Sprint(" one command ")
			if after == pct {
				// 1 migratable of 200 rounds to +0%, which reads as
				// "pointless" — it isn't.
				clause += greenBold.Sprint("+<1%")
			} else {
				clause += greenBold.Sprintf("+%d%%", after-pct)
			}
		}
		if len(manual) > 0 {
			if cov.Migratable > 0 {
				clause += dim.Sprint(" ·")
			}
			clause += dim.Sprintf(" %s only you can fix ", countWord(len(manual), "thing", "things"))
			clause += yellow.Sprintf("+%d%%", pctOf(cov.manualRemainder(), cov.Total()))
		}
		termtext.Wrap(w, 2+coverageBarWidth, "  "+strings.Repeat(" ", coverageBarWidth), clause)
	} else {
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)

	// --- green: what jit will do ---
	if len(migratable) > 0 {
		fmt.Fprint(w, "  ")
		// A migratable file whose every secret ALSO exists somewhere the
		// recommended command will not rewrite — in practice, a
		// production-flagged token pasted at the shell, so it sits in both the
		// config file and a history line whose remedy is manual rotation —
		// gains no coverage: that plaintext copy survives the migrate. (An
		// ordinary history copy migrates now, via in-place redaction, so it no
		// longer pins its group here.) The work is still worth doing, so the
		// block stays, but printing "0 secrets in 1 file, 0% → 0%" over a real
		// recommendation reads as a broken report rather than as the honest
		// statement it is. Name the files, drop the arithmetic, and say why
		// below.
		header := greenBold.Sprint("jit will protect these")
		if cov.Migratable == 0 {
			header += dim.Sprintf(" — %s", countWord(len(migratable), "file", "files"))
		} else {
			header += dim.Sprintf(" — %s in %s, ", countWord(cov.Migratable, "secret", "secrets"), countWord(len(migratable), "file", "files")) +
				greenBold.Sprintf("%d%% → %d%%", pct, after)
		}
		termtext.Wrap(w, 2, "  ", header)
		fmt.Fprint(w, triageNoteIndent)
		// Cyan, not green: cyan is what the reader can type, on every jit
		// surface. Green still carries this section — its header and its
		// coverage arithmetic are green — but it reports the state of the
		// block, and putting it on the command too made scan the one report
		// where a runnable thing wasn't cyan.
		_, _ = cmd.Fprintln(w, "→ jit migrate")
		wraps := 0
		for _, m := range migratable {
			if m.wrapTool != "" {
				wraps++
			}
		}
		intro := fmt.Sprintf("one command; it vaults the values and rewrites %s", countWord(len(migratable)-wraps, "file", "files"))
		if wraps > 0 {
			intro += " and wraps " + countWord(wraps, "CLI", "CLIs")
		}
		fmt.Fprint(w, manifestIndent)
		termtext.Wrap(w, len(manifestIndent), manifestIndent,
			dim.Sprintf("%s — every tool that reads them keeps working:", intro))
		writeMigrateManifest(w, migratable, home, dim, green)
		fmt.Fprint(w, triageNoteIndent)
		note := "these sat in plaintext until now — rotating after vaulting is the " +
			"gold standard · every change is reversible: jit migrate undo"
		if cov.Migratable == 0 {
			note = "every secret here also sits somewhere this migrate will not rewrite, so the score " +
				"moves only once you rotate — protecting the file is still worth doing · " +
				"every change is reversible: jit migrate undo"
		}
		termtext.Wrap(w, len(triageNoteIndent), triageNoteIndent, dim.Sprint(note))
		writeHistoryGuardOffer(w, findings, cmd, dim)
		fmt.Fprintln(w)
	}

	// --- red: what only the user can do ---
	if len(manual) > 0 {
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ",
			red.Sprint("only you can protect these")+
				dim.Sprintf(" — %s, ", countWord(cov.manualRemainder(), "secret", "secrets"))+
				yellowBold.Sprintf("%d%% → 100%%", after))
		for _, g := range manual {
			fmt.Fprint(w, "    ")
			if g.critical {
				_, _ = red.Fprint(w, "!")
			} else {
				_, _ = yellowBold.Fprint(w, "!")
			}
			fmt.Fprint(w, " ")
			termtext.Wrap(w, 6, triageNoteIndent,
				bold.Sprint(g.title)+dim.Sprintf("  (%d)", g.secrets))
			// One exemplar line per file set. A merged group keeps every one
			// of them: the sets are different files, and collapsing them to a
			// single exemplar would hide paths the reader has to go and fix.
			for _, d := range g.details {
				_, _ = dim.Fprintf(w, "%s%s\n", triageNoteIndent,
					termtext.TruncHead(d, termtext.Width()-len(triageNoteIndent)))
			}
			fmt.Fprint(w, triageNoteIndent)
			// The arrow is cyan because it is the action motif; the
			// instruction after it is default weight. Amber used to paint the
			// whole line, which made a sentence of plain advice ("rotate them
			// now") read as a warning state — amber's job, and it already has
			// the "!" glyph above to do it with.
			_, _ = cmd.Fprint(w, "→ ")
			termtext.Wrap(w, len(triageNoteIndent)+2, triageNoteIndent+"  ", g.action)
		}
		fmt.Fprintln(w)
	}

	if len(migratable) == 0 && len(manual) == 0 {
		if cov.Protected > 0 {
			_, _ = green.Fprintln(w, "  Nothing exposed. Every secret jit knows about is already protected.")
		} else {
			_, _ = green.Fprintln(w, "  Nothing exposed. This machine looks clean.")
		}
		fmt.Fprintln(w)
	}

	// --- what jit found and does not cover ---
	//
	// This view is the one people actually read, which makes it the one place
	// this cannot be missing: the whole reason to say it is that "nothing
	// exposed" is otherwise misread as "nothing left here." A user who
	// migrated ~/.aws/credentials and saw a clean report would have no way to
	// know a live plaintext session token was still sitting beside it.
	//
	// It stays under the verdict, not in it: these are not exposures jit is
	// declining to fix, they are working files that belong to other tools.
	// Nothing here moves a count.
	if len(summary.DerivedCredentials) > 0 {
		_, _ = bold.Fprintln(w, "  Outside jit's scope, found anyway:")
		for _, d := range summary.DerivedCredentials {
			fmt.Fprintf(w, "    %s\n", displayFilePath(home, d.Path))
			_, _ = dim.Fprintf(w, "      %s\n", d.What)
		}
		_, _ = dim.Fprintln(w, "  jit protects credentials you stored; these were minted by the tools")
		_, _ = dim.Fprintln(w, "  that used them, and jit does not manage, rotate or hide them.")
		fmt.Fprintln(w)
	}

	// --- the honesty line: what jit saw and does not charge for ---
	quiet := 0
	archived := 0
	fixtures := 0
	for _, f := range findings {
		switch {
		case f.TestFixture:
			// Counted separately from the low-confidence sightings: jit is
			// not unsure about these, it is saying they are not the user's
			// credentials to rotate. Lumping them under "low-confidence"
			// would misdescribe both groups.
			fixtures++
		case !CountedAsSecret(f):
			quiet++
		case f.Archived && f.Remedy != RemedyManual:
			archived++
		}
	}
	// Seven lines of dim prose used to close the report, explaining in full
	// sentences what jit had DECLINED to count — at the bottom of the one
	// view a user actually reads, after the part that asks them to act. It is
	// one tally and one command now: the reader who wants the detail goes and
	// gets it, and everyone else gets their attention back.
	var notCounted []string
	if fixtures > 0 {
		notCounted = append(notCounted, countWord(fixtures, "test fixture", "test fixtures"))
	}
	if archived > 0 {
		notCounted = append(notCounted, fmt.Sprintf("%d in archived folders", archived))
	}
	if quiet > 0 {
		notCounted = append(notCounted, countWord(quiet, "low-confidence sighting", "low-confidence sightings"))
	}
	if len(notCounted) > 0 {
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ", dim.Sprintf("Not counted: %s.", strings.Join(notCounted, " · ")))
	}
	fmt.Fprint(w, "  ")
	_, _ = cmd.Fprint(w, "→ ")
	termtext.Wrap(w, 4, "    ",
		cmd.Sprint("jit scan --full")+dim.Sprint("   the full inventory · ndjson for machines"))
	fmt.Fprintln(w)
	_, _ = dim.Fprintln(w, "  No secret values are ever printed in full.")
}

// The report's two hanging indents: the manifest's rows and the notes that
// bracket them. Named so a continuation line lands under the text it
// continues rather than at column 0.
const (
	manifestIndent   = "        "
	triageNoteIndent = "      "
)

// Layout floors for the manifest's two columns. Below their sum there isn't
// room for a path AND a label on one line, and squeezing them produces two
// truncated columns that each say nothing — at which point stacking the label
// under its path is strictly more readable.
const (
	minManifestPathCol  = 24
	minManifestLabelCol = 18
)

// writeMigrateManifest lays out the "what jit will rewrite" table inside the
// window. The column used to be padded to the longest path, which on a real
// machine is a ~63-character Application Support path — every row then ran to
// 125 columns and the terminal broke it wherever it liked, dropping the label
// under the path and destroying the alignment the table existed for.
//
// Paths are cut at the FRONT (TruncHead): the tail names the file, the prefix
// is the part every row repeats. When even the floors don't fit, the label
// stacks under its path instead — one honest pair of lines beats two columns
// truncated past the point of meaning.
func writeMigrateManifest(w io.Writer, rows []triageFile, home string, dim, green *color.Color) {
	budget := termtext.Width() - len(manifestIndent) - 2
	if budget < minManifestPathCol+minManifestLabelCol {
		for _, m := range rows {
			_, _ = dim.Fprintf(w, "%s%s\n", manifestIndent,
				termtext.TruncHead(ShortenHome(home, m.file), termtext.Width()-len(manifestIndent)))
			_, _ = dim.Fprintf(w, "%s  %s", manifestIndent,
				termtext.TruncTail(m.label, termtext.Width()-len(manifestIndent)-2))
			writeWrapTool(w, m, green)
		}
		return
	}
	longestPath, widestLabel := 0, 0
	for _, m := range rows {
		longestPath = max(longestPath, len(ShortenHome(home, m.file)))
		widestLabel = max(widestLabel, len(m.label))
	}
	// Give the path everything the labels don't need, but never more than half
	// the budget to a label column that only wants a few words.
	pathW := min(longestPath, max(minManifestPathCol, budget-min(widestLabel, budget/2)))
	labelW := budget - pathW
	for _, m := range rows {
		p := termtext.TruncHead(ShortenHome(home, m.file), pathW)
		_, _ = dim.Fprintf(w, "%s%-*s  %s", manifestIndent, pathW, p,
			termtext.TruncTail(m.label, labelW))
		writeWrapTool(w, m, green)
	}
}

func writeWrapTool(w io.Writer, m triageFile, green *color.Color) {
	if m.wrapTool != "" {
		_, _ = green.Fprintf(w, " · wraps %s", m.wrapTool)
	}
	fmt.Fprintln(w)
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
			key = sanitizeDisplay(*f.KeyName)
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
	title string
	// details holds one exemplar line per distinct file set. A merged group
	// keeps them all: each set is a different pile of files to go and fix, so
	// collapsing to one exemplar would hide paths the reader needs.
	details  []string
	action   string
	secrets  int
	critical bool
	sortKey  int // lower renders first
	// files is the total number of file copies the group spans, summed across
	// merged constituents so a merged title can state the real spread.
	files int
	// sample and ctx are kept so a merged group can REGENERATE its action
	// against the combined counts. Inheriting the first constituent's wording
	// told a reader with three exposed passwords to "rotate it now".
	sample Finding
	ctx    manualContext
	// noun is the title without its copy count — the merge key. Three
	// "An exposed database password in N copies of a file" groups differ only
	// in N and in which files, and printing three near-identical headers with
	// three identical actions spent nine lines saying one thing three times.
	noun string
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
	// A file holding one production-flagged secret sets the verdict for every
	// secret found in it: once a file is known to have carried production
	// credentials in plaintext, "protect it in place" is the wrong sentence
	// for anything else inside it. Collected across ALL counted findings, not
	// just the manual ones, so the judgement does not depend on which secret
	// in the file happened to be the sample.
	productionFiles := map[string]bool{}
	for _, f := range findings {
		if CountedAsSecret(f) && f.ProductionIndicatorMatch {
			productionFiles[f.FilePath] = true
		}
	}

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
		ctx := manualContext{secrets: len(p.causes), copies: len(p.files)}
		for _, file := range p.files {
			if productionFiles[file] {
				ctx.production = true
				break
			}
		}
		out = append(out, triageManualGroup{
			secrets:  len(p.causes),
			critical: worst.Severity == SeverityCritical,
			sortKey:  rankOf(worst.Severity),
			title:    manualTitle(p.causes, p.files, worst),
			details:  []string{manualDetail(p.files, worst, home)},
			action:   manualAction(worst, ctx, home),
			noun:     manualNoun(worst),
			files:    len(p.files),
			sample:   worst,
			ctx:      ctx,
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].sortKey < out[b].sortKey })
	return mergeManualGroups(out, home)
}

// mergeManualGroups folds groups that name the same kind of secret AND ask for
// the same fix into one block. It merges the header and the action, never the
// evidence: every constituent group's exemplar line survives, so the merged
// block points at exactly as many files as the separate ones did.
//
// Only same-noun, same-action groups merge, which is what keeps this safe —
// two problems that need different fixes stay two blocks no matter how alike
// their titles read.
func mergeManualGroups(groups []triageManualGroup, home string) []triageManualGroup {
	type key struct{ noun, action string }
	at := map[key]int{}
	var out []triageManualGroup
	for _, g := range groups {
		k := key{g.noun, g.action}
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, g)
			continue
		}
		m := &out[i]
		m.secrets += g.secrets
		m.files += g.files
		m.details = append(m.details, g.details...)
		m.critical = m.critical || g.critical
		if g.sortKey < m.sortKey {
			m.sortKey = g.sortKey
		}
	}
	for i := range out {
		if len(out[i].details) > 1 {
			out[i].title = fmt.Sprintf("%s — %d separate secrets in %s",
				out[i].noun, out[i].secrets,
				countWord(out[i].files, "file copy", "file copies"))
			out[i].ctx.secrets = out[i].secrets
			out[i].ctx.copies = out[i].files
			out[i].action = manualAction(out[i].sample, out[i].ctx, home)
		}
	}
	return out
}

// writeHistoryGuardOffer adds the prevention line when this scan found a
// credential in shell history.
//
// It sits here, in the report, because this is the moment the user learns
// they have this problem at all. The offer used to live only in `jit migrate`'s
// post-run output, which inverted who heard it: you were told how to stop the
// NEXT credential reaching your history only after one already had, and only
// if you ran the fix. Anyone whose history was clean — the people with the
// most to gain from never starting — never learned the command existed.
//
// One line, with what it does rather than just its name: "jit guard history"
// means nothing to someone seeing it for the first time, and a command whose
// effect a reader cannot guess is one they will not run.
func writeHistoryGuardOffer(w io.Writer, findings []Finding, cmd, dim *color.Color) {
	found := false
	for _, f := range findings {
		if f.FindingType == FindingTypeShellHistorySecret && CountedAsSecret(f) && !f.Archived {
			found = true
			break
		}
	}
	if !found {
		return
	}
	fmt.Fprint(w, triageNoteIndent)
	_, _ = cmd.Fprint(w, "jit guard history")
	termtext.Wrap(w, len(triageNoteIndent)+len("jit guard history"), triageNoteIndent,
		dim.Sprint("   stops the next one being recorded: a zsh hook keeps a command "+
			"carrying a credential out of your history file, while leaving it usable in that session"))
}

// manualTitle names the problem in the user's terms: what it is and, when
// it spans copies, how wide it spread. It never says "finding" or a
// severity word — the noun is the secret, the number is the file spread.
func manualTitle(causes []*triageCause, files []string, worst Finding) string {
	// History is titled by WHERE, not by how many files it spread to. Two
	// history files are ~/.zsh_history and ~/.bash_history, which are two
	// shells' records of the same habit — calling that "2 copies of a file"
	// describes a duplicated config, which is not what happened.
	if IsShellHistoryPath(worst.FilePath) {
		if len(causes) > 1 {
			return fmt.Sprintf("%d credentials in shell history", len(causes))
		}
		return manualNoun(worst)
	}
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
	case selfRotating(f):
		c, _ := selfRotatingCacheFor(f.FilePath)
		return c.title
	case isTerraformState(f.FilePath):
		return "A live credential recorded in Terraform state"
	case f.FindingType == FindingTypeIACVariableFile:
		return "A Kubernetes Secret manifest with real values"
	case f.FindingType == FindingTypeShellHistorySecret:
		// The location IS the problem here, so it belongs in the title rather
		// than only in the dim path line below: "An exposed GitHub token" and
		// "A GitHub token in shell history" call for different actions, and
		// the reader decides what to do from this line.
		if f.KeyName != nil && IsPrivateKeyVendor(*f.KeyName) {
			return fmt.Sprintf("%s material typed at the shell", strings.TrimSuffix(*f.KeyName, " Private Key")+" private key")
		}
		if k := shortSecretLabel(f.KeyName); k != "" {
			return fmt.Sprintf("A %s in shell history", k)
		}
		return "A credential in shell history"
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
	shown := ShortenHome(home, first)
	// A history file is thousands of lines long and the fix is to find one of
	// them, so the line number is not a detail — it is the whole address. No
	// other manual finding needs it, because "~/.gemini/oauth_creds.json" is
	// already the location.
	if IsShellHistoryPath(first) && worst.Line != nil {
		shown = fmt.Sprintf("%s:%d", shown, *worst.Line)
	}
	if len(files) == 1 {
		return shown
	}
	return fmt.Sprintf("%s … and %d more", shown, len(files)-1)
}

// selfRotating reports whether f's file is one the owning tool rewrites for
// itself — a mount would be fought by that tool. See selfRotatingCache.
func selfRotating(f Finding) bool { return isSelfRotatingCache(f.FilePath) }

// manualContext is what the action line needs beyond the sample finding: how
// many secrets this problem holds, how many files they were found in, and
// whether ANY finding in those files carried a production indicator.
//
// The last two exist because the action used to be decided from one sample
// finding alone, which let a single file collect contradictory instructions.
// A real scan (2026-07-29) printed "rotate them now, then delete every copy"
// and "protect in place: jit migrate … --mount" for the SAME report file,
// because one of its secrets was production-flagged and another was not.
// Advice a user cannot follow both halves of is worse than no advice.
type manualContext struct {
	secrets    int
	copies     int
	production bool
}

// manualAction is the arrow line: the user-world verb for this problem.
//
// Order is precedence, most specific first, and the two rules above the
// --mount offer are what keep it honest. A secret that spread to several
// copies cannot be fixed by mounting one of them — the other twelve stay
// plaintext — and a file no program reads at run time gains nothing from a
// pipe (see mountable). Both fall through to the instruction that actually
// resolves the exposure: rotate it, then delete what leaked.
func manualAction(f Finding, ctx manualContext, home string) string {
	them := "it"
	if ctx.secrets > 1 {
		them = "them"
	}
	switch {
	case f.FindingType == FindingTypePrivateKeyRisk:
		return "add a passphrase (ssh-keygen -p) or move the key somewhere safer"
	case selfRotating(f):
		c, _ := selfRotatingCacheFor(f.FilePath)
		return c.action
	case isTerraformState(f.FilePath):
		return "rotate " + them + " now; move state to an encrypted remote backend, and keep secrets out of it with ephemeral values (Terraform 1.10+)"
	case f.FindingType == FindingTypeIACVariableFile:
		return "seal it (sealed-secrets/SOPS) or move it to a real secret store"
	case f.FindingType == FindingTypeShellHistorySecret && f.KeyName != nil && IsPrivateKeyVendor(*f.KeyName):
		// A key is not a token: there is no provider to rotate it at, and the
		// line jit matched is the header, so the body is still on the lines
		// around it. Deleting is the user's job here, not jit's.
		return "regenerate the key and replace it wherever it is authorized, then delete those lines by hand"
	case f.FindingType == FindingTypeShellHistorySecret:
		// Above the production branch on purpose. A production credential in
		// history still needs the history instruction, not "delete every
		// copy": there is one copy, deleting it is the easy half, and the
		// half that actually resolves the exposure is the rotation.
		//
		// Rotation leads because it is the fix. The secret has already been
		// written to disk in plaintext, and history files are backed up by
		// Time Machine and committed to dotfile repos as a matter of routine,
		// so removing the line does not un-expose anything that has already
		// left. The closing clause is the part users get wrong: zsh and bash
		// hold history in memory and rewrite the file on exit, so a line
		// deleted while another shell is open comes back.
		lines, file := "the line", "this file"
		if ctx.secrets > 1 {
			lines = "the lines"
		}
		if ctx.copies > 1 {
			file = "these files"
		}
		return fmt.Sprintf("rotate %s at the provider now, then remove %s — your shell rewrites %s on exit, so close other shells first",
			them, lines, file)
	case ctx.production || f.ProductionIndicatorMatch:
		return fmt.Sprintf("rotate %s now, then delete every copy", them)
	case ctx.copies > 1:
		return fmt.Sprintf("rotate %s now, then delete every copy", them)
	case !mountable(f.FilePath):
		return fmt.Sprintf("move %s out of the file, then rotate", them)
	default:
		// A mixed-content file bare migrate skips on purpose, that a program
		// really does read at run time: offer the in-place protection that
		// DOES exist, alongside the honest fix.
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

// coverageBarWidth is how many columns writeBar occupies — the width the
// clause beside it has to hang under when it wraps.
const coverageBarWidth = 10

// writeBar renders the ten-cell coverage bar.
func writeBar(w io.Writer, pct int) {
	filled := pct / 10
	_, _ = color.New(color.FgGreen).Fprint(w, strings.Repeat("▰", filled))
	_, _ = color.New(color.Faint).Fprint(w, strings.Repeat("▱", coverageBarWidth-filled))
}
