// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/jitpass/jit/internal/style"
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
//   - Low/Info sightings cost one line, never sections. What jit does
//     not stand behind, it does not spend the user's attention on.
func WriteTriageReport(w io.Writer, findings []Finding, summary ScanSummary, home string, cov Coverage) {
	bold := style.Bold
	green := style.OK
	greenBold := style.OKBold
	red := style.RiskBold
	yellow := style.Warn
	yellowBold := style.WarnBold
	// cmd is the house color for anything the reader can type, and for the
	// arrow that introduces it — the same cyan `jit status` and every hlCmds
	// call site use. See design/output-style.md, "Colour means one thing".
	cmd := style.Path

	// --- header: who, where, how much, how fast ---
	where := "~/"
	if home == "" {
		where = "scan targets"
	}
	sizeNote := ""
	if summary.FilesScanned > 0 {
		// Inflected, and grouped: "1 file", "25,130 files". countWord would
		// give the inflection but print a bare 25130 — the digit grouping is
		// what makes the walk size read as a credibility number rather than a
		// wall — so the two are composed rather than one chosen.
		sizeNote = fmt.Sprintf(" · %s %s", groupDigits(summary.FilesScanned),
			pluralWord(summary.FilesScanned, "file", "files"))
	}
	// "jit scan  ~/ · 25,130 files · 11.7s" — the command, then what it
	// covered, in the "·" separator the rest of the report uses for a run of
	// facts. It was an em-dash chain carrying user@host, which is a fourth
	// header shape in a tool that has one, and which spent its most prominent
	// line telling the reader their own username and hostname. Both are things
	// the program knows and the reader already does; the diagnostic surfaces
	// (`jit doctor`, NDJSON's endpoint block) are where machine identity earns
	// its place.
	head := style.Bold.Sprint("jit scan") + "  " + where
	if sizeNote != "" {
		head += sizeNote
	}
	head += " · " + formatDuration(summary.ScanDurationMs)
	termtext.Wrap(w, 0, "", head)
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
		termtext.Wrap(w, 2, "  ", "Counts below cover everything else; secrets in the unread categories are not included.")
		fmt.Fprintln(w)
	}

	migratable := triageGroupMigratable(findings)
	manual := triageGroupManual(findings, home)
	// Built once, here, because the ledger COUNTS it and the section below
	// RENDERS it. Counting len(manual) — the problems — while displaying the
	// action groups they fold into promised "13 things only you can fix" over
	// a section showing eight blocks: the same "a number naming nothing the
	// reader can find" bug the archived group was added to fix, in the other
	// unit. Whatever the bar says the reader must be able to count on screen.
	actions := groupManualByAction(manual, home)

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
		clause := "  to 100%:"
		if cov.Migratable > 0 {
			clause += " one command "
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
				clause += " ·"
			}
			// SECRETS, the same unit and the same number as the red header
			// below — not "N things".
			//
			// The pile was being counted three ways at once: the bar said
			// "13 things" (problems), the header said "32 secrets", and each
			// item carried a "(N)" badge. Fixing the badge and the header left
			// two units still disagreeing, and switching the bar to count
			// action groups only moved the disagreement — the reader would see
			// "8 things" over a section holding thirteen "!" items, both
			// countable on screen and neither matching. One denominator ends
			// it: the bar and the header are now the same sentence about the
			// same number, and the grouping below is organisation rather than
			// a third tally.
			clause += fmt.Sprintf(" %s only you can fix ",
				countWord(cov.manualRemainder(), "secret", "secrets"))
			// The remainder is what's LEFT of 100 after the migrate, never its
			// own division. manualRemainder/Total is the same quantity in
			// exact arithmetic, but printed it is a third independent floor:
			// 50 protected, 11 migratable, 32 manual of 93 rendered as
			// "53% ... +12% ... +34%", which sums to 99 on the same line the
			// red header below promises "→ 100%". Deriving it from `after`
			// makes the three numbers close by construction, which is what
			// Coverage.manualRemainder's comment already claims they do.
			//
			// The trade, stated because it is a deliberate inaccuracy: this
			// term now absorbs the rounding error of all three, so it can read
			// up to two points above the manual bucket's true share (the
			// 50/11/32 case prints +35% against a true 34.4%). Three numbers
			// on one line that sum to 99 is a visible error; one number a
			// fraction high is not, and consistency is what the reader is
			// actually checking.
			clause += yellow.Sprintf("+%d%%", 100-after)
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
			header += fmt.Sprintf(" — %s", countWord(len(migratable), "file", "files"))
		} else {
			header += fmt.Sprintf(" — %s in %s, ", countWord(cov.Migratable, "secret", "secrets"), countWord(len(migratable), "file", "files")) +
				greenBold.Sprintf("%d%% "+style.GlyphAction+" %d%%", pct, after)
		}
		termtext.Wrap(w, 2, "  ", header)
		fmt.Fprint(w, triageNoteIndent)
		// Cyan, not green: cyan is what the reader can type, on every jit
		// surface. Green still carries this section — its header and its
		// coverage arithmetic are green — but it reports the state of the
		// block, and putting it on the command too made scan the one report
		// where a runnable thing wasn't cyan.
		_, _ = cmd.Fprintln(w, style.GlyphAction+" jit migrate")
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
			fmt.Sprintf("%s — every tool that reads them keeps working:", intro))
		writeMigrateManifest(w, migratable, home, green)
		fmt.Fprint(w, triageNoteIndent)
		// Present tense: they still ARE in plaintext. "Sat … until now" told
		// the reader the scan had changed something, and the whole point of
		// this block is that nothing has changed yet and one command would.
		note := "these are in plaintext now — rotating after vaulting is the " +
			"gold standard · every change is reversible: jit migrate undo"
		if cov.Migratable == 0 {
			note = "every secret here also sits somewhere this migrate will not rewrite, so the score " +
				"moves only once you rotate — protecting the file is still worth doing · " +
				"every change is reversible: jit migrate undo"
		}
		termtext.Wrap(w, len(triageNoteIndent), triageNoteIndent, note)
		writeHistoryGuardOffer(w, findings, summary, cmd, false)
		fmt.Fprintln(w)
	}

	// --- red: what only the user can do ---
	if len(manual) > 0 {
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ",
			red.Sprint("only you can protect these")+
				fmt.Sprintf(" — %s, ", countWord(cov.manualRemainder(), "secret", "secrets"))+
				yellowBold.Sprintf("%d%% "+style.GlyphAction+" 100%%", after))
		for _, ag := range actions {
			fmt.Fprintln(w)
			fmt.Fprint(w, "    ")
			// Rule 1's header shape, and the count only when there is more
			// than one to count — "[protect in place] 1" invites the reader to
			// compare a number against nothing.
			hdr := fmt.Sprintf("[%s]", ag.kind)
			if ag.secrets > 1 {
				hdr += fmt.Sprintf(" %d", ag.secrets)
			}
			termtext.Wrap(w, 4, "    ", hdr)
			for _, g := range ag.items {
				writeManualItem(w, g, home, bold, red, yellowBold)
			}
			if ag.note != "" {
				// A note may carry several facts, one per \n-separated line,
				// each wrapped on its own — flowing them into one paragraph
				// would glue "…still vaults it" to "already protected…" mid-
				// line, and the one-fact-per-line rule is the house style's.
				for _, fact := range strings.Split(ag.note, "\n") {
					fmt.Fprint(w, triageNoteIndent)
					termtext.Wrap(w, len(triageNoteIndent), triageNoteIndent, fact)
				}
			}
			fmt.Fprint(w, triageNoteIndent)
			// The arrow is cyan because it is the action motif; the
			// instruction after it is default weight. Amber used to paint the
			// whole line, which made a sentence of plain advice ("rotate them
			// now") read as a warning state — amber's job, and it already has
			// the "!" glyph above to do it with.
			_, _ = cmd.Fprint(w, style.GlyphAction+" ")
			// One line either way, but which kind of line decides the cut. A
			// sentence action ("rotate them now, …") truncates, never wraps:
			// it restates the group header, so its tail is expendable. A
			// COMMAND is the opposite — cut anywhere it stops being a
			// command, and a real scan (2026-08-07) shipped an archived-group
			// `jit migrate …` whose ellipsis ate half its targets. A command
			// prints whole as ONE logical line: the archived group's
			// parent-directory form keeps it short, and any explicit-path
			// form soft-wraps in the terminal while still pasting as a
			// single command.
			//
			// Keyed on the ACTION, not on the kind. The 2026-08-07 fix asked
			// `ag.kind == kindArchived` and asserted archived was the only
			// command on these arrows; kindProtectInPlace returns
			// `jit migrate <path> --mount` and was already sitting in the
			// truncating branch, so at 80 columns its path was cut
			// mid-component and the --mount flag vanished silently — a
			// command that reads as complete and does something else. Asking
			// the string removes the chance to add a third command-shaped
			// kind and forget again.
			if isCommandAction(ag.action) {
				// Cyan, like every other command jit prints — the migrate
				// trailer, the --full footer, `jit scan` in the way-back
				// link. These group arrows printed theirs in default weight,
				// so the one command in a block was the only uncoloured
				// command in the report (spotted by a reader, 2026-08-09).
				// The rule the surrounding comment states is about ADVICE:
				// painting a sentence made it read as a warning state. A
				// command is not a sentence, and cyan is its ink.
				_, _ = cmd.Fprintln(w, ag.action)
			} else {
				// Prose WRAPS now; it used to truncate. The justification for
				// cutting it was that "it restates the group header, so its
				// tail is expendable" — true of the three arrows that did
				// restate their header, and those have been rewritten to
				// carry the fact the header cannot. Nothing on this line is
				// expendable any more, and truncation was silently eating the
				// additive half of the two arrows that never restated
				// anything: "…replace it wherever it is authorized, then
				// delet…" and "…sign out and back in to reset — the …", both
				// cut at 80 columns (measured 2026-08-09).
				//
				// Wrapping rather than shortening the sentences, because a
				// short sentence is a property of today's strings and this is
				// a property of the renderer: the next arrow written one word
				// too long would lose its meaning the same silent way.
				termtext.Wrap(w, len(triageNoteIndent)+2, triageNoteIndent+"  ", ag.action)
			}
		}
		fmt.Fprintln(w)
	}

	if len(migratable) == 0 && len(manual) == 0 {
		if cov.Protected > 0 {
			_, _ = green.Fprintln(w, "  Nothing exposed. Every secret jit knows about is already protected.")
		} else {
			_, _ = green.Fprintln(w, "  Nothing exposed. This machine looks clean.")
		}
		// Clean is exactly when prevention is the only thing left to offer,
		// and it was the one outcome that offered nothing.
		writeHistoryGuardOffer(w, findings, summary, cmd, true)
		fmt.Fprintln(w)
	}
	writeTriageFooter(w, findings, summary, home, bold, cmd)
}

// writeManualItem prints one problem inside an action group: the marked title,
// the address, the evidence, and how to look at it. No arrow — the instruction
// belongs to the group, not the item.
func writeManualItem(w io.Writer, g triageManualGroup, home string, bold, red, yellowBold *color.Color) {
	fmt.Fprint(w, "    ")
	if g.critical {
		_, _ = red.Fprint(w, style.GlyphMark)
	} else {
		_, _ = yellowBold.Fprint(w, style.GlyphMark)
	}
	fmt.Fprint(w, " ")
	// No "(N)" badge. The count it carried is on the group header now, and
	// where a problem spans copies the title already says so — "2 credentials
	// in 18 copies of a file  (2)" counted the same thing twice in one line
	// and left the reader deciding which number meant files.
	termtext.Wrap(w, 6, triageNoteIndent, bold.Sprint(g.title))
	// What the credential was called where jit found it, when the line said
	// so unambiguously (assignedCredentialName). It sits with the title
	// rather than with an address because it answers "what is this", not
	// "where is it": a title naming only the vendor reads identically for a
	// live release-publishing token and for a test vector, which is how a
	// real scan (2026-08-09) buried the former among the latter.
	if g.assignedName != "" {
		fmt.Fprintf(w, "%s%s assigned to %s\n", triageNoteIndent, style.GlyphBranch, g.assignedName)
	}
	// The addresses. When jit recorded a line for the files (content and
	// shell-history findings), list every one grouped by folder, each as
	// "name:line" — a reader sees where the copies are and at which line
	// without running a grep. writeManualFileListing handles that and returns
	// true; the old exemplar/hint path below stands in for the findings that
	// still carry no line (structured mcp/env/private-key, until the tier-2
	// scanner work) and for agent caches, whose copies are hash-named and
	// addressed by their origin instead.
	if writeManualFileListing(w, g, home) {
		return
	}
	// One exemplar line per file set. A merged group keeps every one of them:
	// the sets are different files, and collapsing to one exemplar would hide
	// paths the reader has to go and fix.
	//
	// Two hint shapes, told apart by count rather than by index arithmetic.
	// Normally hints are PARALLEL to details — one per address, same index —
	// and each address must be followed by ITS OWN hint. collapsePatternHints
	// instead folds a whole group into ONE grep covering every file, and that
	// single hint belongs after ALL the addresses, not paired with the first.
	collapsed := len(g.hints) == 1 && len(g.details) > 1
	for i, d := range g.details {
		fmt.Fprintf(w, "%s%s\n", triageNoteIndent,
			termtext.TruncHead(d, termtext.Width()-len(triageNoteIndent)))
		if !collapsed && i < len(g.hints) {
			writeManualHint(w, g.hints[i])
		}
	}
	if collapsed {
		writeManualHint(w, g.hints[0])
	} else {
		for i := len(g.details); i < len(g.hints); i++ {
			writeManualHint(w, g.hints[i])
		}
	}
	// The viewing hint sits with the address it explains and ABOVE the arrow,
	// per design/output-style.md: an explanation never follows the action
	// line, because the action is meant to be the last thing on screen.
	// Reading order comes out as the reader's own order anyway — here is the
	// coordinate, here is how to reach it, here is what to do once you have.
	//
	// Glyphless, matching the address line it follows. A glyph would claim
	// this line carries a state of its own, which is the distinction
	// printStatusWarnNote exists to keep.
	//
	// It WRAPS rather than truncating, unlike the address above it. A path cut
	// at the front still identifies the file; a command cut anywhere is no
	// longer a command, and "…mcp_servers/okta-mcp-server/.env" is not
	// something a reader can paste.
}

// writeManualHint prints one evidence line under the address it explains.
func writeManualHint(w io.Writer, h string) {
	if h == "" {
		return
	}
	fmt.Fprint(w, triageNoteIndent)
	termtext.Wrap(w, len(triageNoteIndent), triageNoteIndent+"  ", h)
}

// writeManualFileListing prints the group's files grouped by folder, each as
// "name:line", and reports whether it did. It handles the findings jit has a
// coordinate for; it declines (returns false) for agent caches — whose copies
// are hash-named and belong under their origin, handled by the old path — and
// for findings with no line recorded at all, so those keep the "how to view"
// grep until the tier-2 scanner work gives them a line.
//
// Why folder-grouping: a widely-copied secret sits in files whose NAMES are
// near-identical (developer_secrets_<timestamp>.html) and whose FOLDERS are
// what differ. The flat, left-truncated exemplar list this replaces showed
// the identical tail and cut the folder — the one part that told the copies
// apart (2026-08-09). Naming each folder once, with its files beneath,
// answers "where are they, are they together" at a glance.
//
// Folders are relevance-ordered: an ordinary location first, then ~/Downloads,
// then archived/backup trees. A credential's likely home should lead; a
// derived copy should not sit at the top just because its path sorts first,
// which is what alphabetical order did. No stronger claim than that ordering
// is made — jit does not assert a file is "just a copy".
func writeManualFileListing(w io.Writer, g triageManualGroup, home string) bool {
	if g.sample.FindingType == FindingTypeAgentCachedSecret || len(g.fileLine) == 0 {
		return false
	}
	seen := map[string]bool{}
	var files []string
	for _, f := range g.fileList {
		if f != "" && !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return false
	}

	// A single file needs no folder header — the compact one-liner the reader
	// already liked (~/.gemini/oauth_creds.json:5).
	if len(files) == 1 {
		fmt.Fprintf(w, "%s%s\n", triageNoteIndent,
			termtext.TruncHead(fileAddr(home, files[0], g.fileLine, g.fileEnd), termtext.Width()-len(triageNoteIndent)))
		return true
	}

	byDir := map[string][]string{}
	for _, f := range files {
		d := filepath.Dir(f)
		byDir[d] = append(byDir[d], f)
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.SliceStable(dirs, func(a, b int) bool {
		ra, rb := dirRelevance(home, dirs[a]), dirRelevance(home, dirs[b])
		if ra != rb {
			return ra < rb
		}
		return dirs[a] < dirs[b]
	})

	const fileIndent = "        " // one step past the folder header
	for _, d := range dirs {
		header := ShortenHome(home, d) + "/"
		fmt.Fprintf(w, "%s%s\n", triageNoteIndent,
			termtext.TruncHead(header, termtext.Width()-len(triageNoteIndent)))
		names := byDir[d]
		sort.Strings(names)
		for _, f := range names {
			line := filepath.Base(f)
			if ln, ok := g.fileLine[f]; ok {
				line = fmt.Sprintf("%s:%d", line, ln)
				if e, ok := g.fileEnd[f]; ok {
					line = fmt.Sprintf("%s-%d", line, e)
				}
			}
			fmt.Fprintf(w, "%s%s\n", fileIndent,
				termtext.TruncHead(line, termtext.Width()-len(fileIndent)))
		}
	}
	return true
}

// fileAddr renders one file as "path:line" (or "path:line-end" for a block),
// falling back to the bare path when no line was recorded.
func fileAddr(home, path string, fileLine, fileEnd map[string]int) string {
	s := ShortenHome(home, path)
	ln, ok := fileLine[path]
	if !ok {
		return s
	}
	s = fmt.Sprintf("%s:%d", s, ln)
	if e, ok := fileEnd[path]; ok {
		s = fmt.Sprintf("%s-%d", s, e)
	}
	return s
}

// dirRelevance ranks a directory for listing order: lower sorts first. An
// ordinary working location leads; a download, then an archived/backup tree,
// sink — a copy in one of those is less likely to be the credential's home.
// Deliberately coarse and signal-based (LooksArchived, a ~/Downloads prefix),
// never a claim that a file IS only a copy.
func dirRelevance(home, dir string) int {
	switch {
	case LooksArchived(dir):
		return 2
	case home != "" && (dir == filepath.Join(home, "Downloads") ||
		strings.HasPrefix(dir, filepath.Join(home, "Downloads")+string(filepath.Separator))):
		return 1
	default:
		return 0
	}
}

// writeTriageFooter closes the report: what jit found outside its scope, what
// it saw and does not charge the reader for, and where the full inventory is.
func writeTriageFooter(w io.Writer, findings []Finding, summary ScanSummary, home string, bold, cmd *color.Color) {
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
			fmt.Fprintf(w, "      %s\n", d.What)
		}
		fmt.Fprintln(w, "  jit protects credentials you stored; these were minted by the tools")
		fmt.Fprintln(w, "  that used them, and jit does not manage, rotate or hide them.")
		fmt.Fprintln(w)
	}

	// --- the honesty line: what jit saw and does not charge for ---
	// Archived findings are deliberately absent from this tally. They used to
	// be its largest entry — "Not counted: 8 in archived folders" — and the
	// claim was false: ComputeCoverage counts them (a live credential in a
	// backup folder is exposed, and remedy_test.go pins that), so they were
	// inside YOUR SECRETS, inside "only you can protect these — 32 secrets",
	// and inside its "+34%", while rendering in no group under any of it.
	// A reader was told 32 and shown 25, under a footer saying jit had not
	// counted the difference. They render in their own action group now, and
	// a line here claiming otherwise would contradict it.
	quiet := 0
	fixtures := 0
	examples := 0
	for _, f := range findings {
		switch {
		case f.TestFixture:
			// Counted separately from the low-confidence sightings: jit is
			// not unsure about these, it is saying they are not the user's
			// credentials to rotate. Lumping them under "low-confidence"
			// would misdescribe both groups.
			fixtures++
		case f.SourceExample:
			// Separate for the same reason: jit matched the value and is
			// saying it documents a shape rather than storing a secret.
			examples++
		case !CountedAsSecret(f):
			quiet++
		}
	}
	// Seven lines of prose used to close the report, explaining in full
	// sentences what jit had DECLINED to count — at the bottom of the one
	// view a user actually reads, after the part that asks them to act. It is
	// one tally and one command now: the reader who wants the detail goes and
	// gets it, and everyone else gets their attention back.
	var notCounted []string
	if fixtures > 0 {
		notCounted = append(notCounted, countWord(fixtures, "test fixture", "test fixtures"))
	}
	if examples > 0 {
		notCounted = append(notCounted, countWord(examples, "source example", "source examples"))
	}
	if quiet > 0 {
		notCounted = append(notCounted, countWord(quiet, "low-confidence sighting", "low-confidence sightings"))
	}
	if len(notCounted) > 0 {
		fmt.Fprint(w, "  ")
		termtext.Wrap(w, 2, "  ", fmt.Sprintf("Not counted: %s.", strings.Join(notCounted, " · ")))
	}
	fmt.Fprint(w, "  ")
	_, _ = cmd.Fprint(w, style.GlyphAction+" ")
	termtext.Wrap(w, 4, "    ",
		cmd.Sprint("jit scan --full")+"   the full inventory · ndjson for machines")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  No secret values are ever printed in full.")
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

// maxManifestPathCol is the CEILING on the path column, and it is the point.
// The width budget below is a limit, not a target: given a wide window the
// path column grew to the longest path in the set, so a 122-character kluctl
// manifest path padded all thirteen of its neighbours out to 122 columns and
// opened a gulf of whitespace between every short path and its label. The
// table exists to be read down, and at that width the eye cannot carry a row
// across it.
//
// Same reasoning, same fix as flowNames' maxFlowWidth (internal/cli/style.go),
// which capped column flow after a 190-column window turned a tidy list into
// an unscannable wall.
const maxManifestPathCol = 56

// writeMigrateManifest lays out the "what jit will rewrite" table inside the
// window. The column used to be padded to the longest path, which on a real
// machine is a ~63-character Application Support path — every row then ran to
// 125 columns and the terminal broke it wherever it liked, dropping the label
// under the path and destroying the alignment the table existed for.
//
// Paths are cut in the MIDDLE (TruncMid): the tail names the file, and the
// HEAD is what distinguishes two paths sharing a long tail. They used to be
// cut at the front, and on a real machine two different okta-mcp-server/.env
// manifests — one live, one under backup_2025/ — shared a 65-character tail,
// so at this column width both rows rendered IDENTICALLY on the screen asking
// the reader to approve rewriting them. When even the floors don't fit, the
// label stacks under its path instead — one honest pair of lines beats two
// columns truncated past the point of meaning.
func writeMigrateManifest(w io.Writer, rows []triageFile, home string, green *color.Color) {
	budget := termtext.Width() - len(manifestIndent) - 2
	if budget < minManifestPathCol+minManifestLabelCol {
		for _, m := range rows {
			fmt.Fprintf(w, "%s%s\n", manifestIndent,
				termtext.TruncMid(ShortenHome(home, m.file), termtext.Width()-len(manifestIndent)))
			fmt.Fprintf(w, "%s  %s", manifestIndent,
				termtext.TruncTail(m.label, termtext.Width()-len(manifestIndent)-2))
			writeWrapTool(w, m, green)
		}
		return
	}
	// Columns, not bytes. TruncHead cuts and %-*s pads in runes, so measuring
	// the widest row with len() sizes the column against a different unit than
	// the one it is filled in: one "é" or "…" in a path buys the column a
	// spare column it never uses. termtext.VisibleWidth is the measure the
	// rest of this package lays out with.
	longestPath, widestLabel := 0, 0
	for _, m := range rows {
		longestPath = max(longestPath, termtext.VisibleWidth(ShortenHome(home, m.file)))
		widestLabel = max(widestLabel, termtext.VisibleWidth(m.label))
	}
	// Give the path everything the labels don't need, but never more than half
	// the budget to a label column that only wants a few words.
	pathW := min(longestPath, max(minManifestPathCol, budget-min(widestLabel, budget/2)))
	// The cap never fights the floor: a window too narrow to give the path
	// maxManifestPathCol keeps whatever the budget allowed.
	pathW = min(pathW, max(minManifestPathCol, maxManifestPathCol))
	labelW := budget - pathW
	for _, m := range rows {
		p := termtext.TruncMid(ShortenHome(home, m.file), pathW)
		fmt.Fprintf(w, "%s%-*s  %s", manifestIndent, pathW, p,
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
//
// A file that only POINTS at a credential is labelled by what it reads
// instead. An MCP config reaching a .env with --env-file was labelled with
// its server name, so the row read as "a secret called okta-mcp-server lives
// here" — the exact misreading that made a user open the file, find nothing,
// and ask why jit had flagged it (2026-08-09). The row has to stay: jit
// migrate really does rewrite that config, and consent means listing every
// file the command touches. Only the label was wrong.
func triageGroupMigratable(findings []Finding) []triageFile {
	type agg struct {
		keys     []string
		seen     map[string]bool
		reads    []string
		seenRead map[string]bool
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
			a = &agg{seen: map[string]bool{}, seenRead: map[string]bool{}}
			byFile[f.FilePath] = a
			order = append(order, f.FilePath)
		}
		if f.Remedy == RemedyWrap {
			a.wrapTool = strings.TrimPrefix(f.FixCommand, "jit wrap ")
		}
		if f.OriginPath != "" {
			// Named by the last two components: the manifest column is narrow,
			// and "okta-mcp-server/.env" identifies the target beside the row
			// that lists it in full directly below.
			r := shortTailPath(f.OriginPath)
			if r != "" && !a.seenRead[r] {
				a.seenRead[r] = true
				a.reads = append(a.reads, r)
			}
			continue
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
		// Only when the file holds nothing of its own. A config carrying both
		// an embedded secret and a pointer is labelled by the secret — that is
		// the thing in it.
		if len(a.keys) == 0 && len(a.reads) > 0 {
			if len(a.reads) == 1 {
				out = append(out, triageFile{file: file, label: "reads " + a.reads[0], wrapTool: a.wrapTool})
			} else {
				out = append(out, triageFile{file: file, label: fmt.Sprintf("reads %d credential files", len(a.reads)), wrapTool: a.wrapTool})
			}
			continue
		}
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

// shortTailPath names a file by its last two components — "okta/.env" — for
// a column too narrow for the whole path. The full path is always available
// elsewhere in the report; this is an identifier, not an address.
func shortTailPath(p string) string {
	p = filepath.ToSlash(p)
	parts := strings.Split(strings.TrimSuffix(p, "/"), "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return ""
}

// triageManualGroup is one red-section item: a problem the user must fix,
// possibly spanning many files (copies collapse on cause group).
// constituents returns every finding this group stands for: the samples
// mergeManualGroups accumulated when it folded groups together, or the lone
// sample when nothing was folded. Callers that build a command covering the
// whole group must use this rather than `sample`, which is one exemplar.
func (g triageManualGroup) constituents() []Finding {
	if len(g.hintSamples) > 0 {
		return g.hintSamples
	}
	return []Finding{g.sample}
}

type triageManualGroup struct {
	title string
	// details holds one exemplar line per distinct file set. A merged group
	// keeps them all: each set is a different pile of files to go and fix, so
	// collapsing to one exemplar would hide paths the reader needs.
	details []string
	// hints holds the optional "how do I look at that?" line for each entry in
	// details, same index, "" where a problem needs none. Parallel to details
	// for the reason details is a slice at all: a hint names one exact address,
	// so a merged group keeping two addresses must keep both hints or send the
	// reader to a line that is not the one under discussion.
	hints []string
	// kind is the short remedy label this problem groups under; action is the
	// full sentence. Both come from manualAction, so a problem can never be
	// filed under one remedy and told to do another.
	kind     string
	action   string
	secrets  int
	critical bool
	sortKey  int // lower renders first
	// files is the total number of file copies the group spans, summed across
	// merged constituents so a merged title can state the real spread.
	files int
	// assignedName is the variable or setting this credential was assigned to
	// where jit found it, when every constituent agrees on one. It is what
	// distinguishes two findings that share a vendor, and so share a title.
	assignedName string
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
	// hintSamples is one constituent sample per entry in hints, same index,
	// kept by the merge so collapsePatternHints can regenerate a combined
	// hint instead of parsing the strings it would be folding.
	hintSamples []Finding
	// fileList is every distinct file this group's secret(s) sit in, and
	// fileLine/fileEnd the line (and closing line, for a key block) each holds
	// it on. writeManualItem lists them grouped by folder, with "name:line"
	// where the line is known, so a reader sees where the copies are and at
	// which line without a grep. Empty fileLine means no coordinate was
	// recorded (a structured mcp/env finding) — the file is still listed, just
	// without a line, and the old "how to view" hint stands in until the
	// tier-2 scanner work gives those findings a line too.
	fileList []string
	fileLine map[string]int
	fileEnd  map[string]int
}

// distinctFileCount counts unique paths in a file list — the number the
// report must show beside a listing built from the same deduplicated set, so
// "in N files" always equals the paths a reader can count beneath it.
func distinctFileCount(files []string) int {
	seen := map[string]bool{}
	for _, f := range files {
		if f != "" {
			seen[f] = true
		}
	}
	return len(seen)
}

// mergeCauseLines unions the per-file line maps of a problem's causes. When
// two causes put different secrets in one file at different lines, the first
// wins — the file is one place to go, and the block's job is to point there,
// not to enumerate every secret in it (the count on the header already does).
func mergeCauseLines(causes []*triageCause) (line, end map[string]int) {
	line = map[string]int{}
	end = map[string]int{}
	for _, c := range causes {
		for p, ln := range c.fileLine {
			if _, ok := line[p]; !ok {
				line[p] = ln
			}
		}
		for p, e := range c.fileEnd {
			if _, ok := end[p]; !ok {
				end[p] = e
			}
		}
	}
	return line, end
}

// triageActionGroup is one block of the red section: every problem that ends
// in the same instruction, with that instruction stated once beneath them.
//
// The section used to be a flat list of problems each carrying its own arrow,
// and on a real machine that printed "rotate them now, then delete every copy"
// five times and "rotate it now; jit migrate cleans the file above" three
// more. Rule 5 of design/output-style.md — state a shared fact once per group
// — and the [missing] example in the Report section are both exactly this
// shape: the group names the remedy, the items are the evidence for it.
type triageActionGroup struct {
	kind     string
	action   string
	note     string
	secrets  int
	critical bool
	sortKey  int
	items    []triageManualGroup
}

// groupManualByAction folds problems into one block per remedy, preserving the
// severity order they arrive in.
//
// The action is REGENERATED from the block's combined totals rather than
// inherited from the first item: the wording inflects on how many secrets and
// copies it covers ("rotate it" vs "rotate them"), so a block built from three
// single-secret problems would otherwise tell a reader with three exposed
// passwords to rotate "it".
func groupManualByAction(groups []triageManualGroup, home string) []triageActionGroup {
	at := map[string]int{}
	var out []triageActionGroup
	for _, g := range groups {
		i, ok := at[g.kind]
		if !ok {
			at[g.kind] = len(out)
			out = append(out, triageActionGroup{
				kind: g.kind, action: g.action, note: actionNote(g.kind),
				secrets: g.secrets, critical: g.critical, sortKey: g.sortKey,
				items: []triageManualGroup{g},
			})
			continue
		}
		b := &out[i]
		b.items = append(b.items, g)
		b.secrets += g.secrets
		b.critical = b.critical || g.critical
		if g.sortKey < b.sortKey {
			b.sortKey = g.sortKey
		}
	}
	for i := range out {
		b := &out[i]
		// One item is not the same as one finding. mergeManualGroups folds
		// same-noun archived findings into a single item carrying every
		// constituent, so a group of six files can arrive here as one item —
		// and skipping on the item count alone left its action as whichever
		// file happened to build it, naming one path for a block listing six.
		if len(b.items) == 1 && len(b.items[0].constituents()) == 1 {
			continue
		}
		worst := b.items[0]
		ctx := manualContext{}
		for _, it := range b.items {
			if it.sortKey < worst.sortKey {
				worst = it
			}
			ctx.secrets += it.ctx.secrets
			ctx.copies += it.ctx.copies
			ctx.production = ctx.production || it.ctx.production
		}
		// Both the label and the arrow are regenerated from the block's real
		// totals, and TOGETHER: the kind is the "[…]" header, the action is
		// the arrow, and manualAction derives them from the same worst+ctx, so
		// taking one and keeping the first item's other let a merged block
		// print a header naming one remedy over an arrow naming another (the
		// invariant at mergeManualGroups is that a problem is never filed under
		// one remedy and told to do a different one). The widened guard above
		// newly routes merged single-item blocks through here, so this has to
		// hold for them too.
		b.kind, b.action = manualAction(worst.sample, ctx, home)
		// One arrow per group is the rule, and for a group whose action NAMES
		// a path that rule has a sharp edge: the archived block's command is
		// `jit migrate <file>`, so regenerating it from the worst item alone
		// would print one path for a block listing several, and a reader who
		// ran it would fix that file and silently leave the rest — having been
		// shown them and given a command that appeared to cover them.
		//
		// Naming every file is honest but unreadable: a real scan (2026-08-07)
		// printed six ~70-char paths on the arrow line. When one directory
		// covers the whole group AND naming it would rediscover every file
		// (`jit migrate <dir>` walks project files only), the command is that
		// directory — the shortest line that keeps the promise. The directory
		// must itself look archived, so the shortening can never widen the
		// command past the boundary the reader consented to: ~/Documents is
		// not a thing this line may name because two archives sit under it.
		// Anything else falls back to the full path list, printed whole.
		if b.kind == kindArchived {
			seen := map[string]bool{}
			var raw, paths []string
			discoverable := true
			// Every constituent finding, not one exemplar per item.
			// mergeManualGroups folds archived findings that share a noun into
			// ONE item (they share a fix, and six identical "! An exposed
			// credential" lines were the cost of not folding them), so
			// iterating b.items alone would see a single sample and build a
			// command naming one of the six files while the block listed all
			// six — the exact "shown them and given a command that appeared to
			// cover them" failure the shortening below exists to prevent.
			// hintSamples is where the merge keeps them.
			for _, it := range b.items {
				for _, s := range it.constituents() {
					if s.FilePath == "" {
						continue
					}
					discoverable = discoverable && dirDiscoverable(s)
					if seen[s.FilePath] {
						continue
					}
					seen[s.FilePath] = true
					raw = append(raw, s.FilePath)
					paths = append(paths, shellSafePath(home, s.FilePath))
				}
			}
			switch dir := commonDir(raw); {
			case discoverable && len(raw) > 1 && dir != "" && LooksArchived(dir):
				b.action = "jit migrate " + shellSafePath(home, dir)
				// The note's first line must describe the command actually
				// printed: "naming a file" under a folder command reads as a
				// mismatch, and the folder form has its own fact to state —
				// the walk inside an explicit target skips nothing.
				b.note = "bare jit migrate walks past archive/ and backups/ on purpose — these are counted above, and naming this folder explicitly migrates everything findable inside it\n" +
					archivedDeletionNote
			case len(paths) > 0:
				b.action = "jit migrate " + strings.Join(paths, " ")
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].sortKey < out[b].sortKey })
	return out
}

// triageCause is one distinct manual secret: every finding sharing its
// cause id, the files it was seen in, and the worst-severity sample.
type triageCause struct {
	files    []string
	seenFile map[string]bool
	sample   Finding
	// fileLine records the line each file holds this secret on (path -> line),
	// and fileEnd its closing line for a block that spans several (a PEM key in
	// shell history). Absent when the finding carries no coordinate — a
	// structured mcp/env/private-key finding, which has a file but not a line
	// until the tier-2 scanner work records one. The report lists a file as
	// "name:line" when its line is known and bare otherwise.
	fileLine map[string]int
	fileEnd  map[string]int
	// assignedName is the variable this credential was assigned to, taken
	// from ANY finding in the cause rather than from sample.
	//
	// A cause is one credential in several places, and the places do not
	// agree about how much they reveal: a token pasted into a prompt is bare
	// in the paste cache and named in the transcript of the command it was
	// pasted into. sample is chosen by severity, so keying the name off it
	// loses the name whenever the worst sighting happens to be the bare one —
	// which is what hid a live Homebrew-tap token behind a title identical to
	// this repository's own test vectors (2026-08-09).
	assignedName string
}

// causeKey is a finding's identity for grouping: its cause group, or its
// record id when it has no value to digest.
func causeKey(f Finding) string {
	if f.CauseGroup != "" {
		return f.CauseGroup
	}
	return f.RecordID
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

	// Cause groups with at least one LIVE copy. An archived finding whose
	// secret also sits in a live file is already covered — bare `jit migrate`
	// protects the live copy and ComputeCoverage counts the group as
	// migratable — so admitting it here would render it twice, once in green
	// and once in red, for one credential.
	liveGroups := map[string]bool{}
	for _, f := range findings {
		if CountedAsSecret(f) && !f.Archived {
			liveGroups[causeKey(f)] = true
		}
	}

	byCause := map[string]*triageCause{}
	var causeOrder []string
	for _, f := range findings {
		if !CountedAsSecret(f) {
			continue
		}
		if f.Remedy != RemedyManual {
			// A non-manual finding belongs to the green section — unless it is
			// archived and orphaned, in which case nothing else in the report
			// will ever name it. ComputeCoverage counts these (remedy_test.go
			// pins that: a live credential in a backup folder is exposed), and
			// the sweep skips them, so before this they inflated "only you can
			// protect these — N secrets" while appearing in no group under it.
			// The report said 32 and showed 25.
			if !f.Archived || liveGroups[causeKey(f)] {
				continue
			}
		}
		id := causeKey(f)
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
		if f.Line != nil {
			if c.fileLine == nil {
				c.fileLine = map[string]int{}
			}
			// First coordinate seen for a file wins; a file holding the same
			// value twice is one address to go to, not two.
			if _, ok := c.fileLine[f.FilePath]; !ok {
				c.fileLine[f.FilePath] = *f.Line
				if f.EndLine != nil && *f.EndLine != *f.Line {
					if c.fileEnd == nil {
						c.fileEnd = map[string]int{}
					}
					c.fileEnd[f.FilePath] = *f.EndLine
				}
			}
		}
		if c.assignedName == "" {
			c.assignedName = f.AssignedName
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
		kind, action := manualAction(worst, ctx, home)
		fileLine, fileEnd := mergeCauseLines(p.causes)
		out = append(out, triageManualGroup{
			secrets:      len(p.causes),
			critical:     worst.Severity == SeverityCritical,
			sortKey:      rankOf(worst.Severity),
			title:        manualTitle(p.causes, p.files, worst, home),
			details:      []string{manualDetail(p.files, worst, home)},
			hints:        []string{manualGroupHint(worst, p.files, home, p.causes)},
			kind:         kind,
			action:       action,
			noun:         manualNoun(worst),
			files:        len(p.files),
			fileList:     append([]string(nil), p.files...),
			fileLine:     fileLine,
			fileEnd:      fileEnd,
			assignedName: groupAssignedName(worst, p.causes),
			sample:       worst,
			ctx:          ctx,
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].sortKey < out[b].sortKey })
	return mergeManualGroups(out, home)
}

// groupAssignedName is the name to show for a problem: the worst finding's
// when it has one, otherwise the first any of its causes offers.
//
// The fallback is the point. A credential is frequently bare where it lives
// and named where it was used — a token pasted into a prompt has no name in
// the paste cache, while the transcript of the command it was pasted INTO
// records one. The causes here are all the same credential (that is what a
// cause group means), so a name found on any of them names all of them.
func groupAssignedName(worst Finding, causes []*triageCause) string {
	if worst.AssignedName != "" {
		return worst.AssignedName
	}
	for _, c := range causes {
		if c.assignedName != "" {
			return c.assignedName
		}
	}
	return ""
}

// mergeManualGroups folds groups that name the same kind of secret AND ask for
// the same fix into one block. It merges the header and the action, never the
// evidence: every constituent group's exemplar line survives, so the merged
// block points at exactly as many files as the separate ones did.
//
// Only same-noun, same-action groups merge, which is what keeps this safe —
// two problems that need different fixes stay two blocks no matter how alike
// their titles read.
//
// The archived kind is keyed on its KIND rather than its action, because its
// action names the individual file (`jit migrate <path>`) and so is unique by
// construction. Keyed on the action, six byte-identical findings — same
// finding type, same nil key name, same severity, same remedy — rendered as
// six consecutive "! An exposed credential" lines differing only in the
// address beneath them (measured 2026-08-09 on six archived .env files).
// They already share one fix: groupManualByAction shortens the whole block to
// a single `jit migrate <common parent>` a few steps later, so merging here
// is not a claim about them, it is the same claim arriving in time to be
// rendered once.
func mergeManualGroups(groups []triageManualGroup, home string) []triageManualGroup {
	type key struct{ noun, action string }
	at := map[key]int{}
	var out []triageManualGroup
	for _, g := range groups {
		k := key{g.noun, g.action}
		if g.kind == kindArchived {
			k = key{g.noun, kindArchived}
		}
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			g.hintSamples = []Finding{g.sample}
			out = append(out, g)
			continue
		}
		m := &out[i]
		m.secrets += g.secrets
		m.files += g.files
		m.details = append(m.details, g.details...)
		m.hints = append(m.hints, g.hints...)
		m.hintSamples = append(m.hintSamples, g.sample)
		m.fileList = append(m.fileList, g.fileList...)
		if m.fileLine == nil {
			m.fileLine = map[string]int{}
		}
		for p, ln := range g.fileLine {
			if _, ok := m.fileLine[p]; !ok {
				m.fileLine[p] = ln
			}
		}
		if len(g.fileEnd) > 0 && m.fileEnd == nil {
			m.fileEnd = map[string]int{}
		}
		for p, e := range g.fileEnd {
			if _, ok := m.fileEnd[p]; !ok {
				m.fileEnd[p] = e
			}
		}
		m.critical = m.critical || g.critical
		// Two constituents that name different variables have no single name
		// to show, and showing one of them would attribute the other's
		// credential to it.
		if m.assignedName != g.assignedName {
			m.assignedName = ""
		}
		if g.sortKey < m.sortKey {
			m.sortKey = g.sortKey
		}
	}
	for i := range out {
		if len(out[i].details) > 1 {
			// A merged group of cached copies keeps the agent in its title.
			// The generic "N separate secrets in M file copies" wording is
			// wrong for these twice over: the copies are not copies of a
			// file, and dropping the agent loses the one fact that explains
			// how the credential got there.
			if out[i].sample.FindingType == FindingTypeAgentCachedSecret {
				agent := AgentLabelForPath(home, out[i].sample.FilePath)
				if agent == "" {
					agent = "an AI agent"
				}
				// Pluralised on the key name itself: the title counts
				// secrets, so "2 DATABASE_URL" reads as a typo.
				label := shortSecretLabel(out[i].sample.KeyName)
				if out[i].secrets > 1 && !strings.HasSuffix(label, "s") {
					label += "s"
				}
				out[i].title = fmt.Sprintf("%d %s, copied by %s", out[i].secrets, label, agent)
			} else {
				// Same grammar as manualTitle's multi-file form: "N secrets in
				// M files". "N separate secrets in M file copies" said the
				// same thing in different words two lines apart.
				//
				// The file count is DISTINCT files, taken from the same
				// deduplicated fileList the listing renders — not out[i].files,
				// which sums each constituent's count and so counts a file
				// shared by two secrets twice. That made the header say "21
				// files" over a listing of 15 (2026-08-09): a reader counts the
				// paths, gets a smaller number, and stops trusting the report.
				out[i].title = fmt.Sprintf("%s — %d secrets in %s",
					out[i].noun, out[i].secrets,
					countWord(distinctFileCount(out[i].fileList), "file", "files"))
			}
			out[i].ctx.secrets = out[i].secrets
			out[i].ctx.copies = distinctFileCount(out[i].fileList)
			out[i].kind, out[i].action = manualAction(out[i].sample, out[i].ctx, home)
		}
	}
	for i := range out {
		collapsePatternHints(&out[i], home)
	}
	return out
}

// collapsePatternHints replaces a merged group's per-file view hints with ONE
// hint covering every file, when they are the same command differing only in
// path. A real scan (2026-08-07) printed the identical JWT grep nine times
// under one group, once per paste-cache file — nine lines reading as one
// instruction stuttered. The keep-every-hint rule mergeManualGroups documents
// is about hints that DIFFER (each names an address the reader must reach);
// hints identical up to path carry one instruction, and a single grep over
// all the files runs it in one paste.
//
// Regenerated from the constituents' samples, never parsed out of the hint
// strings — and only for the full-pattern grep form: line-addressed history
// hints and agent-copy breakdowns each name coordinates that a shared
// command cannot stand for.
func collapsePatternHints(m *triageManualGroup, home string) {
	if len(m.hints) < 2 || len(m.hintSamples) != len(m.hints) {
		return
	}
	ere := patternEREFor(m.hintSamples[0])
	if ere == "" {
		return
	}
	seen := map[string]bool{}
	var paths []string
	for _, s := range m.hintSamples {
		if s.FilePath == "" || patternEREFor(s) != ere ||
			s.FindingType == FindingTypeShellHistorySecret ||
			s.FindingType == FindingTypeAgentCachedSecret {
			return
		}
		// A sample that knows its own line renders as "at line N" now
		// (viewHintByAnchor), which is a precise coordinate this file offers.
		// Folding several of those into one grep over *.json throws the
		// coordinates away and undoes the very change that added them —
		// measured against three JWTs at lines 10/20/30 (2026-08-09). The
		// grep form is the fallback for findings with NO line; collapse only
		// applies to those.
		if s.Line != nil {
			return
		}
		if !seen[s.FilePath] {
			seen[s.FilePath] = true
			paths = append(paths, s.FilePath)
		}
	}
	if len(paths) < 2 {
		return
	}
	// -f1,2 rather than the single-file form's -f1: multi-file grep prefixes
	// each hit with its path, so fields one and two are path:line — the
	// content field stays cut off, which is the property the whole hint
	// exists to keep.
	m.hints = []string{fmt.Sprintf("lines: grep -nE '%s' %s | cut -d: -f1,2",
		ere, combinedPathExpr(paths, home))}

	// The ADDRESSES above this hint deliberately do not collapse with it,
	// even though nine ~/.claude/paste-cache/<16 hex>.txt lines over a single
	// glob read badly (measured 2026-08-09). A glob is a search convenience,
	// where combinedPathExpr can accept over-matching because "grep finding
	// nothing extra in them is harmless" — an address is a claim. Rewriting
	// nine addresses to ~/Downloads/*.json would assert jit found something
	// in every .json in that directory, including files it never opened. The
	// hash names are unhelpful; naming files that are not findings is worse.
}

// combinedPathExpr renders several paths as one shell word when a glob can
// honestly stand for them — same directory, same extension, nothing needing
// quotes — and falls back to listing each path. The glob may match files
// beyond the group's; grep finding nothing extra in them is harmless, and
// "~/.claude/paste-cache/*.txt" reads where nine hash-named paths do not.
func combinedPathExpr(paths []string, home string) string {
	dir, ext := filepath.Dir(paths[0]), filepath.Ext(paths[0])
	glob := ext != ""
	for _, p := range paths[1:] {
		if filepath.Dir(p) != dir || filepath.Ext(p) != ext {
			glob = false
			break
		}
	}
	if glob && shellBarePath(dir) {
		return ShortenHome(home, dir) + "/*" + ext
	}
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = shellSafePath(home, p)
	}
	return strings.Join(quoted, " ")
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
// asPrevention is set by the CLEAN call sites, and is the other half of what
// the comment above describes. Moving the offer out of `jit migrate` fixed
// where it appeared but kept requiring a finding, so a clean history — the
// case with the most to gain from never starting — still never heard it. It
// stays off elsewhere: beside a .zshrc finding the reader's problem is the
// config file, and a history tip there is a second subject in one breath.
//
// A targeted scan never gets it either way. `jit scan ~/proj` did not look at
// the shell history, and recommending a fix for something a run never examined
// is how a report starts being read as boilerplate.
func writeHistoryGuardOffer(w io.Writer, findings []Finding, summary ScanSummary, cmd *color.Color, asPrevention bool) {
	found := false
	for _, f := range findings {
		if f.FindingType == FindingTypeShellHistorySecret && CountedAsSecret(f) && !f.Archived {
			found = true
			break
		}
	}
	machineWide := len(summary.Targets) == 0
	if !found && !(asPrevention && machineWide) {
		return
	}
	effect := "   keeps the next typed credential out of your history file: a zsh hook " +
		"holds a command carrying one back from $HISTFILE, while leaving it usable in that session"
	if found {
		effect = "   stops the next one being recorded: a zsh hook keeps a command " +
			"carrying a credential out of your history file, while leaving it usable in that session"
	}
	// Indent follows what the line hangs off. Inside the migrate block it is a
	// note under that group's header (triageNoteIndent); on a clean report it
	// is the only thing under a sentence at the report's own indent, and
	// dropping it four columns further in made it read as a sub-note of
	// nothing.
	indent := triageNoteIndent
	if !found {
		indent = "  "
	}
	fmt.Fprint(w, indent)
	_, _ = cmd.Fprint(w, "jit guard history")
	termtext.Wrap(w, len(indent)+len("jit guard history"), indent, effect)
}

// manualTitle names the problem in the user's terms: what it is and, when
// it spans copies, how wide it spread. It never says "finding" or a
// severity word — the noun is the secret, the number is the file spread.
func manualTitle(causes []*triageCause, files []string, worst Finding, home string) string {
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
	// An agent cache copy is titled by WHO copied it, not by how many files it
	// spread to. "in 9 copies of a file" describes a duplicated config; what
	// happened here is that one agent kept nine snapshots of one credential,
	// and naming the agent is what makes the finding actionable. The count
	// moves to the evidence line, where the breakdown by cache area lives.
	if worst.FindingType == FindingTypeAgentCachedSecret {
		noun := manualNoun(worst)
		if len(causes) > 1 {
			noun = fmt.Sprintf("%d credentials", len(causes))
		}
		if agent := AgentLabelForPath(home, worst.FilePath); agent != "" {
			return fmt.Sprintf("%s, copied by %s", noun, agent)
		}
		return noun + ", copied by an AI agent"
	}
	noun := manualNoun(worst)
	if len(causes) > 1 {
		noun = fmt.Sprintf("%d credentials", len(causes))
	}
	if len(files) > 1 {
		// "in N files", not "in N copies of a file". The old phrasing read as
		// one file duplicated N times, which is a different fact from N
		// distinct files each holding the credential — and it was one of three
		// grammars the section used for the same relationship (the other two
		// being "— N separate secrets in M file copies" and a bare noun).
		// One shape, so two items can be compared at a glance.
		return fmt.Sprintf("%s in %d files", noun, len(files))
	}
	return noun
}

// manualNoun is the one-line "what is this" for a single manual secret.
func manualNoun(f Finding) string {
	switch {
	case f.FindingType == FindingTypePrivateKeyRisk && f.KeyKind == keyKindGCPServiceAccount:
		// Named for what it is, not the bucket it was found by: "at-risk
		// private key" plus passphrase advice sent a real user toward
		// ssh-keygen -p for a key that cannot take a passphrase (2026-08-07).
		return "An exposed Google Cloud service-account key"
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
		// than only in the path line below: "An exposed GitHub token" and
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
		return humanizeCompoundKey(k)
	}
}

// humanizeCompoundKey turns a nested config address into words.
//
// MCP and plugin scanners report a key by its path inside the file —
// "jamf/JAMF_PRO_CLIENT_ID", "Snowflake/header:Authorization" — which is the
// scanner's addressing scheme, not language. Dropped into a title slot it
// reads as a leaked internal identifier ("An exposed Snowflake/header:
// Authorization"), and a report that looks like it is printing its own
// variable names is a report the reader trusts less.
//
// Separators become spaces, and a vendor prefix the tail already names is
// dropped: "jamf/JAMF_PRO_CLIENT_ID" is one fact, not two.
func humanizeCompoundKey(k string) string {
	head, tail, found := strings.Cut(k, "/")
	if !found || head == "" || tail == "" {
		return k
	}
	tail = strings.TrimSpace(strings.ReplaceAll(tail, ":", " "))
	if strings.Contains(strings.ToLower(tail), strings.ToLower(head)) {
		return tail
	}
	return head + " " + tail
}

// manualDetail is the second line: where, compressed — one exemplar
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
	// For a cached copy the address the reader needs is the file the
	// credential LIVES in, never the copy: the copies are named by content
	// hash (93eb694cdfee2a45@v2), which is an address nobody can act on, and
	// the origin is the file they recognise and can go and fix.
	if worst.FindingType == FindingTypeAgentCachedSecret && worst.OriginPath != "" {
		return ShortenHome(home, worst.OriginPath)
	}
	shown := ShortenHome(home, first)
	// A history file is thousands of lines long and the fix is to find one of
	// them, so the line number is not a detail — it is the whole address. No
	// other manual finding needs it, because "~/.gemini/oauth_creds.json" is
	// already the location.
	if IsShellHistoryPath(first) && worst.Line != nil {
		shown = fmt.Sprintf("%s:%d", shown, *worst.Line)
		// A key block is an extent, not a point, and the instruction below is
		// to delete it. Naming both ends turns the address into the answer —
		// but a block that opened and closed on one line is a point, and
		// "2866-2866" would be a stutter that reads as a bug.
		if worst.EndLine != nil && *worst.EndLine != *worst.Line {
			shown = fmt.Sprintf("%s-%d", shown, *worst.EndLine)
		}
	}
	if len(files) == 1 {
		return shown
	}
	// "… and 1 more" never said more WHAT. Beside a group header that counts
	// both secrets and files ("An exposed JWT — 9 secrets in 21 files"), a
	// bare "1 more" reads as plausibly either, and a reader asked (2026-08-09).
	// The noun costs five columns and removes the question.
	return fmt.Sprintf("%s … and %s", shown, countWord(len(files)-1, "more file", "more files"))
}

// manualGroupHint is the evidence line under a group's address. It defers to
// manualViewHint for everything except a cached copy, which needs a different
// kind of line: not "how do I look at that address" but "where did the copies
// actually land", because the address shown is the origin and the copies are
// the thing being reported.
func manualGroupHint(worst Finding, files []string, home string, causes []*triageCause) string {
	if worst.FindingType == FindingTypeAgentCachedSecret {
		if b := AgentCopyBreakdown(home, files); b != "" {
			return style.GlyphBranch + " " + b
		}
	}
	return manualViewHint(worst, home, anchorCoversSeveral(worst, causes), len(files) > 1)
}

// anchorCoversSeveral reports whether the hint's single anchor really stands
// for more than one of this problem's secrets.
//
// "to see them" has to be true of the command actually printed, not of the
// problem's headline count. A problem holding two secrets of DIFFERENT vendors
// in one file set — "2 credentials in 18 copies of a file" is this shape — gets
// one anchor, the worst finding's, and that grep locates one of the two. Saying
// "them" over a command that shows one is the same species of overclaim as an
// anchor that greps to nothing: the reader checks, comes up short, and stops
// believing the line.
func anchorCoversSeveral(worst Finding, causes []*triageCause) bool {
	a := anchorFor(worst)
	if a == "" {
		return false
	}
	n := 0
	for _, c := range causes {
		if anchorFor(c.sample) == a {
			n++
		}
	}
	return n > 1
}

// manualViewHint returns the line, printed under the address line and
// above the action, that shows the reader how to LOOK at that address — or ""
// for problems that need no such line. It stays plain rather than cyan,
// command and all, matching the "jit migrate undo" mention in the green section's
// note: cyan marks the thing the report is asking you to run, and neither of
// those is that.
//
// Only shell history gets one, and only because only shell history is
// addressed by line number: "~/.gemini/oauth_creds.json" is a file you open,
// while "~/.zsh_history:2866" is a coordinate inside 3,000 lines that a reader
// has no obvious way to reach. A user hit exactly this (2026-08-05), read the
// ":2866" as text to search for, ran `grep 2866`, found nothing, and concluded
// the finding was a false positive. An address the report will not help you
// open is an address that reads as wrong.
//
// This is deliberately in tension with manualDetail's rule that the red
// section describes rather than asking the user to run things on these exact
// paths. That rule is about FIXES — jit does not offer to repair what only the
// user can repair. Reading is not fixing, and the instruction directly above
// ("delete those lines by hand") is unfollowable without it.
//
// The private-key case gets a self-locating grep rather than the line number,
// because the line number is the one part of this report with a shelf life:
// zsh trims $HISTFILE to $SAVEHIST and rewrites it, dropping lines off the top
// and shifting every number below. A stale `sed -n '2866p'` prints an
// unrelated command with no error, which is worse than no hint — it looks like
// proof the finding was wrong. Grepping the header re-derives the address at
// the moment the user reads it. Printing that header leaks nothing: it is a
// constant, which is the same reason privateKeyInHistoryFinding refuses to
// treat it as a value.
//
// Every other finding now gets one too, on the same terms. This used to be
// history-only, and the note here read "tokens get no equivalent anchor on
// purpose: the only text that would locate a token line is the token". That
// premise was too strong — it is true only of the VALUE. The vendor prefix
// ("github_pat_", "eyJ") and the config key ("OKTA_KEY_ID") are constants
// that sit in the file beside the credential, and greping those locates it
// while printing nothing secret. What the old rule correctly ruled out was
// `sed -n 'Np'` on an arbitrary file, which prints the line and therefore the
// credential; that is still refused, and a finding with no safe anchor gets
// no hint at all rather than an unsafe one.
//
// The reason to print them: a reader asked to rotate a credential will first
// want to see that it is really there, and a finding they cannot verify is a
// finding they discount. That is not hypothetical — a GCP project ID reported
// as an exposed secret is the kind of item that costs the whole report its
// credibility, and the fastest way to settle it is to look.
func manualViewHint(f Finding, home string, plural, multiFile bool) string {
	if f.FindingType == FindingTypeShellHistorySecret && f.Line != nil {
		return viewHintByLine(f, home)
	}
	return viewHintByAnchor(f, home, plural, multiFile)
}

// viewHintByLine addresses a credential recorded in shell history, where the
// coordinate is a line number inside thousands.
func viewHintByLine(f Finding, home string) string {
	path := shellSafePath(home, f.FilePath)
	// A closed key block gets the range printed, because the reader's next
	// move is to inspect those exact lines before deleting them, and checking
	// what you are about to remove from your own history is a reasonable thing
	// to want. This command's output IS the key — an explicit product
	// decision (2026-08-05), taken knowing it puts key material in the
	// terminal's scrollback. It stays consistent with the report's "no secret
	// values are ever printed in full" footer only in the narrow sense that
	// jit prints a command and the reader chooses to run it.
	if f.KeyName != nil && IsPrivateKeyVendor(*f.KeyName) && f.EndLine != nil {
		// Singular form for a one-line block, both because "'2866,2866p'" is
		// noise and because the sentence above it says "line", not "lines".
		if *f.EndLine == *f.Line {
			return fmt.Sprintf("to see it: sed -n '%dp' %s", *f.Line, path)
		}
		return fmt.Sprintf("to see them: sed -n '%d,%dp' %s", *f.Line, *f.EndLine, path)
	}
	// No range means the block never closed in this file, so there is no
	// honest span to print — sed would need an end line invented for it, and
	// a guessed window either stops mid-key or dumps unrelated history. Fall
	// back to locating the markers.
	if f.KeyName != nil && IsPrivateKeyVendor(*f.KeyName) {
		// -n for the address, -o because the whole safety property lives in
		// that flag: without it grep prints the matching LINE, and a key
		// pasted as one history entry is a line that holds the entire key.
		// With it the output is the literal "PRIVATE KEY" and nothing else,
		// whatever the line contains.
		//
		// The pattern is that bare literal rather than an anchored BEGIN
		// header, which buys three things at once. It is short enough to stay
		// unwrapped at 60 columns. It matches the END marker too, so the
		// reader gets the RANGE to delete from one command instead of the
		// header alone. And it needs no vendor alternation — RSA, OPENSSH,
		// ECDSA and EC headers all contain it.
		//
		// Two shapes read correctly out of the same output: the same line
		// number twice means the key sits on one line, and a single hit means
		// the block was truncated (header pasted, END never recorded, or the
		// file trimmed between them).
		return fmt.Sprintf("to find it: grep -Fno 'PRIVATE KEY' %s", path)
	}
	return fmt.Sprintf("to see that line: sed -n '%dp' %s", *f.Line, path)
}

// viewHintByAnchor is the hint for a finding addressed by FILE rather than by
// line: a grep for a constant that sits next to the credential, printing the
// line number and the anchor and nothing else.
//
// -n for the address, -o because the whole safety property lives in that flag.
// Without it grep prints the matching LINE, and the matching line is the one
// holding the credential; with it the output is the literal anchor, whatever
// else that line contains. This is the same reasoning the private-key branch
// above documents, applied to every other kind of secret.
//
// -F because the anchor lands in grep's PATTERN position, where it would
// otherwise be a regex. identLike admits ".", so a config key "foo.bar" would
// match "fooXbar" — a locator quietly wider than the thing it locates. -F
// costs one character and closes that permanently.
//
// What -F does not restore is the word boundary the vendor pattern had: the
// legacy OpenAI anchor "sk-" is three characters and will also hit "task-" and
// "risk-", so this line points at the credential rather than proving where it
// is. That is the accepted trade for a locator that never prints a value; the
// reader is looking at their own file and can tell the difference.
//
// "" when no constant is available — an unanchored finding keeps the behaviour
// this had before it was generalised, which is to say no hint.
func viewHintByAnchor(f Finding, home string, plural, multiFile bool) string {
	if f.FilePath == "" {
		return ""
	}
	// jit already knows where it looked. When it has a line number AND the
	// address above names exactly one file, saying so beats shipping a command
	// to go and rediscover it: the grep form's output is a column of bare
	// integers with nothing naming them, and two readers in a row ran it and
	// asked what the numbers meant (2026-08-09). For ~/.gemini/oauth_creds.json
	// the record carried "line": 5 the whole time.
	//
	// Gated on multiFile because f.Line is the coordinate in the WORST
	// finding's file, and a cause group can span several: one credential in
	// ~/proj/.env:12 and its copy in ~/backup/.env.bak:3740 renders one detail
	// line ("~/proj/.env … and 1 more file") over which "at line 12" is wrong
	// for the backup — a reader who opens it there finds nothing, the exact
	// greps-to-nothing failure the anchor forms below are built to avoid. A
	// multi-file group falls through to the self-identifying grep, which names
	// its own path and so cannot mislead about which file a number belongs to.
	//
	// The count rides along because "at line 3740" alone would imply the only
	// one — that file held six.
	if f.Line != nil && !multiFile {
		switch {
		case f.Occurrences > 1:
			return fmt.Sprintf("at line %d, and %d more in this file", *f.Line, f.Occurrences-1)
		default:
			return fmt.Sprintf("at line %d", *f.Line)
		}
	}
	// No line: a file-level finding, or one whose scanner never recorded a
	// coordinate. The pattern grep is the honest fallback — it prints line
	// numbers and nothing else, not even the anchor.
	if ere := patternEREFor(f); ere != "" {
		lead := "lines"
		if !plural {
			lead = "line"
		}
		return fmt.Sprintf("%s: grep -nE '%s' %s | cut -d: -f1", lead, ere, shellSafePath(home, f.FilePath))
	}
	a := anchorFor(f)
	if a == "" {
		return ""
	}
	// Singular when the problem is one secret, matching the care the line-
	// addressed hint above takes over "to see it" versus "to see them" — the
	// two forms sit under identical-looking items and reading one as a typo
	// costs more than the branch does.
	lead := "to see them"
	if !plural {
		lead = "to see it"
	}
	// Single quotes are safe for the ANCHOR unconditionally: isAnchorRune and
	// identLike between them admit only letters, digits, "_", "-" and ".".
	// The PATH's quoting is shellSafePath's responsibility, not this line's.
	return fmt.Sprintf("%s: grep -Fno '%s' %s", lead, a, shellSafePath(home, f.FilePath))
}

// patternEREFor resolves the finding's vendor — named directly in KeyName, or
// recovered from Evidence the same way anchorFromEvidence does — to a
// grep-safe full pattern, "" when there is none.
func patternEREFor(f Finding) string {
	if f.KeyName != nil && *f.KeyName != "" {
		if ere := TokenPatternERE(*f.KeyName); ere != "" {
			return ere
		}
	}
	if f.Evidence == "" {
		return ""
	}
	best := ""
	for _, p := range knownTokenPatterns {
		if len(p.vendor) > len(best) && strings.Contains(f.Evidence, p.vendor) {
			best = p.vendor
		}
	}
	if best == "" {
		return ""
	}
	return TokenPatternERE(best)
}

// anchorFor picks the constant to grep for, most specific first. It returns a
// grep pattern; viewHintByAnchor is what turns it into a command.
func anchorFor(f Finding) string {
	if f.KeyName != nil && *f.KeyName != "" {
		k := *f.KeyName
		if IsPrivateKeyVendor(k) {
			return "PRIVATE KEY"
		}
		if a := TokenAnchorFor(k); a != "" {
			return a
		}
		if t := identTail(k); t != "" {
			return t
		}
	}
	// A file-level finding (env_file_present) names no key and no line — the
	// file IS the address — but when the scanner matched a known token format
	// it says so in Evidence, and that vendor has a greppable prefix. Without
	// this the .env findings, which are most of a real report, are the ones
	// that get no hint.
	//
	// Recovered by looking a KNOWN vendor name up inside the sentence, never
	// by parsing the sentence: the set of names is closed, the comparison is
	// exact, and no match means no hint rather than a guess.
	return anchorFromEvidence(f.Evidence)
}

// anchorFromEvidence finds the longest known vendor name mentioned in evidence
// and returns its prefix. Longest wins because the names nest — "GitHub
// Personal Access Token" and "GitHub Fine-Grained Personal Access Token" would
// otherwise be decided by map order, and the two have different prefixes.
func anchorFromEvidence(evidence string) string {
	if evidence == "" {
		return ""
	}
	best := ""
	for _, p := range knownTokenPatterns {
		if len(p.vendor) > len(best) && strings.Contains(evidence, p.vendor) {
			if literalPrefix(p.pattern.String()) != "" {
				best = p.vendor
			}
		}
	}
	if best == "" {
		return ""
	}
	return TokenAnchorFor(best)
}

// identTail returns the part of a scanner's key that is literally written in
// the file, or "" when the key is a vendor's name for a shape rather than
// text anyone typed.
//
// Nested configs report a compound key — "jamf/JAMF_PRO_CLIENT_ID" from an
// MCP server block, "Snowflake/header:Authorization" from a plugin manifest —
// where only the last segment appears in the file; grepping the whole thing
// finds nothing. A label carrying spaces or brackets ("JSON Web Token (JWT)")
// is a pattern's name for itself, is in no file, and must produce no hint:
// a hint that greps to nothing reads as proof the finding was wrong, which is
// the exact failure this whole line exists to prevent.
func identTail(k string) string {
	if i := strings.LastIndexAny(k, "/:"); i >= 0 {
		k = k[i+1:]
	}
	if !identLike.MatchString(k) {
		return ""
	}
	return k
}

// identLike matches a config key as actually written: an identifier with no
// spaces, of at least minAnchorLen characters. Derived from that constant
// rather than restating it — the two were a hand-computed {2,} and a comment
// citing a test that was never written, which is a magic number with an
// imaginary safety net.
var identLike = regexp.MustCompile(
	fmt.Sprintf(`^[A-Za-z_][A-Za-z0-9_.\-]{%d,}$`, minAnchorLen-1))

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
// The kinds, which double as the group headers. They are short because they
// are read as a list — the sentence that explains the fix is the arrow line
// under the group, printed once for all of it.
const (
	kindTrash          = "empty the trash"
	kindIAMKey         = "rotate in IAM, then delete the file"
	kindArchived       = "name the file — the sweep skips archived folders"
	kindPassphrase     = "add a passphrase"
	kindSelfRotating   = "sign out and back in"
	kindTerraformState = "get secrets out of Terraform state"
	kindSeal           = "seal it"
	kindAgentCopies    = "rotate — an agent kept its own copies"
	kindKeyByHand      = "delete by hand"
	kindHistoryLine    = "rotate, then clear the line"
	kindRotateDelete   = "rotate, then delete every copy"
	kindMoveOut        = "move it out, then rotate"
	kindProtectInPlace = "protect in place"
)

// isCommandAction reports whether an arrow line is a command to run rather
// than a sentence of advice. The two are cut differently — a sentence
// truncates, a command must print whole (see the arrow renderer) — and this
// is the one place that decides which.
//
// Asks the string rather than the kind on purpose. Every command jit puts on
// an arrow is one of its own subcommands, so the prefix is the honest test,
// and it cannot fall out of step with manualAction the way an enumerated list
// of kinds did: kindProtectInPlace returned `jit migrate <path> --mount` for
// months while the renderer believed kindArchived was the only command, and
// silently truncated the flag off.
func isCommandAction(action string) bool {
	return strings.HasPrefix(action, "jit ")
}

func manualAction(f Finding, ctx manualContext, home string) (kind, action string) {
	them := "it"
	if ctx.secrets > 1 {
		them = "them"
	}
	switch {
	case inTrash(f.FilePath):
		// Above archived, which would otherwise swallow it (every trash path
		// looks archived). Trash is the one archived-looking place where even
		// migrate-by-name is the wrong offer: the user already decided this
		// file should not exist, and vaulting it would preserve what deletion
		// is about to fix. Finishing the deletion IS the remedy.
		return kindTrash, "empty the Trash, then rotate anything it held"
	case f.Archived:
		// Next, because archived is a property of WHERE the file is and it
		// overrides every remedy below: bare `jit migrate` walks past these
		// directories, so whatever else is true of the secret, the instruction
		// has to name the file explicitly or it will not run.
		return kindArchived, fmt.Sprintf("jit migrate %s", shellSafePath(home, f.FilePath))
	case f.FindingType == FindingTypePrivateKeyRisk && f.KeyKind == keyKindGCPServiceAccount:
		// Not the passphrase advice below: a service-account key has no
		// passphrase to add, and the only revocation lives at the provider.
		files := "this file"
		if ctx.secrets > 1 {
			files = "these files"
		}
		// The arrow says where to go, not what the header already said. It
		// used to read "rotate the key in IAM, then delete these files",
		// which is the group header ("rotate in IAM, then delete the file")
		// in different words six lines below it — and the note between them
		// already carries the fact that makes this kind different. Naming the
		// console is the one thing neither line said.
		return kindIAMKey, "rotate it under IAM's Service Accounts, then delete " + files
	case f.FindingType == FindingTypePrivateKeyRisk:
		return kindPassphrase, "add a passphrase (ssh-keygen -p) or move the key somewhere safer"
	case selfRotating(f):
		c, _ := selfRotatingCacheFor(f.FilePath)
		return kindSelfRotating, c.action
	case isTerraformState(f.FilePath):
		return kindTerraformState, "rotate " + them + " now; move state to an encrypted remote backend, and keep secrets out of it with ephemeral values (Terraform 1.10+)"
	case f.FindingType == FindingTypeIACVariableFile:
		return kindSeal, "seal it (sealed-secrets/SOPS) or move it to a real secret store"
	case f.FindingType == FindingTypeAgentCachedSecret:
		// Rotation leads because it is the fix: the credential sat in an
		// agent's cache in plaintext, and clearing a copy does not un-expose
		// what was already readable.
		//
		// The second clause used to say `jit migrate` "cleans the file above,
		// not these copies". That was false, and had been for as long as
		// migrate called CleanAgentCaches: migrating the origin vaults the
		// value AND replaces every cached copy of it with a
		// <jit:redacted:VAR> marker. A real run cleared ten of them while the
		// scan was still promising it would not (measured 2026-08-09) — the
		// same shape of scan-contradicts-migrate the tfvars advisory had.
		above := "the file above"
		if ctx.copies > 0 && ctx.secrets > 1 {
			above = "the files above"
		}
		return kindAgentCopies, fmt.Sprintf("rotate %s now — migrating %s clears these copies too", them, above)
	case f.FindingType == FindingTypeShellHistorySecret && f.KeyName != nil && IsPrivateKeyVendor(*f.KeyName):
		// A key is not a token: there is no provider to rotate it at, and the
		// line jit matched is the header, so the body is still on the lines
		// around it. Deleting is the user's job here, not jit's.
		return kindKeyByHand, "regenerate the key and replace it wherever it is authorized, then delete those lines by hand"
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
		return kindHistoryLine, fmt.Sprintf("rotate %s at the provider now, then remove %s — your shell rewrites %s on exit, so close other shells first",
			them, lines, file)
	case ctx.production || f.ProductionIndicatorMatch:
		// Rotation FIRST and on its own clause, because the deletion is the
		// part people do and mistake for the fix. The arrow used to read
		// "rotate them now, then delete every copy" — the group header
		// verbatim, plus "now". What the header cannot say is why deleting
		// alone is not enough.
		return kindRotateDelete, fmt.Sprintf("rotate %s at the provider — deleting the copies undoes nothing", them)
	case ctx.copies > 1:
		return kindRotateDelete, fmt.Sprintf("rotate %s at the provider — deleting the copies undoes nothing", them)
	case !mountable(f.FilePath):
		// Says why this is "move out" rather than the mount offered two
		// branches down: nothing reads this file at run time, so there is no
		// consumer for a pipe to serve.
		return kindMoveOut, fmt.Sprintf("move %s out, then rotate — no program reads this file at run time", them)
	default:
		// A mixed-content file bare migrate skips on purpose, that a program
		// really does read at run time: offer the in-place protection that
		// DOES exist. The honest alternative used to ride the same line after
		// a "·", which put two next steps on one arrow — the thing the action
		// motif exists to prevent — and buried a 100-column path mid-sentence
		// where Wrap could not truncate it. It is a note above the arrow now
		// (see actionNote), which is where an explanation belongs.
		return kindProtectInPlace, fmt.Sprintf("jit migrate %s --mount", shellSafePath(home, f.FilePath))
	}
}

// actionNote is the caveat or alternative that belongs ABOVE a group's arrow.
// Nothing goes after the arrow: the command is the last thing on screen
// because it is the thing the reader acts on.
func actionNote(kind string) string {
	switch kind {
	case kindProtectInPlace:
		return "or move the secret out of the file, then rotate it"
	case kindArchived:
		// Two facts on two lines (the renderer splits on \n): what the sweep
		// does and why the group exists, then the remedy migrate cannot offer
		// — for a copy whose live sibling is already protected, deletion
		// beats vaulting a stale secret, and only the note can say so
		// because scan never deletes anything.
		return "bare jit migrate walks past archive/ and backups/ on purpose — these are counted above, and naming a file explicitly still vaults it\n" +
			archivedDeletionNote
	case kindTrash:
		return "this file is already on its way out — migrating it would preserve what deletion is about to fix"
	case kindIAMKey:
		return "deleting the file does not revoke the key — only deleting the key in IAM does"
	}
	return ""
}

// archivedDeletionNote is the second line of the archived group's note, kept
// identical between the file-list and folder forms of the group so the two
// cannot drift apart in wording.
const archivedDeletionNote = "already protected the live copy? deleting the archived one is the cleaner fix"

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

// coverageBarWidth is how many columns writeBar occupies — the width the
// clause beside it has to hang under when it wraps.
const coverageBarWidth = 10

// writeBar renders the ten-cell coverage bar.
func writeBar(w io.Writer, pct int) {
	filled := pct / 10
	_, _ = style.OK.Fprint(w, strings.Repeat(style.GlyphBarFilled, filled))
	fmt.Fprint(w, strings.Repeat(style.GlyphBarEmpty, coverageBarWidth-filled))
}
