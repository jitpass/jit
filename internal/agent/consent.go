// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/lineage"
)

// consentCaller maps the kernel-identified socket peer to a consent.Caller,
// keyed on the TOOL that wanted the credential — not on the jit helper that
// carried the request. Every gated socket credential (aws/docker/git/terraform/
// kube/sops) reaches the agent through a `jit <x>-credential` helper it spawned,
// so c.self is ALWAYS the jit binary; keying the consent cache on c.self would
// collapse every consumer of a class to one key, and approving aws once would
// silently cover an unrelated script's aws for the rest of the session. The real
// tool is the nearest explanatory ancestor of that helper — the same identity
// the FIFO path keys on (consentCallerForPID) — so we key on ITS ExecPath and
// describe what launched IT as the lineage, mirroring the FIFO side exactly.
//
// Strength stays Hard: the anchor is still the kernel-vouched peer pid
// (LOCAL_PEERPID), and the launcher is one ancestry hop up from it, resolved
// while that peer is alive. The launcher is ancestry-derived rather than the
// peer itself, but it is not caller-reported — a process cannot forge its own
// parent — and a tighter key can only ever prompt MORE, never let a stranger
// ride a warm approval.
//
// If no explanatory launcher resolves (a human ran the helper directly at a
// shell, or the ancestry was unreadable), ExecPath stays empty; consent.Decide
// then declines to cache the decision at all and re-prompts every access —
// fail-safe, never over-sharing.
func consentCaller(c *caller) consent.Caller {
	cc := consent.Caller{Strength: consent.Hard}
	if c == nil {
		return cc
	}
	cc.PID = c.pid
	if launcher, above, ok := lineage.LaunchedByProcess(c.ancestors); ok {
		cc.ExecPath = launcher.ExecPath
		cc.Lineage = lineage.LaunchedBy(above)
	}
	return cc
}

// consentReason is the single line the human decides by. Every part is either
// kernel-derived (the caller and its lineage) or authoritative (the class is
// AEAD-bound into the wrap, so a caller cannot lie about it) — nothing
// caller-reported ever reaches this prompt, unlike Request.Label. See
// consentReasonFor for its shape.
func consentReason(req consent.Request) string {
	return consentReasonFor(req, false)
}

// unlockAnd marks a disclosed prompt whose approval also unlocks the vault
// (see forceDisclosedChallengeUnlocking): "let terraform unlock the vault and
// use aws". It is part of the fixed half, so no caller-chosen length can push
// it out of the dialog: the human is authorizing the whole vault as well. It
// never LEADS the sentence: a reason starting "unlock the vault" is a plain
// unlock.
const unlockAnd = unlockTheVault + " and "

// consentReasonFor is consentReason, saying unlockAnd when the approval will
// also open the session.
//
// The shape is "let <who> use your <class> credential, via <launcher>": who
// asked, then what for (Meni, 2026-09-29). The old shape led with the ask so
// that a long path could not bury it; the name is bounded instead. The fixed
// half is built first and the names share what is left, the caller before
// its launcher, so nothing either of their authors chose can push the
// credential, the unlock or a warning out of the dialog.
//
// With the unlock the credential is named by its one word ("use aws"): the
// full phrase took a fourth line, and the vault is the larger half of what
// is being approved.
func consentReasonFor(req consent.Request, unlocking bool) string {
	cc, class := req.Caller, req.Credential
	const lead = "let "
	what := fmt.Sprintf(" use your %s credential", class)
	if unlocking {
		what = " " + unlockAnd + "use " + class
	}
	flags := consentFlags(cc.Strength == consent.BestEffort, req.PriorRefusals)
	budget := maxReasonLen - len([]rune(lead+what+flags))

	var lineage string
	if l := dialogName(cc.Lineage); l != "" {
		lineage = ", via " + truncate(l, maxConsentLineageLen)
	}
	if n := len([]rune(lineage)); n > budget-minConsentWhoLen {
		lineage = "" // a pathological launcher is dropped, never the caller
	}

	who := truncateHead(dialogName(displayExecPath(cc.ExecPath)), budget-len([]rune(lineage)))
	if who == "" {
		// The unidentified fallback is subject to the same budget as a real
		// path: an empty ExecPath is what makes every anonymous caller share
		// one throttle key, so it is exactly the caller that reaches the
		// highest refusal counts. The short form keeps the pid whole.
		room := budget - len([]rune(lineage))
		who = fmt.Sprintf("a process (pid %d)", cc.PID)
		if len([]rune(who)) > room {
			who = fmt.Sprintf("pid %d", cc.PID)
		}
	}
	return lead + who + what + lineage + flags
}

// consentFlags are the two facts that make a request worth a second look, in
// one bracket at the sentence's end: "(unverified, refused 2 times)".
//
// "unverified" is an identity found by scanning running processes, not
// vouched for by the kernel: it changes what the answer means. A request
// already refused this session says so, because repetition is the whole
// mechanism behind prompt fatigue: the tenth identical dialog is evidence
// that something is asking in a loop, and a prompt that renders it like the
// first leaves the user nothing to notice that with. Both are part of the
// fixed half and never what truncation drops.
func consentFlags(unverified bool, refusals int) string {
	var flags []string
	if unverified {
		flags = append(flags, "unverified")
	}
	switch {
	case refusals == 1:
		flags = append(flags, "refused once")
	case refusals > 1:
		flags = append(flags, fmt.Sprintf("refused %d times", refusals))
	}
	if len(flags) == 0 {
		return ""
	}
	return " (" + strings.Join(flags, ", ") + ")"
}

const (
	// maxConsentLineageLen bounds the launcher half ("via npm install"), and
	// minConsentWhoLen is the room reserved for the caller itself no matter
	// what: the launcher is context, the caller is the subject of the
	// sentence, so the launcher is what gets dropped when they can't both
	// fit.
	maxConsentLineageLen = 24
	minConsentWhoLen     = 12
)

// standardToolDirs are the locations a legitimately-installed CLI lives in.
// An executable in one of these is shown by name alone; anything else is shown
// with its directory, because "gcloud" and "gcloud, from /tmp/x" are different
// answers to the question the prompt is asking.
//
// Being outside this set is not evidence of anything — plenty of people run
// tools from ~/go/bin or a project venv — which is why the difference is
// surfaced to the human rather than used to decide.
var standardToolDirs = map[string]bool{
	"/bin":               true,
	"/sbin":              true,
	"/usr/bin":           true,
	"/usr/sbin":          true,
	"/usr/local/bin":     true,
	"/usr/local/sbin":    true,
	"/opt/homebrew/bin":  true,
	"/opt/homebrew/sbin": true,
}

// standardToolTrees extends the same judgment to whole install trees:
// locations whose layout puts the real binary in a versioned or vendored
// subdirectory, so the exact parent dir can't be enumerated. A Homebrew cask
// runs from /opt/homebrew/Caskroom/<name>/<version>/, git's plumbing from a
// libexec/git-core deep under the CLT or a Cellar keg — and spelling those
// paths out ("…mebrew/Caskroom/claude-code/2.1.212/claude") is what turned
// the prompt into a wall the user stopped reading. /System, /usr/libexec and
// /Library/Developer are SIP-protected; /opt/homebrew carries exactly the
// trust its bin/ already had in standardToolDirs, since anyone who can write
// Caskroom can write bin.
var standardToolTrees = []string{
	"/System/",
	"/usr/libexec/",
	"/Library/Developer/",
	"/Library/Apple/",
	"/opt/homebrew/",
}

func displayExecPath(execPath string) string {
	base := filepath.Base(execPath)
	if execPath == "" || base == "." || base == "/" || base == string(filepath.Separator) {
		return ""
	}
	if standardToolDirs[filepath.Dir(execPath)] {
		return base
	}
	for _, tree := range standardToolTrees {
		if strings.HasPrefix(execPath, tree) {
			return base
		}
	}
	return execPath
}

// truncateHead cuts s to at most max RUNES from the FRONT, the opposite end
// from truncate. Paths are the case: the tail ("…/x/gcloud") is what
// identifies the program, so a path too long for the dialog has to lose its
// leading directories, not its filename.
func truncateHead(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return string(r[len(r)-1:])
	}
	return "…" + string(r[len(r)-(max-1):])
}

// gateConsent runs the consent decision for one unwrap. It returns nil to
// allow the unwrap, or an error to deny it. It is a no-op (allow) unless
// consent is enabled, the class is one consent gates, and the kernel
// identified the caller — so it never blocks the agent's own in-process mount
// serving (nil caller) or ordinary project secrets.
//
// The prompt is a fresh disclosed Touch ID; approve → allow (remembered for the
// session, so a tool reading the credential repeatedly is asked once, not once
// per read). A challenge that DOESN'T approve is denied for this access but
// scoped Once — never cached: forceDisclosedChallenge can't tell a genuine
// decline from a transient failure (a keychain hiccup, a lost prompt), and
// caching either as a session-long Deny would lock the credential out with no
// recourse short of re-locking. Re-prompting the next access is the fail-safe
// direction.
//
// Fail-safe for the credential, though, is not free for the human, and this
// path deliberately does not arm the agent's unlock cooldown either (see
// discloseChallenge). Both are defensible alone and together they left the one
// prompt an arbitrary process can trigger on demand with no throttle at all:
// refusing cost a modal per request, approving cost nothing, and a caller in a
// loop could simply outlast the user. The engine's per-request backoff
// (consent.Throttled) is what supplies the missing half — a pause rather than
// a cached Deny, so nothing is locked out and a genuine retry still asks.
//
// unlockOp is the op of the request this gate stands in front of, when that
// request goes straight on to unlock (an unwrap does). On a locked vault the
// one prompt then says so and its approval opens the session, instead of a
// second Touch ID a moment later asking to unlock for the same request. ""
// offers no unlock.
func (s *Server) gateConsent(class string, c *caller, unlockOp string) error {
	if s.Consent == nil || c == nil || !consent.RequiresConsent(class) {
		return nil
	}
	// Settle the session first. A session that lapsed without its timer
	// firing is collected by the first thing that looks, and collecting it
	// clears consent (notifyPendingLock). Looking HERE puts that clear before
	// Decide, so it neither ends this request's own approval (Decide caches
	// nothing that a Clear overtook) nor lets a decision from the lapsed
	// session answer this request. peekSession never extends the session.
	if mek := s.peekSession(); mek != nil {
		wipe(mek)
	}
	cc := consentCaller(c)
	cc.DescendsFromGrant = s.descendsFromTrust(c.pid)
	prompt := func(req consent.Request) (consent.Decision, consent.Scope, error) {
		reasonFor := func(unlocking bool) string { return consentReasonFor(req, unlocking) }
		if err := s.forceDisclosedChallengeUnlocking(reasonFor, c, unlockOp); err != nil {
			return consent.Deny, consent.Once, nil
		}
		return consent.Allow, consent.Session, nil
	}
	d, err := s.Consent.Decide(consent.Request{Credential: class, Caller: cc}, prompt)
	// A throttled request never reached a human, so it must not be reported as
	// though one turned it down. The engine's message says how many refusals
	// earned the pause and how long is left — which is also what a legitimate
	// tool's error output needs to explain itself to whoever runs it next.
	var throttled *consent.Throttled
	if errors.As(err, &throttled) {
		return fmt.Errorf("consent: %w", err)
	}
	if err != nil || d != consent.Allow {
		return fmt.Errorf("consent: access to your %s credential was not granted", class)
	}
	return nil
}

// trust records pid (with its fork-time stamp) as a consent trust root — a
// `jit run --trust`. The stamp anchors the identity so a recycled pid can't
// inherit a dead run's trust; recording fails silently if the process is
// already gone (nothing to anchor).
func (s *Server) trust(pid int32) {
	start, ok := lineage.ProcessStartTime(pid)
	if !ok {
		return
	}
	s.trustMu.Lock()
	s.trustRoots[pid] = start
	s.trustMu.Unlock()
}

// descendsFromTrust reports whether pid sits in the process tree of a live
// trust root. Each root is re-verified by fork-time before it's honored (a
// recycled pid, or one whose start-time no longer matches, is reaped and
// ignored), then the spike-verified ancestry walk decides descent. Fails
// closed: any unreadable link answers "not trusted", so it can only ever skip
// a prompt for a genuine descendant, never reveal to a stranger.
func (s *Server) descendsFromTrust(pid int32) bool {
	s.trustMu.Lock()
	roots := make(map[int32]int64, len(s.trustRoots))
	for r, st := range s.trustRoots {
		roots[r] = st
	}
	s.trustMu.Unlock()

	for root, start := range roots {
		if cur, ok := lineage.ProcessStartTime(root); !ok || cur != start {
			s.trustMu.Lock()
			if s.trustRoots[root] == start { // reap only if unchanged since our copy
				delete(s.trustRoots, root)
			}
			s.trustMu.Unlock()
			continue
		}
		if lineage.AncestryContainsPID(pid, root) {
			return true
		}
	}
	return false
}

// clearTrust drops every trust root — called on re-lock, so trust never
// outlives the session it was declared in.
func (s *Server) clearTrust() {
	s.trustMu.Lock()
	s.trustRoots = map[int32]int64{}
	s.trustMu.Unlock()
}

// consentCallerForPID builds a consent.Caller for a FIFO mount reader found by
// scanning holders. Identity is BEST-EFFORT (Strength BestEffort): there is no
// socket peer to vouch for it, only an unprivileged process-table scan, so a
// determined same-user attacker could spoof the lineage — the honest weaker
// counterpart to the socket path's kernel-vouched identity.
func consentCallerForPID(pid int32) consent.Caller {
	cc := consent.Caller{PID: pid, Strength: consent.BestEffort}
	if p, ok := lineage.Describe(pid); ok {
		cc.ExecPath = p.ExecPath
	}
	if chain := lineage.Ancestry(pid); len(chain) > 1 {
		cc.Lineage = lineage.LaunchedBy(chain[1:])
	}
	return cc
}

// ConsentReaders makes a best-effort consent decision for a FIFO credential
// mount (gcp/npm/netrc) that no run-scoped grant already authorized: given the
// mount's current holder pids and the credential name, it returns true to serve
// real content. False when consent is off, there are no holders, or ANY holder
// is denied or unidentified — fail closed, the same all-holders-must-pass rule
// the run-scoped grant gate uses. A holder inside a --trust'd run or already
// approved this session is honored without a fresh prompt. Exported because the
// mount serve path lives in the CLI layer (internal/cli), across the package
// boundary from the consent engine the agent holds.
func (s *Server) ConsentReaders(cred string, holders []int32) bool {
	if s.Consent == nil || len(holders) == 0 {
		return false
	}
	// Settle the session first, as gateConsent does: a lapsed session is
	// collected (and consent cleared) before any decision can answer.
	if mek := s.peekSession(); mek != nil {
		wipe(mek)
	}
	for _, h := range holders {
		cc := consentCallerForPID(h)
		cc.DescendsFromGrant = s.descendsFromTrust(h)
		prompt := func(req consent.Request) (consent.Decision, consent.Scope, error) {
			// The "identified by process scan" qualifier is added by
			// consentReason itself, off the caller's BestEffort strength, so
			// it is budgeted alongside the credential name rather than
			// appended past a truncation that would cut into it.
			if err := s.forceDisclosedChallenge(consentReason(req), callerForPID(h)); err != nil {
				// Scoped Once, not Session: see gateConsent — a transient
				// challenge failure must not cache a session-long Deny.
				return consent.Deny, consent.Once, nil
			}
			return consent.Allow, consent.Session, nil
		}
		if d, err := s.Consent.Decide(consent.Request{Credential: cred, Caller: cc}, prompt); err != nil || d != consent.Allow {
			return false
		}
	}
	return true
}
