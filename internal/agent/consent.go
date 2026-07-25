// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package agent

import (
	"fmt"
	"path/filepath"

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
// caller-reported ever reaches this prompt, unlike Request.Label.
//
// Kernel-derived is not the same as attacker-independent, though, and this
// prompt has to survive both differences:
//
//   - The BASENAME is chosen by whoever wrote the file. A process running from
//     /tmp/x/gcloud is honestly reported by the kernel as exactly that, and
//     rendering it as a bare "gcloud" turns the kernel's honesty into the
//     attacker's disguise. So an executable outside the standard tool
//     directories shows where it actually lives (see displayExecPath).
//   - The LENGTH is chosen by the same person. challengeReason has always
//     capped its output because macOS renders the reason as one sentence in a
//     small modal; this one didn't, so a long enough filename could push the
//     part that names the credential out of the dialog entirely. Each variable
//     piece now gets its own budget, and the fixed "wants your <class>
//     credential" tail — the half that carries the actual decision — is never
//     what gets truncated.
func consentReason(cc consent.Caller, class string) string {
	// Built tail-first, so the budget is apportioned from what the fixed part
	// actually costs rather than from constants that have to be re-tuned every
	// time a class name gets longer. Whatever is left over goes to the
	// identity, which is the part that can be arbitrarily long.
	tail := fmt.Sprintf(" wants your %s credential", class)
	budget := maxReasonLen - len([]rune(tail))

	var lineage string
	if cc.Lineage != "" {
		lineage = ", " + truncate(cc.Lineage, maxConsentLineageLen) + ","
	}
	if n := len([]rune(lineage)); n > budget-minConsentWhoLen {
		lineage = "" // a pathological launcher is dropped, never the caller
	}

	who := truncateHead(displayExecPath(cc.ExecPath), budget-len([]rune(lineage)))
	if who == "" {
		who = fmt.Sprintf("a process (pid %d)", cc.PID)
	}
	return who + lineage + tail
}

const (
	// maxConsentLineageLen bounds the launcher half ("launched by npm
	// install"), and minConsentWhoLen is the room reserved for the caller
	// itself no matter what: the launcher is context, the caller is the
	// subject of the sentence, so the launcher is what gets dropped when they
	// can't both fit.
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

func displayExecPath(execPath string) string {
	base := filepath.Base(execPath)
	if execPath == "" || base == "." || base == "/" || base == string(filepath.Separator) {
		return ""
	}
	if standardToolDirs[filepath.Dir(execPath)] {
		return base
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
func (s *Server) gateConsent(class string, c *caller) error {
	if s.Consent == nil || c == nil || !consent.RequiresConsent(class) {
		return nil
	}
	cc := consentCaller(c)
	cc.DescendsFromGrant = s.descendsFromTrust(c.pid)
	prompt := func(req consent.Request) (consent.Decision, consent.Scope, error) {
		if err := s.forceDisclosedChallenge(consentReason(req.Caller, req.Credential), c); err != nil {
			return consent.Deny, consent.Once, nil
		}
		return consent.Allow, consent.Session, nil
	}
	d, err := s.Consent.Decide(consent.Request{Credential: class, Caller: cc}, prompt)
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
	for _, h := range holders {
		cc := consentCallerForPID(h)
		cc.DescendsFromGrant = s.descendsFromTrust(h)
		prompt := func(req consent.Request) (consent.Decision, consent.Scope, error) {
			// The qualifier is the honest part — this identity came from an
			// unprivileged process scan, not a kernel-vouched socket peer — so
			// it must not be what falls off the end of the dialog. Truncate
			// the identity, then append.
			reason := truncate(consentReason(req.Caller, req.Credential), maxReasonLen-len(" (identified by process scan)")) + " (identified by process scan)"
			if err := s.forceDisclosedChallenge(reason, nil); err != nil {
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
