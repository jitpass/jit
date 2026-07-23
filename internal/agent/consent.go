// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"path/filepath"

	"github.com/jitpass/jit/internal/consent"
	"github.com/jitpass/jit/internal/lineage"
)

// consentCaller maps the kernel-identified socket peer to a consent.Caller.
// Strength is Hard: the pid came from LOCAL_PEERPID at connect time, not a
// scan, so a same-user process cannot forge it.
func consentCaller(c *caller) consent.Caller {
	cc := consent.Caller{Strength: consent.Hard}
	if c == nil {
		return cc
	}
	cc.PID = c.pid
	cc.ExecPath = c.self.ExecPath
	cc.Lineage = lineage.LaunchedBy(c.ancestors)
	return cc
}

// consentReason is the single line the human decides by. Every part is either
// kernel-derived (the caller and its lineage) or authoritative (the class is
// AEAD-bound into the wrap, so a caller cannot lie about it) — nothing
// caller-reported ever reaches this prompt, unlike Request.Label.
func consentReason(cc consent.Caller, class string) string {
	who := filepath.Base(cc.ExecPath)
	if who == "" || who == "." || who == "/" {
		who = fmt.Sprintf("a process (pid %d)", cc.PID)
	}
	if cc.Lineage != "" {
		who = fmt.Sprintf("%s, %s,", who, cc.Lineage)
	}
	return fmt.Sprintf("%s wants your %s credential", who, class)
}

// gateConsent runs the consent decision for one unwrap. It returns nil to
// allow the unwrap, or an error to deny it. It is a no-op (allow) unless
// consent is enabled, the class is one consent gates, and the kernel
// identified the caller — so it never blocks the agent's own in-process mount
// serving (nil caller) or ordinary project secrets.
//
// The prompt is a fresh disclosed Touch ID; approve → allow, decline or no UI
// → deny. Either outcome is remembered for the session (Scope Session) so a
// tool reading the credential repeatedly is asked once, not once per read.
func (s *Server) gateConsent(class string, c *caller) error {
	if s.Consent == nil || c == nil || !consent.RequiresConsent(class) {
		return nil
	}
	cc := consentCaller(c)
	prompt := func(req consent.Request) (consent.Decision, consent.Scope, error) {
		if err := s.forceDisclosedChallenge(consentReason(req.Caller, req.Credential), c); err != nil {
			return consent.Deny, consent.Session, nil
		}
		return consent.Allow, consent.Session, nil
	}
	d, err := s.Consent.Decide(consent.Request{Credential: class, Caller: cc}, prompt)
	if err != nil || d != consent.Allow {
		return fmt.Errorf("consent: access to your %s credential was not granted", class)
	}
	return nil
}
