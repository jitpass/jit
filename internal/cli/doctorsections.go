// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// vaultHasMasterKey probes the keychain for this Mac's master encryption key
// without a challenge and without caching anything (keychainwrap.HasMEK). A
// package var so tests can stub it: the real one reads the PRODUCTION
// keychain, so left un-stubbed it would answer from whatever the machine
// running the test suite happens to hold — true on a developer's Mac, false
// on a CI runner, and the test would be asserting the environment rather than
// the code.
var vaultHasMasterKey = func() bool { return keychainwrap.New().HasMEK() }

// interactiveTTY reports whether a human is on the other end. Stubbed in
// tests for the same reason as vaultHasMasterKey.
var interactiveTTY = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// gatherSystemFindings runs the absorbed mega-doctor sections — agent, backup,
// and wrap-shim health — and returns them as advisory checkFindings (warnings,
// never hard problems; see checkKind.warning). This is what makes `jit doctor`
// a single "what's wrong" rollup instead of three commands: it reuses the
// exact gather functions `jit status` and `jit wrap doctor` already own
// (gatherAgentStatus, gatherMountStatus, gatherVaultStatus, wrap.Doctor), so
// the reports can't drift, and emits a finding ONLY when something is actually
// wrong — a healthy agent/backup/shim stays silent, keeping doctor focused on
// problems rather than restating status's full snapshot. Best-effort per
// section: a section that can't run reports that as its own finding rather
// than failing the whole command.
func gatherSystemFindings(root string, v *vault.Vault) []checkFinding {
	var findings []checkFinding
	findings = append(findings, agentFindings(root)...)
	findings = append(findings, backupFindings(v)...)
	findings = append(findings, wrapFindings()...)
	return findings
}

// gatherVaultIntegrityFindings reports the two whole-vault states that make
// EVERY secret unreadable no matter which profile you asked about: the
// master key missing from this Mac's keychain, and a master-key rotation
// that never finished.
//
// Unlike gatherSystemFindings these run even under --profile. The contract
// --profile promises is "skip the SYSTEM-health sections" — a stopped agent
// and a stale backup say nothing about whether one profile resolves. These
// two say everything about it: with no master key, "this profile's secrets
// all resolve cleanly" is a sentence doctor has no business printing, since
// not one of those envelopes can be opened. Scoping them out would have
// preserved the letter of --profile's contract while handing back exactly
// the false all-clear this whole check exists to stop.
func gatherVaultIntegrityFindings(root string, v *vault.Vault) []checkFinding {
	var out []checkFinding

	// Ordered first: while the marker exists every vault WRITE is refused,
	// so this explains failures the reader may already have hit today.
	if rekeyInProgress(root) {
		out = append(out, checkFinding{
			Kind:   kindRekey,
			Detail: "a master-key rotation is in progress, or was interrupted — every command that writes to the vault will refuse until it finishes.",
			Action: "`jit vault rekey` to finish it",
		})
	}

	// An empty vault with no key is a machine that hasn't run `jit vault
	// init`, which is a state, not a fault — and `jit status` already says
	// "no secrets yet". Only a vault with something IN it can be orphaned
	// from its key.
	paths, err := v.List()
	if err != nil {
		// Reportable, but not here: gatherVaultStatus covers a vault it
		// can't list, and two findings for one I/O error is noise.
		return out
	}
	if len(paths) == 0 {
		return out
	}

	// Deliberately gated on a human being present. HasMEK itself never
	// challenges, but reading a keychain item CAN raise the OS's own
	// "allow access to your keychain" dialog when the requesting binary's
	// signature differs from the one that stored the item — precisely what a
	// re-signed jit build triggers. internal/cli/firstrun.go gates the same
	// call on the same test for the same reason. A piped or CI `jit doctor`
	// must never block on a dialog nobody is there to dismiss, so it skips
	// the probe rather than risk hanging the run.
	if !interactiveTTY() {
		return out
	}
	if !vaultHasMasterKey() {
		out = append(out, checkFinding{
			Kind: kindVaultKey,
			Detail: fmt.Sprintf(
				"the vault holds %s but this Mac's master key is missing from the keychain, so none of them can be decrypted. Every envelope is structurally intact — only the key is gone.",
				countWord(len(paths), "secret", "secrets")),
			Action: "`jit vault import <file>` from a `jit vault export` backup",
		})
	}
	return out
}

// agentFindings surfaces the agent states a user needs to act on: a build
// that drifted from this CLI, an installed-but-not-running service (launchd
// was supposed to keep it up, so this is a real failure, not "go install
// it"), and mounts left unserved because the agent is down. A running,
// current agent — or no agent and nothing that needs one — stays silent.
func agentFindings(root string) []checkFinding {
	st, err := gatherAgentStatus(root)
	if err != nil {
		return []checkFinding{{Kind: kindService, Detail: fmt.Sprintf("could not check the service: %v", err)}}
	}
	return agentFindingsFrom(root, st)
}

// agentFindingsFrom is the classification half, split out from the gathering
// half so every branch is reachable from a test without a live launchd
// service behind it — the reason three of these states went unexercised (and
// one of them, the unreachable agent, silently wrong) until now.
func agentFindingsFrom(root string, st statusAgent) []checkFinding {
	var out []checkFinding
	if warn := agentBuildMismatchLine(st.Build); warn != "" {
		out = append(out, checkFinding{Kind: kindService, Detail: warn})
	}

	switch {
	case st.Error != "":
		// The socket answered with something other than "not running" — a
		// hung agent, a half-written socket, a protocol mismatch after a
		// partial upgrade. gatherAgentStatus reports that state with
		// Running=false, so without this case it fell through to
		// "installed but not running, it may have crashed", which names the
		// wrong fault and drops the only detail worth having. `jit status`
		// has always printed this; doctor, the surface someone is on when
		// they're filing a bug, was the one throwing it away.
		out = append(out, checkFinding{
			Kind:   kindService,
			Detail: fmt.Sprintf("the service is unreachable: %s", st.Error),
			Action: "`jit service restart` to bring it back",
		})
	case !st.Running && st.Installed:
		out = append(out, checkFinding{
			Kind:   kindService,
			Detail: "the service is installed but not running — it may have crashed, or be mid-restart.",
			// installedNotRunningAdvice packs the restart, what it recovers,
			// and the log command into one sentence, which is three next
			// steps on one line. The action line takes at most one (rule:
			// "a reader given three next steps takes none"); the log command
			// follows as its own finding-level note rather than riding along.
			Action: "`jit service restart` — reloads it, recovering even one launchd has dropped. `jit service log` shows recent output",
		})
	case !st.Running:
		// Not installed and not running is fine on its own — you just haven't
		// set the agent up, and profiles/secrets resolve without it. It is
		// only worth flagging when there are mounts that need serving.
		if ms, mErr := gatherMountStatus(root, st); mErr == nil && ms.Registered > 0 {
			out = append(out, checkFinding{
				Kind: kindService,
				Detail: fmt.Sprintf("the service isn't running, so %s %s being served",
					countWord(ms.Registered, "registered mount", "registered mounts"),
					pluralWord(ms.Registered, "isn't", "aren't")),
				Action: "`jit service restart` to start it",
			})
		}
	}
	return out
}

// backupFindings mirrors `jit status`'s backup nudge: the vault only decrypts
// on this Mac, and a `jit vault export` is the one thing that survives losing
// it. Silent for an empty vault (nothing to lose) or an up-to-date export.
func backupFindings(v *vault.Vault) []checkFinding {
	vs, err := gatherVaultStatus(v)
	if err != nil {
		return []checkFinding{{Kind: kindBackup, Detail: fmt.Sprintf("could not check vault backup state: %v", err)}}
	}
	if vs.SecretsStored == 0 && vs.BackupsStored == 0 {
		return nil
	}
	switch {
	case !vs.ExportRecorded:
		return []checkFinding{{
			Kind:   kindBackup,
			Detail: "no vault export on record — the vault only decrypts on this Mac.",
			// Matches the wording `jit status` uses for the same state, so
			// the two surfaces read as one tool.
			Action: "`jit vault export <file>` — a copy you could restore on another Mac",
		}}
	case vs.ExportStale:
		return []checkFinding{{
			Kind: kindBackup,
			Detail: fmt.Sprintf("secrets have changed since the last vault export (%s).",
				time.Unix(vs.ExportUnixTime, 0).Format("2006-01-02")),
			Action: "`jit vault export <file>` — the newest secrets aren't in any backup",
		}}
	}
	return nil
}

// wrapFindings folds `jit wrap doctor`'s per-tool checks into the rollup,
// emitting one finding per FAILED check (a missing shim, a shim pointing at a
// moved binary, a profile gone). A user who never ran `jit wrap add` has no
// shims and gets nothing (wrap.Doctor reports that as an OK check).
func wrapFindings() []checkFinding {
	home, err := os.UserHomeDir()
	if err != nil {
		return []checkFinding{{Kind: kindWrap, Detail: fmt.Sprintf("could not check wrap shims: %v", err)}}
	}
	var out []checkFinding
	for _, c := range wrap.Doctor(home, os.Getenv("PATH"), os.Getenv("SHELL")) {
		if !c.OK {
			out = append(out, checkFinding{Kind: kindWrap, Detail: fmt.Sprintf("%s: %s", c.Name, c.Detail)})
		}
	}
	return out
}
