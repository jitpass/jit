// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/auditlog"
	"github.com/jitpass/jit/internal/keychainwrap"
	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

// runningTool identifies the binary producing this report: release version,
// VCS revision, and whether it satisfies jit's own release-signing
// requirement. design/output-style.md puts build revisions on the diagnostic
// surfaces "where someone is filing a bug", and doctor was carrying none of
// them — a pasted report could not be tied to a release at all.
func runningTool() doctorTool {
	return doctorTool{
		Version:   shortVersion(agent.Version()),
		Build:     agent.BuildID(),
		Signature: binarySignature(),
	}
}

// binarySignature runs the SAME requirement check `jit upgrade` gates on
// (verifyStagedSignature), against this process's own executable. A package
// var so tests don't spawn codesign per doctor invocation.
//
// Worth reporting because that check fails CLOSED: a jit whose signature
// doesn't satisfy the requirement can never self-upgrade, and the error it
// gives names the downloaded file rather than the installed one — so the
// cause is invisible exactly when it matters.
var binarySignature = func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- fixed system binary; the only variable is our own path
	if err := exec.CommandContext(ctx, "/usr/bin/codesign",
		"--verify", "--strict", "-R", signatureRequirement(upgradeTeamID), exe).Run(); err != nil {
		return "unsigned or not a jit release build"
	}
	return "signed " + upgradeTeamID
}

// vaultMasterKeyPresence probes the keychain for this Mac's master encryption
// key WITHOUT reading its bytes and WITHOUT prompting
// (keychainwrap.MEKPresence), so the check is safe on a non-interactive run: a
// piped or CI `jit doctor --format json` gets the same master-key verdict a
// human at a TTY would, instead of skipping the probe to avoid hanging on the
// login keychain's per-signature access dialog. A package var so tests can
// stub it: the real one reads the PRODUCTION keychain, so left un-stubbed it
// would answer from whatever the machine running the test suite happens to
// hold, and the test would be asserting the environment rather than the code.
var vaultMasterKeyPresence = func() keychainwrap.MEKPresence { return keychainwrap.New().MEKPresence() }

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
func gatherSystemFindings(root string, v *vault.Vault) ([]checkFinding, []string) {
	var findings []checkFinding
	findings = append(findings, agentFindings(root)...)
	findings = append(findings, backupFindings(v)...)
	findings = append(findings, auditLogFindings(root)...)
	wrapped, wrapOK := wrapFindings()
	return append(findings, wrapped...), wrapOK
}

// auditLogFindings reports an audit trail that has stopped recording.
//
// auditlog.Append deliberately swallows its write failures — "the audit trail
// is a nicety and a full disk must never make the command that was about to
// be recorded fail after it already ran" — which is the right call at write
// time and leaves nobody to notice. For a tool whose whole job is custody of
// secrets, silently losing the record of what touched them is worth a line.
// auditlog.FileName has been exported "so a reader (jit audit) and doctor can
// name it" since the logger was written; this is doctor finally doing so.
//
// Advisory: the trail going quiet breaks no secret and blocks no command.
func auditLogFindings(root string) []checkFinding {
	path := filepath.Join(root, auditlog.FileName)
	info, err := os.Stat(path)
	if err != nil {
		// No log yet is the normal state on a fresh machine — the first
		// recorded command creates it. Anything else (an unreadable config
		// root) is already reported by the sections above.
		return nil
	}
	if info.IsDir() {
		return []checkFinding{{
			Kind:   kindAudit,
			Detail: fmt.Sprintf("%s is a directory, so no command is being recorded", shortPath(path)),
			Action: "remove it — the next jit command recreates the log",
		}}
	}
	// Openable for append is the exact question Append asks, so ask it the
	// same way rather than inferring from the mode bits: O_APPEND on an
	// existing file creates nothing and writes nothing.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) // #nosec G304 -- jit's own log under its own config root
	if err != nil {
		return []checkFinding{{
			Kind:   kindAudit,
			Detail: fmt.Sprintf("the audit log at %s can't be written, so commands are going unrecorded: %v", shortPath(path), shortHome(err.Error())),
			Action: fmt.Sprintf("`chmod u+w %s`, or remove it to start a fresh trail", shortPath(path)),
		}}
	}
	_ = f.Close()
	return nil
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

	// The probe reads only the key item's presence, never its bytes, and
	// refuses any UI (keychainwrap.MEKPresence), so unlike the old data-reading
	// check it can't raise the login keychain's per-signature "allow access"
	// dialog a re-signed build triggers. That means it no longer has to skip
	// itself on a non-interactive run to avoid hanging: a piped or CI
	// `jit doctor --format json` now reports the same master-key verdict a
	// human would. MEKAbsent is the genuine total-loss state this section
	// exists to catch; MEKIndeterminate (a keychain error, or a query that
	// would have required interaction) is reported as neither present nor gone,
	// so doctor stays silent rather than raise a false alarm.
	if vaultMasterKeyPresence() == keychainwrap.MEKAbsent {
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

// wrapFindings is now the ONLY place wrap's per-tool checks are turned into a
// verdict — `jit wrap doctor` renders through here too rather than keeping a
// second copy that could disagree with this one (and did).
//
// It returns findings for the failures and a plain summary line per passing
// check, the latter only surfaced under --verbose. Positive confirmation was
// the one thing the standalone command offered that the rollup didn't: right
// after `jit wrap add`, "shim, real binary, and profile all resolve" is the
// answer you came for, and doctor could only ever say nothing.
//
// A failure's severity comes from the check (wrap.DoctorCheck.Environmental),
// not from which command is rendering it.
func wrapFindings() ([]checkFinding, []string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return []checkFinding{{Kind: kindWrap, Detail: fmt.Sprintf("could not check wrap shims: %v", err)}}, nil
	}
	var out []checkFinding
	var ok []string
	for _, c := range wrap.Doctor(home, os.Getenv("PATH"), os.Getenv("SHELL")) {
		if c.OK {
			ok = append(ok, fmt.Sprintf("%s: %s", c.Name, c.Detail))
			continue
		}
		kind := kindWrap
		if c.Environmental {
			kind = kindWrapEnv
		}
		out = append(out, checkFinding{Kind: kind, Detail: fmt.Sprintf("%s: %s", c.Name, c.Detail)})
	}
	return out, ok
}
