// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/jitpass/jit/internal/vault"
	"github.com/jitpass/jit/internal/wrap"
)

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

// agentFindings surfaces the agent states a user needs to act on: a build
// that drifted from this CLI, an installed-but-not-running service (launchd
// was supposed to keep it up, so this is a real failure, not "go install
// it"), and mounts left unserved because the agent is down. A running,
// current agent — or no agent and nothing that needs one — stays silent.
func agentFindings(root string) []checkFinding {
	st, err := gatherAgentStatus(root)
	if err != nil {
		return []checkFinding{{Kind: kindAgent, Detail: fmt.Sprintf("could not check the agent: %v", err)}}
	}

	var out []checkFinding
	if warn := agentBuildMismatch(st.Build); warn != "" {
		out = append(out, checkFinding{Kind: kindAgent, Detail: warn})
	}

	switch {
	case !st.Running && st.Installed:
		out = append(out, checkFinding{Kind: kindAgent, Detail: installedNotRunningAdvice("Agent:")})
	case !st.Running:
		// Not installed and not running is fine on its own — you just haven't
		// set the agent up, and profiles/secrets resolve without it. It is
		// only worth flagging when there are mounts that need serving.
		if ms, mErr := gatherMountStatus(root, st); mErr == nil && ms.Registered > 0 {
			out = append(out, checkFinding{Kind: kindAgent, Detail: fmt.Sprintf(
				"agent not running, so %d registered mount(s) aren't being served; run `jit agent install` to start it", ms.Registered)})
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
		return []checkFinding{{Kind: kindBackup, Detail: "no vault export on record, the vault only decrypts on this Mac. Run `jit vault export <file>` so losing it isn't losing every secret."}}
	case vs.ExportStale:
		return []checkFinding{{Kind: kindBackup, Detail: fmt.Sprintf(
			"secrets have changed since the last vault export (%s). Run `jit vault export <file>` to refresh it.",
			time.Unix(vs.ExportUnixTime, 0).Format("2006-01-02"))}}
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
