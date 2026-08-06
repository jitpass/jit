// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mount"
	"github.com/jitpass/jit/internal/vault"
)

var (
	statusFormat        string
	statusSecretsDetail bool
)

// statusResult is `jit status`'s --format json shape (GAPS.md #22) — one
// struct per section, mirroring the text report's lines exactly so
// the two representations never drift apart in what they cover.
type statusResult struct {
	CLI     statusCLI     `json:"cli"`
	Vault   statusVault   `json:"vault"`
	Agent   statusAgent   `json:"agent"`
	Secrets statusSecrets `json:"secrets"`
	Mounts  statusMounts  `json:"mounts"`
}

// statusCLI identifies the jit binary answering this very command — the
// release-scale Version alongside the VCS-revision Build, same pair the
// agent section carries for the agent process. Having both in one report
// is what lets a user (or a bug report) say "CLI vX at revision Y, agent
// vX at revision Z" without hunting through separate commands.
type statusCLI struct {
	Version string `json:"version"`
	// Build is agent.BuildID()'s output verbatim, including its "unknown"
	// sentinel (a binary with no VCS info embedded), matching how the
	// agent's own build has always been reported.
	Build string `json:"build,omitempty"`
}

type statusVault struct {
	// SecretsStored counts real secrets only; `_backups/…` entries (kept
	// for `jit migrate undo`) are reported separately so the headline
	// number always agrees with `jit vault list`.
	SecretsStored int `json:"secrets_stored"`
	BackupsStored int `json:"backups_stored"`
	// ExportRecorded/ExportUnixTime/ExportStale surface the vault's one
	// disaster-recovery path: the vault only decrypts on this machine
	// (device keychain-bound), and `jit vault export` is what survives
	// losing it — but nothing ever suggested it existed. Stale means a
	// secret has been written since the recorded export, i.e. the newest
	// secret isn't in any backup.
	ExportRecorded bool  `json:"export_recorded"`
	ExportUnixTime int64 `json:"export_unix_time,omitempty"`
	ExportStale    bool  `json:"export_stale,omitempty"`
}

// statusAgent mirrors agentStatusResult (agent.go) deliberately, field for
// field — `jit status` and `jit service status` report the same
// underlying state and shouldn't diverge in shape just because one is a
// section of a larger report. Mounts (GAPS.md #37) is no exception.
type statusAgent struct {
	Running bool `json:"running"`
	// Installed mirrors agentStatusResult.Installed: with Running false,
	// it separates "crashed or mid-restart" from "never set up" — two
	// states with entirely different fixes.
	Installed      bool                      `json:"installed"`
	Unlocked       bool                      `json:"unlocked"`
	LocksInSeconds int64                     `json:"locks_in_seconds,omitempty"`
	Mounts         []agent.MountRevealStatus `json:"mounts"`
	Build          string                    `json:"build,omitempty"`
	// Version is the running service PROCESS's release version, empty when
	// the agent isn't running or predates the field — the counterpart to
	// statusCLI.Version, at the same release-scale zoom Build refines.
	Version string `json:"version,omitempty"`
	// Error is set when the socket exists but the conversation failed — a
	// hung agent, a half-written socket, a protocol mismatch after a partial
	// upgrade. `jit status` promises a safe, always-runnable overview, so a
	// sick service degrades to one reported section rather than taking the
	// vault, secrets and mounts sections down with it.
	Error string `json:"error,omitempty"`
}

// statusSecrets reconciles the flat vault store against the profiles jit can
// see from cwd — the picture the retired `jit profile list` never drew. Every
// stored secret is one of: wired here (a project-local profile uses it), managed
// elsewhere (referenced only by a global profile or a mount), or unreferenced
// (a candidate orphan). Groups is populated only with --secrets, to keep the
// default snapshot small.
type statusSecrets struct {
	TotalSecrets int `json:"total_secrets"`
	TotalGroups  int `json:"total_groups"`

	WiredGroups     int `json:"wired_groups"`
	WiredProfiles   int `json:"wired_profiles"`
	WiredReferences int `json:"wired_references"`
	// WiredProblems counts project-local references whose secret isn't stored —
	// the wired-but-broken references `jit doctor` reports in full.
	WiredProblems int `json:"wired_problems"`

	ManagedElsewhereGroups int `json:"managed_elsewhere_groups"`

	UnreferencedGroups  int `json:"unreferenced_groups"`
	UnreferencedSecrets int `json:"unreferenced_secrets"`
	// UnreferencedInMixed counts unreferenced secrets inside groups bucketed
	// as wired/elsewhere — the ones `jit vault orphans` lists but the group
	// totals above can't, so the two commands don't look like they disagree.
	UnreferencedInMixed int `json:"unreferenced_in_mixed,omitempty"`
	// DuplicateGroups/DuplicateSecrets are the subset of the unreferenced
	// totals that carry the same key names as a group still in use — the
	// leftovers a re-migration renamed past. A subset, never an extra bucket.
	DuplicateGroups  int `json:"duplicate_groups,omitempty"`
	DuplicateSecrets int `json:"duplicate_secrets,omitempty"`

	// ParseFailures counts visible profile manifests that wouldn't load; their
	// references are excluded, so secrets don't get mislabeled unreferenced.
	ParseFailures int `json:"parse_failures,omitempty"`

	Groups []statusSecretGroup `json:"groups,omitempty"`
}

// statusSecretGroup is one group's --secrets JSON row: its name, its dominant
// state as a stable slug, its secret keys, and whether its members disagree.
type statusSecretGroup struct {
	Name    string   `json:"name"`
	State   string   `json:"state"`
	Secrets []string `json:"secrets"`
	Mixed   bool     `json:"mixed,omitempty"`
	// DuplicateOf names the still-referenced group this unreferenced one
	// mirrors key-for-key (by name — status never decrypts).
	DuplicateOf string `json:"duplicate_of,omitempty"`
}

// stateSlug renders a secretState as the stable identifier the JSON and the
// text detail view both use.
func stateSlug(s secretState) string {
	switch s {
	case stateWiredHere:
		return "wired-here"
	case stateManagedElsewhere:
		return "managed-elsewhere"
	default:
		return "unreferenced"
	}
}

// secretsStatusFrom projects a reconciliation onto the JSON/report shape,
// attaching the per-group detail only when asked (the --secrets path).
func secretsStatusFrom(rec secretsReconciliation, includeGroups bool) statusSecrets {
	s := statusSecrets{
		TotalSecrets:           rec.TotalSecrets,
		TotalGroups:            rec.TotalGroups,
		WiredGroups:            rec.WiredGroups,
		WiredProfiles:          rec.WiredProfiles,
		WiredReferences:        rec.WiredRefs,
		WiredProblems:          rec.WiredProblems,
		ManagedElsewhereGroups: rec.ElsewhereGroups,
		UnreferencedGroups:     rec.UnreferencedGroups,
		UnreferencedSecrets:    rec.UnreferencedSecrets,
		UnreferencedInMixed:    rec.UnreferencedInMixed,
		DuplicateGroups:        rec.DuplicateGroups,
		DuplicateSecrets:       rec.DuplicateSecrets,
		ParseFailures:          rec.ParseFailures,
	}
	if includeGroups {
		s.Groups = make([]statusSecretGroup, 0, len(rec.Groups))
		for _, g := range rec.Groups {
			keys := make([]string, 0, len(g.Members))
			for _, m := range g.Members {
				keys = append(keys, m.Key)
			}
			s.Groups = append(s.Groups, statusSecretGroup{
				Name:        g.Name,
				State:       stateSlug(g.State),
				Secrets:     keys,
				Mixed:       g.Mixed,
				DuplicateOf: g.DuplicateOf,
			})
		}
	}
	return s
}

// statusMounts.BeingServed is inferred from agent running+unlocked state,
// not a per-mount query RPC (none exists) — see printMountsText/gatherMounts.
type statusMounts struct {
	Registered  int  `json:"registered"`
	BeingServed bool `json:"being_served"`
	// ServingReal is true only when the agent is unlocked — GAPS.md #35
	// made BeingServed true whenever the agent process is merely running,
	// locked or not, since a mount always has at least decoy content
	// behind it by then. Real content additionally needs an unlock (so the
	// vault can be resolved) AND, per mount, an active run-scoped grant
	// (jit run --live/--with) to actually flow to a reader — this field
	// distinguishes "decoy only" from "real content can be granted" in the
	// text report below.
	ServingReal bool `json:"serving_real"`
}

var statusCmd = &cobra.Command{
	Use:     "status",
	GroupID: groupWorkflow,
	Short:   "One-shot overview of vault, service, secret, and mount health",
	Long: "Rolls up what previously took several separate commands to piece together, " +
		"is the vault initialized, is the service running and unlocked, how do this " +
		"project's stored secrets line up against its profiles, are mounts being served, " +
		"into one read-only report. Never decrypts a secret value or triggers a Touch " +
		"ID/passcode prompt, matching jit doctor's own safe-to-run-often " +
		"shape; each section points at the dedicated command for full detail rather than " +
		"duplicating it.\n\n" +
		"The Secrets section reconciles the vault against the profiles jit can see: every " +
		"stored secret is wired here (a project-local profile uses it), managed elsewhere " +
		"(referenced only by a global profile or a mount), or unreferenced (a candidate " +
		"orphan). Add --secrets to expand it into the full per-group listing.\n\n" +
		"An unreferenced group holding the same key names as a group still in use is " +
		"called out as such: usually a second migration renamed the group and left the " +
		"original copy behind, and those leftovers are usually the bulk of what " +
		"jit vault orphans would prune. Key names are compared, never values, since " +
		"status never decrypts.\n\n" +
		"--format json prints a machine-readable snapshot instead of the default " +
		"text report, in the same shape jit service status/vault list/doctor's own " +
		"--format json use for their overlapping sections.",
	Args: cobra.NoArgs,
	// See doctor.go's SilenceUsage comment — a --format json snapshot must
	// never have cobra's usage text appended to it on a RunE error.
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateOutputFormat(statusFormat); err != nil {
			return fmt.Errorf("jit status: %w", err)
		}

		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("jit status: %w", err)
		}
		root, err := vaultRootDir()
		if err != nil {
			return fmt.Errorf("jit status: %w", err)
		}
		v, err := openVaultReadOnly()
		if err != nil {
			return fmt.Errorf("jit status: %w", err)
		}

		vaultStatus, err := gatherVaultStatus(v)
		if err != nil {
			return fmt.Errorf("jit status: listing vault: %w", err)
		}
		agentStatus, err := gatherAgentStatus(root)
		if err != nil {
			return fmt.Errorf("jit status: checking the service: %w", err)
		}
		rec, err := reconcileSecrets(root, cwd, v)
		if err != nil {
			return fmt.Errorf("jit status: reconciling secrets: %w", err)
		}
		mountStatus, err := gatherMountStatus(root, agentStatus)
		if err != nil {
			return fmt.Errorf("jit status: reading mount registry: %w", err)
		}

		result := statusResult{
			CLI:     statusCLI{Version: agent.Version(), Build: agent.BuildID()},
			Vault:   vaultStatus,
			Agent:   agentStatus,
			Secrets: secretsStatusFrom(rec, statusSecretsDetail),
			Mounts:  mountStatus,
		}
		if statusFormat == "json" {
			return writeJSON(cmd.OutOrStdout(), result)
		}
		printStatusText(cmd.OutOrStdout(), result)
		if statusSecretsDetail {
			printSecretsDetail(cmd.OutOrStdout(), rec, v)
		}
		noteFolderRename(cmd.OutOrStdout(), cwd)
		return nil
	},
}

// gatherVaultStatus reports how many secrets are stored, never their
// values, via the same read-only Exists/List path jit doctor uses (no
// KeyWrapper, so no local-auth prompt).
func gatherVaultStatus(v *vault.Vault) (statusVault, error) {
	paths, err := v.List()
	if err != nil {
		return statusVault{}, err
	}
	secrets, backups := splitBackupPaths(paths)
	result := statusVault{SecretsStored: len(secrets), BackupsStored: len(backups)}
	if len(paths) == 0 {
		return result, nil // an empty vault has nothing worth exporting, no nudge
	}
	exportedAt, recorded, err := vault.LastExport(v.Root)
	if err != nil {
		return statusVault{}, err
	}
	if recorded {
		result.ExportRecorded = true
		result.ExportUnixTime = exportedAt.Unix()
		newest, err := v.NewestSecretTime()
		if err != nil {
			return statusVault{}, err
		}
		result.ExportStale = newest.After(exportedAt)
	}
	return result, nil
}

// agentBuildMismatch returns a warning when the running service process was
// built from a different revision than this CLI, or "" when they match or
// either side can't tell (GAPS.md #49). launchd's KeepAlive keeps an old
// agent process alive across rebuilds and reinstalls indefinitely — a real
// investigation trap: the running service predated the binary on disk by 21
// minutes and nothing anywhere could say so, making a just-built fix look
// like it didn't work. Shared by `jit status` and `jit service status`;
// lives in this file (not agent.go) because status.go is deliberately
// portable while agent.go is darwin-gated.
// It returns the two build IDs rather than a finished sentence, because the
// two audiences want different things from them: the dashboard is being read
// by someone finding out whether anything needs doing, and a pair of git
// revisions answers no question they have, while doctor and `jit service
// status` are where you go to file or diagnose a bug and the revisions are
// the whole point. ok is false when they match or either side can't tell.
//
// Note it can only prove the builds DIFFER, never which is newer — neither
// side carries a timestamp. Wording built on this must stay symmetrical: "out
// of date" would be a guess, right though it usually would be.
func agentBuildMismatch(agentBuild string) (service, cli string, ok bool) {
	cliBuild := agent.BuildID()
	if agentBuild == "" || agentBuild == "unknown" || cliBuild == "unknown" || agentBuild == cliBuild {
		return "", "", false
	}
	return agentBuild, cliBuild, true
}

// agentBuildMismatchLine is the flat one-sentence form, for the diagnostic
// surfaces that render a finding as a single string rather than as a state
// row with an action beneath it — and that do want the revisions named.
func agentBuildMismatchLine(agentBuild string) string {
	service, cli, ok := agentBuildMismatch(agentBuild)
	if !ok {
		return ""
	}
	return fmt.Sprintf("The background service is running a different build than this CLI (service %s, CLI %s) — run `jit service restart` to move it to the current binary.", service, cli)
}

// gatherAgentStatus reports the same running/unlocked state `jit service
// status` does.
func gatherAgentStatus(root string) (statusAgent, error) {
	client := agent.NewClient(agent.SocketPath(root))
	st, err := client.Status()
	if errors.Is(err, agent.ErrNotRunning) {
		// Not running is a reportable state, not an error — and whether
		// it's ALSO installed decides which fix the report suggests.
		return statusAgent{Installed: agentInstalled()}, nil
	}
	if err != nil {
		// Reportable, not fatal: the rest of the report (vault, secrets,
		// mounts) is still readable and still worth printing. Taking the
		// whole overview down because the service is sick is exactly
		// backwards — a sick service is when you most want to look at it.
		return statusAgent{Installed: agentInstalled(), Error: err.Error()}, nil
	}
	result := statusAgent{Running: true, Installed: agentInstalled(), Unlocked: st.Unlocked, Mounts: st.Mounts, Build: st.Build, Version: st.Version}
	if st.Unlocked {
		result.LocksInSeconds = int64(st.Remaining.Round(time.Second).Seconds())
	}
	return result, nil
}

// gatherMountStatus reports how many mounts are registered and infers
// whether they're actually being served from the agent's own state —
// there's no separate per-mount query RPC, so this is the same inference
// the rest of this package already relies on (e.g. jit migrate's own
// post-registration messaging). GAPS.md #35 changed what that inference
// means: a mount now has at least decoy content behind it as soon as the
// agent PROCESS is running, locked or not (mountManager.startDecoyOnly
// runs at raw startup, and stop/OnLock no longer tears serving down) —
// only "agent not running at all" means truly unserved. ServingReal is
// the narrower "real content is potentially available" signal, which
// still does need an actual unlock.
func gatherMountStatus(root string, agentStatus statusAgent) (statusMounts, error) {
	entries, err := mount.LoadRegistry(mount.RegistryPath(root))
	if err != nil {
		return statusMounts{}, err
	}
	return statusMounts{
		Registered:  len(entries),
		BeingServed: len(entries) > 0 && agentStatus.Running,
		ServingReal: len(entries) > 0 && agentStatus.Running && agentStatus.Unlocked,
	}, nil
}

// versionBuild renders one binary's identity — "dev (build 4486c1c1234a)"
// — from whichever halves are actually known: BuildID's "unknown" sentinel
// and an old agent's empty version both just drop out rather than being
// printed as if they were facts.
func versionBuild(version, build string) string {
	if build == "" || build == "unknown" {
		if version == "" {
			return "version unknown"
		}
		return version
	}
	if version == "" {
		return fmt.Sprintf("build %s", build)
	}
	return fmt.Sprintf("%s (build %s)", version, build)
}

// statusVersionTail is the jit row's value: release versions only. The build
// revisions this row used to carry are diagnostic — they answer a question only
// someone filing a bug is asking — and they live on `jit service status` and
// `jit doctor`, which is where that person already is. The service version
// appears only when it differs from the CLI's, since printing the same string
// twice tells the reader nothing.
func statusVersionTail(r statusResult) string {
	cli := shortVersion(r.CLI.Version)
	if cli == "" {
		cli = "version unknown"
	}
	if r.Agent.Running && r.Agent.Version != "" && r.Agent.Version != r.CLI.Version {
		return cli + " · service " + shortVersion(r.Agent.Version)
	}
	return cli
}

// goPseudoVersion matches the tail Go synthesises for a module with no release
// tag — "-0.20260729054817-5107fa37ec1e", optionally "+dirty".
var goPseudoVersion = regexp.MustCompile(`-(0\.)?\d{14}-[0-9a-f]{12}(\+dirty)?$`)

// shortVersion reduces a version to the part a human reads. A released binary
// carries a plain "0.66.0" and passes through untouched; one built straight
// from a checkout gets Go's pseudo-version, and
// "v0.66.1-0.20260729054817-5107fa37ec1e+dirty" is a build-system artifact
// nobody reads. A genuine prerelease suffix ("-rc1") is short and meaningful,
// so only the pseudo-version tail is stripped.
func shortVersion(v string) string {
	return goPseudoVersion.ReplaceAllString(v, "")
}

// printStatusHeadline prints the jit row: which version is answering. It
// briefly carried a verdict ("1 thing to fix") instead, which counted the
// findings without naming them — so the one question it existed to answer,
// "what needs doing?", still meant scanning the rows below for the glyph it
// was referring to. The glyph column already does that job, and does it
// pointing at the actual line.
func printStatusHeadline(w io.Writer, r statusResult) {
	statusLabel(w, "jit")
	printStatusValue(w, "%s", statusVersionTail(r))
}

func printStatusText(w io.Writer, r statusResult) {
	// The dashboard reads as aligned label/value rows (docker-style): a plain
	// fixed-width label, then the value, with a semantic glyph leading any row
	// that carries a state so the one needing attention is found at a glance
	// (design/output-style.md).
	printStatusHeadline(w, r)

	if r.Vault.SecretsStored == 0 && r.Vault.BackupsStored == 0 {
		statusLabel(w, "vault")
		printStatusValue(w, "%s", hlCmds("no secrets yet — run `jit vault init`, or `jit migrate .` to populate it."))
	} else {
		statusLabel(w, "vault")
		// The group breakdown moved up here from the secrets rollup, which
		// used to restate the same total one section later ("57 secrets
		// stored" then "57 stored in 13 groups"). Stated once, on the row
		// that owns the number. A backups-only vault has no groups to
		// report, and "0 secrets in 0 groups" reads like a broken template,
		// so the clause is dropped rather than rendered empty.
		stored := countWord(r.Vault.SecretsStored, "secret", "secrets")
		if r.Vault.SecretsStored > 0 {
			stored += " in " + countWord(r.Secrets.TotalGroups, "group", "groups")
		}
		if r.Vault.BackupsStored > 0 {
			// hlCmds, like every other command mention in this report: without
			// it the backticks printed literally, so this one line leaked its
			// own markup while the line above rendered the same kind of
			// command in cyan.
			printStatusValue(w, "%s", hlCmds(fmt.Sprintf("%s · %s kept for `jit migrate undo`",
				stored, countWord(r.Vault.BackupsStored, "file backup", "file backups"))))
		} else {
			printStatusValue(w, "%s", stored)
		}
		statusLabel(w, "backup")
		switch {
		case !r.Vault.ExportRecorded:
			_, _ = cRisk.Fprint(w, glyphRisk+" ")
			printStatusGlyphValue(w, "no vault export on record — the vault only decrypts on this Mac")
			// Says what the export IS, in concrete terms the reader can
			// picture. An earlier draft ("the only copy that survives losing
			// it") left "it" pointing at either the Mac or the vault, and
			// made the reader work out what an export even is.
			printStatusAction(w, "`jit vault export <file>` — a copy you could restore on another Mac")
		case r.Vault.ExportStale:
			_, _ = cWarn.Fprint(w, glyphWarn+" ")
			printStatusGlyphValue(w, "secrets changed since the last export (%s)", time.Unix(r.Vault.ExportUnixTime, 0).Format("2006-01-02"))
			printStatusAction(w, "`jit vault export <file>` — the newest secrets aren't in any backup")
		default:
			_, _ = cOK.Fprint(w, glyphOK+" ")
			printStatusGlyphValue(w, "export up to date (%s)", time.Unix(r.Vault.ExportUnixTime, 0).Format("2006-01-02"))
		}
	}

	statusLabel(w, "service")
	switch {
	case r.Agent.Error != "":
		// The socket answered with something other than "not running" — a
		// hung or mismatched agent. Say so rather than reporting the
		// no-service state, which would send the reader after the wrong fix.
		_, _ = cRisk.Fprint(w, glyphRisk+" ")
		printStatusGlyphValue(w, "unreachable — %s", r.Agent.Error)
		printStatusAction(w, "`jit service restart` to bring it back")
	case !r.Agent.Running && r.Agent.Installed:
		// launchd was supposed to keep this one alive — "run install" is
		// the wrong advice and hides that something actually failed.
		_, _ = cRisk.Fprint(w, glyphRisk+" ")
		printStatusGlyphValue(w, "%s", installedNotRunningAdvice("the service is"))
	case !r.Agent.Running:
		_, _ = cRisk.Fprint(w, glyphRisk+" ")
		fmt.Fprint(w, "not running — run ")
		_, _ = cPath.Fprintln(w, "jit service restart")
	case r.Agent.Unlocked:
		_, _ = cOK.Fprint(w, glyphOK+" ")
		printStatusGlyphValue(w, "running · unlocked (locks in %s)", (time.Duration(r.Agent.LocksInSeconds) * time.Second).String())
	default:
		_, _ = cOK.Fprint(w, glyphOK+" ")
		printStatusGlyphValue(w, "running · locked")
	}
	if _, _, mismatched := agentBuildMismatch(r.Agent.Build); mismatched {
		// Says what jit is (two programs, which is news to most readers),
		// then the consequence, then the fix. The revisions live in `jit
		// service status` and `jit doctor` — naming them here answered a
		// question nobody reading a dashboard was asking, and cost the line
		// the room it needed to explain itself.
		printStatusWarnNote(w, "running a different build than this command; recent changes may not take effect until they match")
		printStatusAction(w, "`jit service restart` — or leave it; it self-restarts once locked and idle")
	}

	printSecretsSection(w, r.Secrets)

	statusLabel(w, "mounts")
	registered := countWord(r.Mounts.Registered, "registered mount", "registered mounts")
	switch {
	case r.Mounts.Registered == 0:
		printStatusValue(w, "%s", "none registered")
	case r.Mounts.ServingReal:
		granted := 0
		for _, m := range r.Agent.Mounts {
			if len(m.Grants) > 0 {
				granted++
			}
		}
		if granted > 0 {
			_, _ = cOK.Fprint(w, glyphOK+" ")
			printStatusGlyphValue(w, "%s · %d serving real content to an active jit run grant, the rest decoy", registered, granted)
		} else {
			printStatusValue(w, "%s · unlocked, all decoy (real values flow through a jit run grant, or an approved consent prompt for a global credential file)", registered)
		}
	case r.Mounts.BeingServed:
		_, _ = cWarn.Fprint(w, glyphWarn+" ")
		printStatusGlyphValue(w, "%s · serving decoy content only (service locked)", registered)
	default:
		printStatusValue(w, "%s · not being served (service not running)", registered)
	}

	// A reader that most recently got DECOY values is the one mount fact
	// worth surfacing in the rollup itself: it's either harmless (a backup
	// tool, an editor) or exactly the "my dev server is failing and
	// nothing says why" case — and only the user can tell which, so say
	// it happened and point at the command with the who/when detail.
	decoyReads := 0
	for _, m := range r.Agent.Mounts {
		if m.LastServe != nil && m.LastServe.Decoy {
			decoyReads++
		}
	}
	if decoyReads > 0 {
		printStatusWarnNote(w, "%s most recently served decoy values to a reader.",
			countWord(decoyReads, "mount", "mounts"))
		printStatusAction(w, "`jit service status` to see which reader, and when")
	}
}

// printSecretsSection renders the vault<->profile reconciliation rollup: how
// many secrets are stored, and how they split across wired-here (a project-local
// profile uses them), managed-elsewhere (a global profile or a mount), and
// unreferenced-here (candidate orphans). It replaces the old `Profiles:` line,
// which could only ever count the manifests in this folder and never told the
// user about the secrets those manifests don't touch.
func printSecretsSection(w io.Writer, s statusSecrets) {
	// "none stored yet" only when there is genuinely nothing to reconcile: no
	// secrets, no profile, no unreadable manifest. A project profile that points
	// at a missing secret (WiredProblems) must still surface even on an otherwise
	// empty vault, so it can't short-circuit here. Deliberately not the phrase
	// "no secrets stored yet" — that belongs to the Vault line, and colliding
	// with it would make a backups-only vault look wrongly empty.
	if s.TotalSecrets == 0 && s.WiredProfiles == 0 && s.ParseFailures == 0 {
		statusLabel(w, "secrets")
		printStatusValue(w, "%s", "none stored yet")
		return
	}
	statusLabel(w, "secrets")
	printStatusValue(w, "%s", "reconciled against every profile and mount")

	// Each state leads with a semantic glyph so the eye finds the one that
	// needs attention (an amber ○ unreferenced, or a red ✗ broken) before
	// reading a word — the same glyph vocabulary `jit status --secrets` uses
	// for these exact states, so the rollup and the detail read as one.
	switch {
	case s.WiredProfiles == 0:
		printEmptyRollupLine(w, "Wired here", "none — no project-local profile")
	case s.WiredProblems == 0:
		// "Resolve" here means the referenced secret EXISTS — the cheap glance,
		// existence-only. jit doctor additionally verifies each envelope reads,
		// so point there rather than imply an integrity check this didn't run.
		printRollupLine(w, cOK, glyphOK, "Wired here", fmt.Sprintf("%s via %s (%s), all resolve.",
			countWord(s.WiredGroups, "group", "groups"),
			countWord(s.WiredProfiles, "profile", "profiles"),
			countWord(s.WiredReferences, "reference", "references")))
	default:
		printRollupLine(w, cRisk, glyphRisk, "Wired here", fmt.Sprintf("%s via %s (%s), %d broken — run `jit doctor` for details.",
			countWord(s.WiredGroups, "group", "groups"),
			countWord(s.WiredProfiles, "profile", "profiles"),
			countWord(s.WiredReferences, "reference", "references"), s.WiredProblems))
	}

	printRollupLine(w, cOK, glyphOK, "Managed elsewhere", fmt.Sprintf("%s · referenced only by global profiles or mounts",
		countWord(s.ManagedElsewhereGroups, "group", "groups")))

	if s.UnreferencedGroups == 0 {
		printEmptyRollupLine(w, "Unreferenced here", "none")
	} else {
		printRollupLine(w, cWarn, glyphWarn, "Unreferenced here", fmt.Sprintf("%s, %s. May belong to another project.",
			countWord(s.UnreferencedGroups, "group", "groups"),
			countWord(s.UnreferencedSecrets, "secret", "secrets")))
		// The single most useful thing to say about a pile of orphans is
		// which of them are already accounted for elsewhere. Without this the
		// reader has to diff the group listings by eye before they can safely
		// prune anything, so most people never prune at all.
		if s.DuplicateGroups > 0 {
			// Three phrasings, because the difference matters to the reader:
			// "3 of them" says part of this pile is accounted for, "all 3"
			// says the whole pile is, and the lone-group case gets a singular
			// verb rather than the "all 1" this first shipped as.
			subject, verb := fmt.Sprintf("%d of them", s.DuplicateGroups), "have"
			switch {
			case s.UnreferencedGroups == 1:
				subject, verb = "it", "has"
			case s.DuplicateGroups == s.UnreferencedGroups:
				subject = fmt.Sprintf("all %d", s.DuplicateGroups)
			}
			// Plain words, deliberately: an earlier draft called this "the
			// fingerprint of a re-migration", which is the author's vocabulary
			// rather than the reader's. Say what probably happened instead.
			printStatusNote(w, "%s (%s) %s the same key names as a group still in use.", subject,
				countWord(s.DuplicateSecrets, "secret", "secrets"), verb)
			printStatusNote(w, "Usually a second migration renamed the group; jit compared names, not values.")
		}
		printStatusAction(w, "`jit status --secrets` to inspect · `jit vault orphans --prune` to delete")
	}

	// Stated whatever the group totals say, including when they say "none":
	// this is exactly the case where `jit vault orphans` reports secrets the
	// rollup above doesn't, and an unexplained mismatch between two jit
	// commands costs more trust than the number is worth.
	if s.UnreferencedInMixed > 0 {
		printStatusNote(w, "%s inside groups counted above as in use %s unreferenced too;",
			countWord(s.UnreferencedInMixed, "secret", "secrets"),
			pluralWord(s.UnreferencedInMixed, "is", "are"))
		printStatusNote(w, "jit vault orphans lists those as well.")
	}

	if s.ParseFailures > 0 {
		printStatusWarnNote(w, "%s couldn't be read and %s skipped.",
			countWord(s.ParseFailures, "profile manifest", "profile manifests"),
			pluralWord(s.ParseFailures, "was", "were"))
		printStatusAction(w, "`jit doctor` to see which")
	}
}

// statusLabel prints one dashboard row's label (jit, vault, backup, service,
// secrets, mounts) in plain default weight, padded to a fixed width so the
// values line up in a column docker-style. No brackets, no bold: faint was
// an unreadable dark grey here long before it was removed tool-wide, and the
// user preferred a plain word to both bold and the older bracket delimiter. The caller prints the value —
// with a leading glyph for a state-bearing row — immediately after, then its
// own newline.
func statusLabel(w io.Writer, label string) {
	fmt.Fprintf(w, "%-*s", statusLabelWidth, label)
}

// The dashboard's two continuation columns. A value that outruns the window
// has to resume under the value column, not at column 0 where the terminal
// would put it; a value that leads with a glyph has to clear the glyph too,
// or its second line reads as an unmarked row of its own.
const (
	statusLabelWidth = 9
	statusGlyphWidth = statusLabelWidth + 2
)

var (
	statusValueIndent = strings.Repeat(" ", statusLabelWidth)
	statusGlyphIndent = strings.Repeat(" ", statusGlyphWidth)
)

// printStatusValue completes a row the caller opened with statusLabel.
func printStatusValue(w io.Writer, format string, a ...any) {
	wrapBody(w, statusLabelWidth, statusValueIndent, fmt.Sprintf(format, a...))
}

// printStatusGlyphValue completes a row whose value already leads with a
// state glyph, so continuations hang past it.
func printStatusGlyphValue(w io.Writer, format string, a ...any) {
	wrapBody(w, statusGlyphWidth, statusGlyphIndent, fmt.Sprintf(format, a...))
}

// printRollupLine renders one Secrets-rollup row: a semantic state glyph, the
// fixed-width state label, and its body. The glyph carries the state in color
// (green healthy, amber needs-a-look, red broken); the body stays default
// weight so the glyph column, not a wall of colored text, is what the eye
// scans down. The label pad matches the continuation indent above.
// printStatusAction renders one runnable next step in `jit scan`'s action
// shape: an indented arrow, then the step with its `backtick`-delimited
// commands in the house cyan. Scan established that a state line says what IS
// and the arrow line beneath says what to DO; the dashboard used to bury the
// same advice mid-sentence ("… — run jit vault export <file>"), where it read
// as prose rather than as a thing to go type.
func printStatusAction(w io.Writer, body string) {
	fmt.Fprint(w, statusNoteIndent)
	_, _ = cPath.Fprint(w, glyphAction+" ")
	wrapBody(w, len(statusNoteIndent)+2, statusNoteIndent+"  ", hlCmds(body))
}

// statusNoteIndent is where the arrow and the explanatory notes hang. It sits
// left of the value column on purpose: an action belongs to the whole row
// above it, not to the value's text.
const statusNoteIndent = "      "

// printStatusNote renders one explanatory line under a state line, at the
// same indent as the action arrow — scan's habit of explaining a finding just
// above the command that resolves it. Plain by rule 3: an explanation is
// secondary to the state it explains, and secondary text takes no colour and
// no weight.
func printStatusNote(w io.Writer, format string, a ...any) {
	fmt.Fprint(w, statusNoteIndent)
	wrapBody(w, len(statusNoteIndent), statusNoteIndent,
		fmt.Sprintf(format, a...))
}

// printStatusWarnNote is printStatusNote for a line that carries a STATE of
// its own rather than explaining one: it leads with the amber warn glyph and
// stays default weight. The distinction matters because a warning rendered
// with no glyph, directly beneath a green row reads as part of that
// healthy row — which is exactly how the build-mismatch notice disappeared.
func printStatusWarnNote(w io.Writer, format string, a ...any) {
	fmt.Fprint(w, statusNoteIndent)
	_, _ = cWarn.Fprintf(w, "%s ", glyphWarn)
	wrapBody(w, len(statusNoteIndent)+2, statusNoteIndent+"  ",
		fmt.Sprintf(format, a...))
}

func printRollupLine(w io.Writer, glyphColor *color.Color, glyph, label, body string) {
	fmt.Fprint(w, "  ")
	_, _ = glyphColor.Fprintf(w, "%s ", glyph)
	fmt.Fprintf(w, "%-*s", rollupLabelWidth, label)
	fmt.Fprint(w, "  ")
	used := 2 + 2 + rollupLabelWidth + 2
	wrapBody(w, used, strings.Repeat(" ", used), body)
}

// printEmptyRollupLine is printRollupLine for a state with nothing in it. It
// prints NO glyph: the glyph column means "here is a state to read", and a
// mark of any color beside the word "none" claims there is something there.
// The row still holds its column so the three states stay aligned.
func printEmptyRollupLine(w io.Writer, label, body string) {
	fmt.Fprint(w, "    ")
	_, _ = fmt.Fprintf(w, "%-*s", rollupLabelWidth, label)
	fmt.Fprint(w, "  ")
	used := 4 + rollupLabelWidth + 2
	wrapBody(w, used, strings.Repeat(" ", used), body)
}

// rollupLabelWidth holds "Unreferenced here" plus a space of air.
const rollupLabelWidth = 18

// printSecretsDetail is the `jit status --secrets` body: the full reconciliation,
// one block per state. The unreferenced block reuses printOrphanGroups verbatim,
// so it renders identically (origins and ages included) to `jit vault orphans` —
// the two views can't drift. This is where the retired `jit profile list`
// content now lives, enriched from "manifests in this folder" into "every stored
// secret, and who references it".
func printSecretsDetail(w io.Writer, rec secretsReconciliation, v *vault.Vault) {
	var wired, elsewhere, unref []secretGroup
	for _, g := range rec.Groups {
		switch g.State {
		case stateWiredHere:
			wired = append(wired, g)
		case stateManagedElsewhere:
			elsewhere = append(elsewhere, g)
		default:
			unref = append(unref, g)
		}
	}

	// Section headers follow the house style: a title with a plain one-line
	// summary, then the groups, then a blank line — whitespace does the
	// separating, no rules (see design/output-style.md).
	printSecretsStateHeader(w, glyphOK, "Wired here",
		fmt.Sprintf("%d %s · %d %s", len(wired), pluralWord(len(wired), "group", "groups"), rec.WiredProfiles, pluralWord(rec.WiredProfiles, "profile", "profiles")))
	printGroupsWithKeys(w, wired)

	printSecretsStateHeader(w, glyphOK, "Managed elsewhere",
		fmt.Sprintf("%d %s · referenced by global profiles or mounts", len(elsewhere), pluralWord(len(elsewhere), "group", "groups")))
	printGroupsWithKeys(w, elsewhere)

	printSecretsStateHeader(w, glyphWarn, "Unreferenced here",
		fmt.Sprintf("%d %s · %d %s · may belong to another project", len(unref), pluralWord(len(unref), "group", "groups"), rec.UnreferencedSecrets, pluralWord(rec.UnreferencedSecrets, "secret", "secrets")))
	if len(unref) == 0 {
		_, _ = fmt.Fprintln(w, "  none")
		return
	}
	// Name the mirrored pairs once, above the listing, rather than tagging
	// every group row: rule 5 (state a shared fact once per section) and the
	// same instinct printOrphanGroups already applies to a shared origin.
	var mirrors []string
	for _, g := range unref {
		if g.DuplicateOf != "" {
			mirrors = append(mirrors, g.Name+" = "+g.DuplicateOf)
		}
	}
	if len(mirrors) > 0 {
		_, _ = fmt.Fprintf(w, "  %d mirror a group still in use, key for key (names, not values):\n", len(mirrors))
		flowNames(w, mirrors, "      ")
		fmt.Fprintln(w)
	}

	var paths []string
	for _, g := range unref {
		for _, m := range g.Members {
			paths = append(paths, m.Path)
		}
	}
	printOrphanGroups(w, v, paths)
	_, _ = fmt.Fprint(w, "  Inspect with ")
	_, _ = cPath.Fprint(w, "jit vault list")
	_, _ = fmt.Fprint(w, ", prune with ")
	_, _ = cPath.Fprint(w, "jit vault orphans --prune")
	fmt.Fprintln(w)
}

// printSecretsStateHeader renders one --secrets state block header: a blank
// line, a colored state glyph, the state name, and a plain one-line summary.
// This is the dashboard-family header — light, no [brackets], no rule —
// matching how the top status rollup names each state.
func printSecretsStateHeader(w io.Writer, glyph, name, summary string) {
	fmt.Fprintln(w)
	_, _ = cWarnOrOK(glyph).Fprintf(w, "%s ", glyph)
	fmt.Fprint(w, name)
	_, _ = fmt.Fprintf(w, "  %s\n", summary)
}

// cWarnOrOK picks the glyph's semantic color so the state reads at a glance:
// the warn glyph is amber, everything else (the healthy states) green.
func cWarnOrOK(glyph string) *color.Color {
	if glyph == glyphWarn {
		return cWarn
	}
	return cOK
}

// printGroupsWithKeys lists each group and its secret keys, the enriched
// successor to `jit profile list`'s flat rows. A mixed group (members in
// different states, e.g. after a re-migration split one) is flagged so the
// dominant-state bucketing above isn't silently lossy. Keys flow into
// aligned columns rather than one bullet per line: a 14-secret group is
// three tidy rows, not a fourteen-line stack (GAPS.md readability).
func printGroupsWithKeys(w io.Writer, groups []secretGroup) {
	if len(groups) == 0 {
		_, _ = fmt.Fprintln(w, "  none")
		return
	}
	for _, g := range groups {
		fmt.Fprintf(w, "  [%s]", g.Name)
		_, _ = fmt.Fprintf(w, " %d", len(g.Members))
		if g.Mixed {
			_, _ = cWarn.Fprint(w, "  mixed states")
		}
		fmt.Fprintln(w)
		keys := make([]string, len(g.Members))
		for i, m := range g.Members {
			keys[i] = m.Key
		}
		flowNames(w, keys, "      ")
	}
}

func init() {
	statusCmd.Flags().StringVar(&statusFormat, "format", "text", `output format: "text" (default) or "json"`)
	statusCmd.Flags().BoolVar(&statusSecretsDetail, "secrets", false, "expand the Secrets section into a full per-group reconciliation")
	rootCmd.AddCommand(statusCmd)
}
