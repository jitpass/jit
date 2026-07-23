// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
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
				Name:    g.Name,
				State:   stateSlug(g.State),
				Secrets: keys,
				Mixed:   g.Mixed,
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
func agentBuildMismatch(agentBuild string) string {
	cliBuild := agent.BuildID()
	if agentBuild == "" || agentBuild == "unknown" || cliBuild == "unknown" || agentBuild == cliBuild {
		return ""
	}
	return fmt.Sprintf("Heads up: the running service is a different build than this CLI (service %s, CLI %s), run `jit service restart` to move it to the current binary now (it also restarts itself once its session is locked and idle).", agentBuild, cliBuild)
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
		return statusAgent{}, err
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

func printStatusText(w io.Writer, r statusResult) {
	if r.Agent.Running {
		fmt.Fprintf(w, "Versions: jit %s; service %s.\n", versionBuild(r.CLI.Version, r.CLI.Build), versionBuild(r.Agent.Version, r.Agent.Build))
	} else {
		fmt.Fprintf(w, "Versions: jit %s; service not running.\n", versionBuild(r.CLI.Version, r.CLI.Build))
	}

	if r.Vault.SecretsStored == 0 && r.Vault.BackupsStored == 0 {
		fmt.Fprintln(w, "Vault: no secrets stored yet. Run `jit vault init` if you haven't set it up, or `jit migrate .` to populate it.")
	} else {
		if r.Vault.BackupsStored > 0 {
			fmt.Fprintf(w, "Vault: %d secret(s) stored, plus %d encrypted file backup(s) kept for `jit migrate undo`.\n", r.Vault.SecretsStored, r.Vault.BackupsStored)
		} else {
			fmt.Fprintf(w, "Vault: %d secret(s) stored.\n", r.Vault.SecretsStored)
		}
		switch {
		case !r.Vault.ExportRecorded:
			_, _ = color.New(color.FgYellow).Fprintln(w, "Backup: no vault export on record, the vault only decrypts on this Mac. Run `jit vault export <file>` so losing it isn't losing every secret.")
		case r.Vault.ExportStale:
			_, _ = color.New(color.FgYellow).Fprintf(w, "Backup: secrets have changed since the last vault export (%s). Run `jit vault export <file>` to refresh it.\n", time.Unix(r.Vault.ExportUnixTime, 0).Format("2006-01-02"))
		default:
			fmt.Fprintf(w, "Backup: vault export up to date (%s).\n", time.Unix(r.Vault.ExportUnixTime, 0).Format("2006-01-02"))
		}
	}

	switch {
	case !r.Agent.Running && r.Agent.Installed:
		// launchd was supposed to keep this one alive — "run install" is
		// the wrong advice and hides that something actually failed.
		fmt.Fprintln(w, installedNotRunningAdvice("Service:"))
	case !r.Agent.Running:
		fmt.Fprintln(w, "Service: not running. Run `jit service restart` to start it.")
	case r.Agent.Unlocked:
		fmt.Fprintf(w, "Service: running and unlocked (locks in %s).\n", (time.Duration(r.Agent.LocksInSeconds) * time.Second).String())
	default:
		fmt.Fprintln(w, "Service: running and locked.")
	}
	if warning := agentBuildMismatch(r.Agent.Build); warning != "" {
		_, _ = color.New(color.FgYellow).Fprintf(w, "  %s\n", warning)
	}

	printSecretsSection(w, r.Secrets)

	switch {
	case r.Mounts.Registered == 0:
		fmt.Fprintln(w, "Mounts: none registered.")
	case r.Mounts.ServingReal:
		granted := 0
		for _, m := range r.Agent.Mounts {
			if len(m.Grants) > 0 {
				granted++
			}
		}
		if granted > 0 {
			fmt.Fprintf(w, "Mounts: %d registered, service unlocked, %d currently serving real content to an active jit run grant, the rest decoy. Run `jit service status` to see which.\n", r.Mounts.Registered, granted)
		} else {
			fmt.Fprintf(w, "Mounts: %d registered, service unlocked, all serving decoy (real values flow only inside a jit run --live/--with grant).\n", r.Mounts.Registered)
		}
	case r.Mounts.BeingServed:
		fmt.Fprintf(w, "Mounts: %d registered, serving decoy content only (service locked).\n", r.Mounts.Registered)
	default:
		fmt.Fprintf(w, "Mounts: %d registered, not being served (service not running).\n", r.Mounts.Registered)
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
		_, _ = color.New(color.FgYellow).Fprintf(w, "  Heads up: %d mount(s) most recently served decoy values to a reader, run `jit service status` to see which reader, when.\n", decoyReads)
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
		fmt.Fprintln(w, "Secrets: none stored yet.")
		return
	}
	fmt.Fprintf(w, "Secrets: %d stored in %d group(s).\n", s.TotalSecrets, s.TotalGroups)

	switch {
	case s.WiredProfiles == 0:
		fmt.Fprintf(w, "  %-18s none (no project-local profile).\n", "Wired here:")
	case s.WiredProblems == 0:
		// "Resolve" here means the referenced secret EXISTS — the cheap glance,
		// existence-only. jit doctor additionally verifies each envelope reads,
		// so point there rather than imply an integrity check this didn't run.
		fmt.Fprintf(w, "  %-18s %d group(s) via %d profile(s) (%d reference(s)), all resolve.\n",
			"Wired here:", s.WiredGroups, s.WiredProfiles, s.WiredReferences)
	default:
		_, _ = color.New(color.FgRed).Fprintf(w, "  %-18s %d group(s) via %d profile(s) (%d reference(s)), %d broken — run `jit doctor` for details.\n",
			"Wired here:", s.WiredGroups, s.WiredProfiles, s.WiredReferences, s.WiredProblems)
	}

	fmt.Fprintf(w, "  %-18s %d group(s) (referenced only by global profiles or mounts).\n",
		"Managed elsewhere:", s.ManagedElsewhereGroups)

	if s.UnreferencedGroups == 0 {
		fmt.Fprintf(w, "  %-18s none.\n", "Unreferenced here:")
	} else {
		_, _ = color.New(color.FgYellow).Fprintf(w, "  %-18s %d group(s), %d secret(s). May belong to another project.\n",
			"Unreferenced here:", s.UnreferencedGroups, s.UnreferencedSecrets)
		fmt.Fprintf(w, "  %-18s Run `jit status --secrets` to inspect, `jit vault orphans` to prune.\n", "")
	}

	if s.ParseFailures > 0 {
		_, _ = color.New(color.FgYellow).Fprintf(w, "  Heads up: %d profile manifest(s) couldn't be read and were skipped; run `jit doctor` to see which.\n", s.ParseFailures)
	}
}

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

	fmt.Fprintf(w, "\nWired here (%d group(s), %d profile(s)):\n", len(wired), rec.WiredProfiles)
	printGroupsWithKeys(w, wired)

	fmt.Fprintf(w, "\nManaged elsewhere (%d group(s)):\n", len(elsewhere))
	printGroupsWithKeys(w, elsewhere)

	fmt.Fprintf(w, "\nUnreferenced here (%d group(s), %d secret(s)):\n", len(unref), rec.UnreferencedSecrets)
	if len(unref) == 0 {
		fmt.Fprintln(w, "  none.")
		return
	}
	var paths []string
	for _, g := range unref {
		for _, m := range g.Members {
			paths = append(paths, m.Path)
		}
	}
	printOrphanGroups(w, v, paths)
	fmt.Fprintln(w, "  Inspect with `jit vault list`, prune with `jit vault orphans --prune`.")
}

// printGroupsWithKeys lists each group and its secret keys, the enriched
// successor to `jit profile list`'s flat rows. A mixed group (members in
// different states, e.g. after a re-migration split one) is flagged so the
// dominant-state bucketing above isn't silently lossy.
func printGroupsWithKeys(w io.Writer, groups []secretGroup) {
	if len(groups) == 0 {
		fmt.Fprintln(w, "  none.")
		return
	}
	for _, g := range groups {
		mixed := ""
		if g.Mixed {
			mixed = "  [mixed states]"
		}
		fmt.Fprintf(w, "  %s/ (%d)%s\n", g.Name, len(g.Members), mixed)
		for _, m := range g.Members {
			fmt.Fprintf(w, "    • %s\n", m.Key)
		}
	}
}

func init() {
	statusCmd.Flags().StringVar(&statusFormat, "format", "text", `output format: "text" (default) or "json"`)
	statusCmd.Flags().BoolVar(&statusSecretsDetail, "secrets", false, "expand the Secrets section into a full per-group reconciliation")
	rootCmd.AddCommand(statusCmd)
}
