// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/job"
	"github.com/jitpass/jit/internal/profile"
)

// jit job — AI Jobs (design/agent-jobs.md). A job is a command you approved,
// with the secrets it gets; an AI tool runs it by name, the service runs it,
// and the tool gets the output with every secret value hidden. It never holds
// a key. `allow` takes a Touch ID; `remove` never does; `run` asks each time.
// The CLI is a thin client: the service resolves, fingerprints and decides.

var (
	jobProfile     string
	jobShown       []string
	jobOutputs     []string
	jobReplace     bool
	jobDescription string
	jobAsk         string
	jobDryRun      bool
	jobListFormat  string
	jobRunFormat   string
)

var jobCmd = &cobra.Command{
	Use:     "job",
	GroupID: groupSecrets,
	Short:   "Let AI tools run approved scripts without seeing their keys",
	Long: `An AI job is a command you approve once, with the secrets it needs.
An AI tool (Claude Code, Codex, Claude Desktop) runs it by name. The jit
service runs it on this Mac and hands back the output with every secret
value hidden, so the tool never holds a key.

Two things keep an approval meaning what you approved. jit fingerprints
the job's folder, so a script, a library or a profile edited afterwards
stops the job until you approve it again. And the secrets are fixed at
approval: editing the profile later never changes what the job gets.`,
	Example: `  cd ~/Security-Ops/custom_scripts/notion
  jit job allow notion-guests -- .venv/bin/python list_guest_users.py
  jit job run notion-guests
  jit job list
  jit job remove notion-guests`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var jobAllowCmd = &cobra.Command{
	Use:   "allow NAME [--profile NAME] [--show VAR] [--output DIR] -- COMMAND [ARGS...]",
	Short: "Approve a command as an AI job (asks for Touch ID)",
	Long: `Approve COMMAND, run in this folder, as the AI job NAME. jit shows the
whole job, then asks for Touch ID. Nothing runs now.

--profile names the profile whose secrets the job gets. With one profile
in this folder's .jit/profiles it is picked for you. Every value is hidden
in the output unless you name it with --show: use that for configuration
that appears in what the script prints, never for a key.

--output names a folder the job writes into. New files there are reported
to the tool by path, and changes there never stop the job.

Some commands are refused because they hand the values straight back:
env, cat, echo, or a program written into the command (python -c,
sh -c, node -e). Save it as a file and approve that file.`,
	Example: `  jit job allow notion-guests --show INTERNAL_DOMAINS \
    --output ~/Security-Ops/reports_and_archives/csv_reports \
    -- .venv/bin/python list_guest_users.py`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("jit job allow: give a name and the command, e.g. jit job allow notion-guests -- .venv/bin/python list_guest_users.py")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runJobAllow(cmd.OutOrStdout(), args[0], args[1:]); err != nil {
			return fmt.Errorf("jit job allow: %w", err)
		}
		return nil
	},
}

var jobListCmd = &cobra.Command{
	Use:   "list",
	Short: "Show the approved AI jobs and whether each can run",
	Long: `List every AI job: what it runs, whether it can run now, and who ran it
last. A job whose files changed, or whose secret was rotated, is marked
and cannot run until you approve it again. Reading this never prompts.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runJobList(cmd.OutOrStdout()); err != nil {
			return fmt.Errorf("jit job list: %w", err)
		}
		return nil
	},
}

var jobRemoveCmd = &cobra.Command{
	Use:               "remove NAME",
	Short:             "Remove an AI job now",
	Long:              "Remove an AI job. No Touch ID: reducing access is always free. The removal is recorded in 'jit audit'.",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeJobNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runJobRemove(cmd.OutOrStdout(), args[0]); err != nil {
			return fmt.Errorf("jit job remove: %w", err)
		}
		return nil
	},
}

var jobRunCmd = &cobra.Command{
	Use:   "run NAME",
	Short: "Run an AI job and print its output, secret values hidden",
	Long: `Ask the service to run an AI job. Its output is printed here with every
secret value replaced by [hidden: NAME], and jit exits with the job's own
exit code. A job approved to ask each time asks for Touch ID, naming who
asked.

This is how an AI tool in a terminal (Claude Code, Codex, Gemini CLI) runs
a job. It needs no MCP server: the tool already reaches the service.`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeJobNames,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runJobRun(cmd.OutOrStdout(), cmd.ErrOrStderr(), args[0])
	},
}

func init() {
	jobAllowCmd.Flags().StringVar(&jobProfile, "profile", "", "profile whose secrets the job gets")
	jobAllowCmd.Flags().StringArrayVar(&jobShown, "show", nil, "a variable whose value may appear in the output (repeatable)")
	jobAllowCmd.Flags().StringArrayVar(&jobOutputs, "output", nil, "a folder the job writes into (repeatable)")
	jobAllowCmd.Flags().BoolVar(&jobReplace, "replace", false, "approve over an existing job of the same name")
	jobAllowCmd.Flags().StringVar(&jobDescription, "description", "", "one line an AI tool sees in the job list")
	jobAllowCmd.Flags().BoolVar(&jobDryRun, "dry-run", false, "check the job and show what approving it would do, without asking or keeping anything")
	jobAllowCmd.Flags().StringVar(&jobAsk, "ask", string(job.AskEachTime), "each-time (Touch ID per run) or never (runs unasked until you remove it)")
	jobListCmd.Flags().StringVar(&jobListFormat, "format", "text", "output format: text or json")
	jobRunCmd.Flags().StringVar(&jobRunFormat, "format", "text", "output format: text or json")
	jobCmd.AddCommand(jobAllowCmd, jobListCmd, jobRemoveCmd, jobRunCmd)
	rootCmd.AddCommand(jobCmd)
}

// jobAgentErr strips the RPC framing from a service error, grantAgentErr's
// treatment.
func jobAgentErr(op string, err error) error {
	return grantAgentErr(op, err)
}

// defaultJobProfile picks the folder's only profile, so the common case
// (one script folder, one profile) needs no flag.
func defaultJobProfile(dir string) (string, error) {
	matches, _ := filepath.Glob(filepath.Join(dir, profile.ProfilesDir, "*.yaml"))
	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return strings.TrimSuffix(filepath.Base(matches[0]), ".yaml"), nil
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(filepath.Base(m), ".yaml"))
	}
	return "", fmt.Errorf("this folder has %d profiles (%s): name one with --profile", len(names), strings.Join(names, ", "))
}

func runJobAllow(out io.Writer, name string, argv []string) error {
	if err := job.ValidateName(name); err != nil {
		return err
	}
	if !job.Ask(jobAsk).Valid() {
		return fmt.Errorf("--ask takes %s or %s", job.AskEachTime, job.AskNever)
	}
	// Refuse here too, before the RPC, so the sentence reaches the terminal
	// without a round trip; the service checks again and is what counts.
	if err := job.CheckArgv(argv); err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	prof := jobProfile
	if prof == "" {
		if prof, err = defaultJobProfile(cwd); err != nil {
			return err
		}
	}
	var vars []string
	if prof != "" {
		p, err := profile.Load(cwd, prof)
		if err != nil {
			return err
		}
		for v := range p {
			vars = append(vars, v)
		}
		sort.Strings(vars)
	}
	home, _ := os.UserHomeDir()
	spec := agent.JobSpec{
		Dir: cwd, Argv: argv, Ask: jobAsk, Shown: jobShown, Outputs: jobOutputs,
		PathEnv: os.Getenv("PATH"), Home: home, Description: jobDescription, Replace: jobReplace,
	}
	if prof != "" {
		spec.Profile = &agent.GrantProfile{Name: prof, Root: cwd}
	}

	// The whole job, before the prompt: the Touch ID dialog only has room
	// for a name and a count, and this is what the human is approving.
	fmt.Fprintf(out, "[AI job] %s\n", name)
	fmt.Fprintf(out, "  runs     %s\n", strings.Join(argv, " "))
	fmt.Fprintf(out, "  in       %s\n", displayPath(home, cwd))
	fmt.Fprintf(out, "  secrets  %s\n", jobSecretsLine(prof, vars, jobShown))
	for _, o := range jobOutputs {
		fmt.Fprintf(out, "  output   %s\n", displayPath(home, o))
	}
	if job.Ask(jobAsk) == job.AskNever {
		fmt.Fprintln(out, "  asks     never, until you remove it: runs while you are away")
	} else {
		fmt.Fprintln(out, "  asks     each time, naming who asked")
	}
	fmt.Fprintln(out)

	ac, err := agentClient()
	if err != nil {
		return err
	}
	if jobDryRun {
		return printJobPreview(out, ac, name, spec, home)
	}
	st, err := ac.JobAllow(name, spec)
	if err != nil {
		return jobAgentErr("job_allow", err)
	}
	_, _ = cOK.Fprint(out, glyphDone)
	fmt.Fprintf(out, " Approved %s · %s fingerprinted\n", st.Name, countWord(st.Files, "file", "files"))
	fmt.Fprint(out, "  ")
	_, _ = cPath.Fprintf(out, "%s jit job run %s", glyphAction, st.Name)
	fmt.Fprintln(out, "   how an AI tool runs it")
	return nil
}

// jobSecretsLine is "NOTION_API_KEY hidden · INTERNAL_DOMAINS shown", from
// the profile's variables and the --show list.
func jobSecretsLine(prof string, vars, shown []string) string {
	if prof == "" {
		return "none"
	}
	var hid, show []string
	for _, v := range vars {
		if containsStr(shown, v) {
			show = append(show, v)
		} else {
			hid = append(hid, v)
		}
	}
	parts := []string{"from " + prof}
	if len(hid) > 0 {
		parts = append(parts, strings.Join(hid, ", ")+" hidden")
	}
	if len(show) > 0 {
		parts = append(parts, strings.Join(show, ", ")+" shown")
	}
	return strings.Join(parts, " · ")
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func runJobList(out io.Writer) error {
	if err := validateOutputFormat(jobListFormat); err != nil {
		return err
	}
	ac, err := agentClient()
	if err != nil {
		return err
	}
	jobs, err := ac.JobList()
	if err != nil {
		return jobAgentErr("job_list", err)
	}
	if jobListFormat == "json" {
		if jobs == nil {
			jobs = []agent.JobStatus{}
		}
		return writeJSON(out, jobs)
	}
	renderJobRows(out, jobs, time.Now())
	return nil
}

// renderJobRows is `jit job list`: a report, state in the glyph (ready ●,
// stopped ○), the name bold because it is what run and remove take.
func renderJobRows(out io.Writer, jobs []agent.JobStatus, now time.Time) {
	fmt.Fprintf(out, "[AI jobs] %d\n", len(jobs))
	if len(jobs) == 0 {
		fmt.Fprintln(out, "  no AI jobs yet")
		fmt.Fprint(out, "  ")
		_, _ = cPath.Fprintf(out, "%s jit job allow NAME -- COMMAND", glyphAction)
		fmt.Fprintln(out, "   approve one, from its folder")
		return
	}
	widest := 0
	for _, j := range jobs {
		if n := len([]rune(j.Name)); n > widest {
			widest = n
		}
	}
	for _, j := range jobs {
		glyph, ink := glyphOK, cOK
		state := jobReadyLine(j, now)
		switch j.State {
		case agent.JobChanged:
			glyph, ink = glyphWarn, cWarn
			state = "stopped · " + jobChangeLine(j.Changes)
			if len(j.Changes) == 0 && j.LastRefusal != "" {
				// Stopped earlier; the folder may match again now, and the
				// stop still stands until the job is approved again.
				state = "stopped · " + truncateRunes(j.LastRefusal, 60)
			}
		case agent.JobRotated:
			glyph, ink = glyphWarn, cWarn
			state = "stopped · a secret was rotated"
		}
		fmt.Fprint(out, "  ")
		_, _ = ink.Fprint(out, glyph)
		fmt.Fprint(out, " ")
		_, _ = cBold.Fprint(out, j.Name)
		fmt.Fprintf(out, "%s  %s\n", strings.Repeat(" ", widest-len([]rune(j.Name))), state)
		fmt.Fprintf(out, "    %s %s\n", glyphBranch, truncateRunes(strings.Join(j.Argv, " "), 64))
	}
	for _, j := range jobs {
		if j.State == agent.JobChanged || j.State == agent.JobRotated {
			fmt.Fprintln(out)
			fmt.Fprint(out, "  ")
			_, _ = cPath.Fprintf(out, "%s %s", glyphAction, reapproveCommand(j))
			fmt.Fprintln(out)
			fmt.Fprintln(out, "    once you have looked at the change")
			break
		}
	}
}

// reapproveCommand is the exact line that approves j again with every
// setting it has now. Leaving the flags off would re-approve a different
// job: a shown value would go back to hidden and the output folder would
// start stopping the job.
func reapproveCommand(j agent.JobStatus) string {
	parts := []string{"cd", quoteIfNeeded(j.Dir), "&&", "jit", "job", "allow", j.Name, "--replace"}
	if j.Ask == string(job.AskNever) {
		parts = append(parts, "--ask", string(job.AskNever))
	}
	if j.Profile != "" {
		parts = append(parts, "--profile", quoteIfNeeded(j.Profile))
	}
	for _, sec := range j.Secrets {
		if sec.Shown {
			parts = append(parts, "--show", sec.Var)
		}
	}
	for _, o := range j.Outputs {
		parts = append(parts, "--output", quoteIfNeeded(o))
	}
	if j.Description != "" {
		parts = append(parts, "--description", quoteIfNeeded(j.Description))
	}
	parts = append(parts, "--")
	for _, a := range j.Argv {
		parts = append(parts, quoteIfNeeded(a))
	}
	return strings.Join(parts, " ")
}

// quoteIfNeeded leaves a plain word bare and single-quotes anything a shell
// would split or expand (shellQuote, export.go), so the printed line reads
// cleanly and still pastes back as the same argv.
func quoteIfNeeded(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:@%+,", r))
	}) < 0 {
		return s
	}
	return shellQuote(s)
}

func jobReadyLine(j agent.JobStatus, now time.Time) string {
	ready := "ready"
	if j.Ask == string(job.AskNever) {
		ready = "ready, runs unasked"
	}
	if j.LastRunUnix == 0 {
		return ready + " · not run yet"
	}
	s := fmt.Sprintf("%s · %s ran it %s", ready, j.LastCaller, agoPhrase(now.Sub(time.Unix(j.LastRunUnix, 0))))
	if j.LastExit != 0 {
		s += fmt.Sprintf(", exit %d", j.LastExit)
	}
	if j.LastHidden > 0 {
		s += fmt.Sprintf(" · hid %s", countWord(j.LastHidden, "value", "values"))
	}
	return s
}

func jobChangeLine(changes []job.Change) string {
	if len(changes) == 0 {
		return "files changed"
	}
	s := fmt.Sprintf("%s %s", changes[0].Path, changes[0].Kind)
	if len(changes) > 1 {
		s += fmt.Sprintf(" (+%d more)", len(changes)-1)
	}
	return s
}

func agoPhrase(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return countWord(int(d/time.Minute), "minute", "minutes") + " ago"
	case d < 24*time.Hour:
		return countWord(int(d/time.Hour), "hour", "hours") + " ago"
	}
	return countWord(int(d/(24*time.Hour)), "day", "days") + " ago"
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func runJobRemove(out io.Writer, name string) error {
	ac, err := agentClient()
	if err != nil {
		return err
	}
	if err := ac.JobRemove(name); err != nil {
		return jobAgentErr("job_remove", err)
	}
	_, _ = cOK.Fprint(out, glyphDone)
	fmt.Fprintf(out, " Removed %s. AI tools can no longer run it.\n", name)
	return nil
}

// runJobRun prints the job's own output as it came back, stdout to stdout
// and stderr to stderr, then jit's notes on stderr, and exits with the job's
// code, so a calling agent reads it exactly as if it had run the script.
func runJobRun(stdout, stderr io.Writer, name string) error {
	if err := validateOutputFormat(jobRunFormat); err != nil {
		return fmt.Errorf("jit job run: %w", err)
	}
	ac, err := agentClient()
	if err != nil {
		return fmt.Errorf("jit job run: %w", err)
	}
	res, err := ac.JobRun(name)
	if err != nil {
		return fmt.Errorf("jit job run: %w", jobAgentErr("job_run", err))
	}
	if jobRunFormat == "json" {
		if err := writeJSON(stdout, res); err != nil {
			return err
		}
	} else {
		fmt.Fprint(stdout, res.Stdout)
		fmt.Fprint(stderr, res.Stderr)
		for _, f := range res.NewFiles {
			fmt.Fprintf(stderr, "[jit] new file: %s\n", f)
		}
		for _, n := range res.Notes {
			fmt.Fprintf(stderr, "[jit] %s\n", n)
		}
		fmt.Fprintf(stderr, "[jit] %s\n", hiddenSummary(res.Hidden))
	}
	if res.Exit != 0 {
		return &ExitError{Code: jobExitCode(res), Msg: fmt.Sprintf("[jit] %s exited %d", name, res.Exit)}
	}
	return nil
}

func jobExitCode(res agent.JobResult) int {
	if res.Exit < 0 || res.Exit > 255 {
		return 1
	}
	return res.Exit
}

func hiddenSummary(hidden map[string]int) string {
	if len(hidden) == 0 {
		return "hidden values: none"
	}
	names := make([]string, 0, len(hidden))
	for k := range hidden {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, k := range names {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, hidden[k]))
	}
	return "hidden values: " + strings.Join(parts, ", ")
}

func completeJobNames(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	ac, err := agentClientNoHeal()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	jobs, err := ac.JobNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var out []string
	for _, j := range jobs {
		if strings.HasPrefix(j.Name, toComplete) {
			out = append(out, j.Name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// printJobPreview is `jit job allow --dry-run`: the service's own checks,
// run exactly as approval runs them, with nothing asked and nothing kept.
// It is the terminal's side of what the app's New AI Job sheet shows.
func printJobPreview(out io.Writer, ac *agent.Client, name string, spec agent.JobSpec, home string) error {
	p, err := ac.JobPreview(name, spec)
	if err != nil {
		return jobAgentErr("job_preview", err)
	}
	if p.Refusal != "" {
		return fmt.Errorf("%s", strings.TrimPrefix(p.Refusal, "job_allow: "))
	}
	_, _ = cOK.Fprint(out, glyphOK)
	fmt.Fprintf(out, " Would approve %s · %s fingerprinted\n", name, countWord(p.Files, "file", "files"))
	fmt.Fprintf(out, "  program  %s\n", displayPath(home, p.Exe))
	for _, e := range p.Extra {
		fmt.Fprintf(out, "  outside  %s\n", displayPath(home, e))
	}
	if p.Exists {
		fmt.Fprintf(out, "  replaces the job already named %s\n", name)
	}
	fmt.Fprintf(out, "  Touch ID will say: jit is trying to %s.\n", p.Prompt)
	fmt.Fprintln(out, "  Nothing was asked and nothing was kept.")
	return nil
}
