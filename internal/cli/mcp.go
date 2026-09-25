// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/mcp"
	"github.com/jitpass/jit/internal/vault"
)

// jit mcp — the MCP server that lets an AI app list and run AI jobs
// (design/agent-jobs.md, step 3). The protocol lives in internal/mcp; this
// file wires it to the service and manages the one entry an app's config
// needs. Install touches only that entry, after a backup, and says so.

var (
	mcpClientName  string
	mcpCommandPath string
	mcpStatusFmt   string
)

var mcpCmd = &cobra.Command{
	Use:     "mcp",
	GroupID: groupSecrets,
	Short:   "MCP server that lets AI apps run AI jobs (started by the app)",
	Long: `jit mcp is an MCP server over stdin and stdout. An AI app starts it on
this Mac (Claude Desktop does, from its config) and gets three tools:
list_jobs, run_job and request_job. It is how Claude Desktop's Cowork,
whose shell is a Linux VM that cannot run jit, runs your approved AI jobs.

It never holds a key. It asks the jit service to run a job by name and
relays the output, in which the service has already hidden every secret
value. A proposal from request_job creates nothing: it answers with the
'jit job allow' line for you to run.

You do not run this by hand. 'jit mcp install' adds it to Claude Desktop.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := mcpAgentClient()
		if err != nil {
			return fmt.Errorf("jit mcp: %w", err)
		}
		s := &mcp.Server{Backend: mcpBackend{c}, Version: agent.Version()}
		return s.Serve(cmd.InOrStdin(), cmd.OutOrStdout())
	},
}

var mcpInstallCmd = &cobra.Command{
	Use:   "install [--client claude-desktop]",
	Short: "Add jit's MCP server to Claude Desktop",
	Long: `Add one entry, "jit", to Claude Desktop's MCP servers, so Cowork can list
and run your AI jobs. The config file is backed up first, beside itself,
and nothing else in it changes. Claude Desktop reads it at start, so quit
and reopen it afterwards.

Connecting approves nothing. Claude can only run jobs you approved with
'jit job allow', and can only propose new ones for you to approve.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runMCPInstall(cmd.OutOrStdout(), true); err != nil {
			return fmt.Errorf("jit mcp install: %w", err)
		}
		return nil
	},
}

var mcpUninstallCmd = &cobra.Command{
	Use:   "uninstall [--client claude-desktop]",
	Short: "Remove jit's MCP server from Claude Desktop",
	Long:  "Remove the \"jit\" entry from Claude Desktop's MCP servers, after a backup. Your AI jobs stay; only this app's way in goes.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runMCPInstall(cmd.OutOrStdout(), false); err != nil {
			return fmt.Errorf("jit mcp uninstall: %w", err)
		}
		return nil
	},
}

var mcpStatusCmd = &cobra.Command{
	Use:   "status [--client claude-desktop]",
	Short: "Show whether Claude Desktop can reach jit's MCP server",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runMCPStatus(cmd.OutOrStdout()); err != nil {
			return fmt.Errorf("jit mcp status: %w", err)
		}
		return nil
	},
}

func init() {
	for _, c := range []*cobra.Command{mcpInstallCmd, mcpUninstallCmd, mcpStatusCmd} {
		c.Flags().StringVar(&mcpClientName, "client", "claude-desktop", "the AI app: claude-desktop")
	}
	mcpInstallCmd.Flags().StringVar(&mcpCommandPath, "command", "", "the jit to start (default: the jit on your PATH)")
	mcpStatusCmd.Flags().StringVar(&mcpStatusFmt, "format", "text", "output format: text or json")
	mcpCmd.AddCommand(mcpInstallCmd, mcpUninstallCmd, mcpStatusCmd)
	rootCmd.AddCommand(mcpCmd)
}

// mcpAgentClient is agentClient without the Touch ID notice: stdout is the
// protocol here, and stderr goes to the app's log where nobody reads it. It
// keeps the full wait, because an each-time job legitimately waits on a
// human, and it heals a dead service like every client that needs one.
func mcpAgentClient() (*agent.Client, error) {
	root, err := vaultRootDir()
	if err != nil {
		return nil, err
	}
	c := agent.NewClient(agent.SocketPath(root))
	if agentInstalled() {
		c = c.WithDialRetry(agentRestartGrace).WithDialFailedHook(healDeadService)
	}
	return c, nil
}

type mcpBackend struct{ c *agent.Client }

func (b mcpBackend) ListJobs() ([]agent.JobStatus, error)        { return b.c.JobList() }
func (b mcpBackend) RunJob(name string) (agent.JobResult, error) { return b.c.JobRun(name) }

// mcpServerName is the entry's key in an app's mcpServers.
const mcpServerName = "jit"

// mcpConfigPath is where the named app keeps its MCP servers. Only Claude
// Desktop is automated; others are documented until each is checked to start
// stdio servers on the host rather than inside its own sandbox.
func mcpConfigPath(client string) (string, error) {
	if client != "claude-desktop" {
		return "", fmt.Errorf("--client %s is not supported yet: only claude-desktop is set up automatically. For another app, add an MCP server that runs `jit mcp`", client)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
}

// mcpCommand is the jit the app should start: the one on PATH (the cask's
// /opt/homebrew/bin/jit link), not this binary's own path, so an app update
// that moves the binary inside JitPass.app does not break the entry.
func mcpCommand() (string, error) {
	if mcpCommandPath != "" {
		if !filepath.IsAbs(mcpCommandPath) {
			return "", fmt.Errorf("--command must be an absolute path")
		}
		return mcpCommandPath, nil
	}
	if p, err := exec.LookPath("jit"); err == nil {
		if abs, aerr := filepath.Abs(p); aerr == nil {
			return abs, nil
		}
	}
	return os.Executable()
}

type mcpServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// setMCPEntry adds (entry non-nil) or removes the jit entry in the config at
// path, keeping every other key's bytes as they were. It returns whether the
// file changed and where the backup went. A file that is not JSON is refused
// and left alone: it is the user's, and a parse failure is not permission to
// rewrite it.
func setMCPEntry(path string, entry *mcpServerEntry, now time.Time) (changed bool, backup string, err error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the AI app's own config file, a fixed path under the user's home
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return false, "", err
	}
	top := map[string]json.RawMessage{}
	if !missing && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &top); err != nil {
			return false, "", fmt.Errorf("%s is not valid JSON, so it was left as it is (%v)", path, err)
		}
	}
	servers := map[string]json.RawMessage{}
	if s, ok := top["mcpServers"]; ok {
		if err := json.Unmarshal(s, &servers); err != nil {
			return false, "", fmt.Errorf("%s: mcpServers is not an object, so the file was left as it is", path)
		}
	}
	current, has := servers[mcpServerName]
	if entry == nil {
		if !has {
			return false, "", nil
		}
		delete(servers, mcpServerName)
	} else {
		want, _ := json.Marshal(entry)
		if has && jsonEqual(current, want) {
			return false, "", nil
		}
		servers[mcpServerName] = want
	}
	if len(servers) == 0 {
		delete(top, "mcpServers")
	} else {
		s, _ := json.Marshal(servers)
		top["mcpServers"] = s
	}
	out, err := json.MarshalIndent(top, "", "  ")
	if err != nil {
		return false, "", err
	}
	if !missing {
		backup = fmt.Sprintf("%s.jit-backup-%s", path, now.Format("20060102-150405"))
		if err := os.WriteFile(backup, raw, 0o600); err != nil { // #nosec G703 -- beside the AI app's own config file, a fixed path under the user's home, not external input
			return false, "", fmt.Errorf("backing up %s: %w", path, err)
		}
	}
	if err := vault.AtomicWriteFile(path, append(out, '\n')); err != nil {
		return false, backup, err
	}
	return true, backup, nil
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}

func runMCPInstall(out io.Writer, install bool) error {
	path, err := mcpConfigPath(mcpClientName)
	if err != nil {
		return err
	}
	var entry *mcpServerEntry
	if install {
		cmdPath, err := mcpCommand()
		if err != nil {
			return err
		}
		entry = &mcpServerEntry{Command: cmdPath, Args: []string{"mcp"}}
	}
	changed, backup, err := setMCPEntry(path, entry, time.Now())
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	switch {
	case !changed && install:
		_, _ = cOK.Fprint(out, glyphOK)
		fmt.Fprintln(out, " Claude Desktop already starts jit's MCP server")
		return nil
	case !changed:
		_, _ = cOK.Fprint(out, glyphOK)
		fmt.Fprintln(out, " Claude Desktop does not start jit's MCP server")
		return nil
	}
	_, _ = cOK.Fprint(out, glyphDone)
	if install {
		fmt.Fprintf(out, " Claude Desktop will start %s mcp\n", entry.Command)
	} else {
		fmt.Fprintln(out, " Removed jit from Claude Desktop's MCP servers")
	}
	fmt.Fprintf(out, "  changed  %s\n", displayPath(home, path))
	if backup != "" {
		fmt.Fprintf(out, "  backup   %s\n", displayPath(home, backup))
	}
	fmt.Fprintln(out, "  Quit and reopen Claude Desktop to pick this up.")
	return nil
}

type mcpStatusJSON struct {
	Client    string `json:"client"`
	Config    string `json:"config"`
	Installed bool   `json:"installed"`
	Command   string `json:"command,omitempty"`
	// Runnable says the command exists and is executable; an entry pointing
	// at a jit that was since removed would fail at the app's next start.
	Runnable bool `json:"runnable"`
}

func runMCPStatus(out io.Writer) error {
	if err := validateOutputFormat(mcpStatusFmt); err != nil {
		return err
	}
	path, err := mcpConfigPath(mcpClientName)
	if err != nil {
		return err
	}
	st := mcpStatusJSON{Client: mcpClientName, Config: path}
	if raw, rerr := os.ReadFile(path); rerr == nil { // #nosec G304 -- the AI app's own config file
		var cfg struct {
			MCPServers map[string]mcpServerEntry `json:"mcpServers"`
		}
		if json.Unmarshal(raw, &cfg) == nil {
			if e, ok := cfg.MCPServers[mcpServerName]; ok {
				st.Installed, st.Command = true, e.Command
				if info, ierr := os.Stat(e.Command); ierr == nil && info.Mode()&0o111 != 0 {
					st.Runnable = true
				}
			}
		}
	}
	if mcpStatusFmt == "json" {
		return writeJSON(out, st)
	}
	switch {
	case st.Installed && st.Runnable:
		_, _ = cOK.Fprint(out, glyphOK)
		fmt.Fprintf(out, " Claude Desktop starts %s mcp\n", st.Command)
	case st.Installed:
		_, _ = cRisk.Fprint(out, glyphRisk)
		fmt.Fprintf(out, " Claude Desktop starts %s, which is not there\n", st.Command)
		fmt.Fprint(out, "  ")
		_, _ = cPath.Fprintf(out, "%s jit mcp install", glyphAction)
		fmt.Fprintln(out, "   points it at the jit on your PATH")
	default:
		_, _ = cWarn.Fprint(out, glyphWarn)
		fmt.Fprintln(out, " Claude Desktop does not start jit's MCP server")
		fmt.Fprint(out, "  ")
		_, _ = cPath.Fprintf(out, "%s jit mcp install", glyphAction)
		fmt.Fprintln(out, "   lets Cowork run your AI jobs")
	}
	return nil
}
