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
	"strings"
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
this Mac (Claude Desktop and Cursor do, from their config) and gets three
tools: list_jobs, run_job and request_job. It is how Claude Desktop's Cowork,
whose shell is a Linux VM that cannot run jit, runs your approved AI jobs.

It never holds a key. It asks the jit service to run a job by name and
relays the output, in which the service has already hidden every secret
value. A proposal from request_job creates nothing: it answers with the
'jit job allow' line for you to run.

You do not run this by hand. 'jit mcp install' adds it to Claude Desktop,
and 'jit mcp install --client cursor' to Cursor.`,
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
	Use:   "install [--client claude-desktop|cursor]",
	Short: "Add jit's MCP server to Claude Desktop or Cursor",
	Long: `Add one entry, "jit", to the app's MCP servers, so its agent can list
and run your AI jobs: Claude Desktop (the default) or Cursor. The config
file is backed up first, beside itself, and nothing else in it changes.
The app reads it at start, so quit and reopen it afterwards.

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
	Use:   "uninstall [--client claude-desktop|cursor]",
	Short: "Remove jit's MCP server from Claude Desktop or Cursor",
	Long:  "Remove the \"jit\" entry from the app's MCP servers, after a backup. Your AI jobs stay; only this app's way in goes.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runMCPInstall(cmd.OutOrStdout(), false); err != nil {
			return fmt.Errorf("jit mcp uninstall: %w", err)
		}
		return nil
	},
}

var mcpStatusCmd = &cobra.Command{
	Use:   "status [--client claude-desktop|cursor]",
	Short: "Show whether an AI app can reach jit's MCP server",
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
		c.Flags().StringVar(&mcpClientName, "client", "claude-desktop", "the AI app: claude-desktop or cursor")
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
func (b mcpBackend) RequestJob(name string, spec agent.JobSpec, why string) error {
	_, err := b.c.JobRequest(name, spec, why)
	return err
}

// mcpServerName is the entry's key in an app's mcpServers.
const mcpServerName = "jit"

// mcpClient is an AI app `jit mcp install` sets up: where it keeps its MCP
// servers, and what connecting it lets its agent do. An app is added here
// only once it is checked to start stdio MCP servers on this Mac rather than
// inside a sandbox of its own (the condition design/agent-jobs.md sets).
// Both files share the `mcpServers` shape setMCPEntry edits.
type mcpClient struct {
	id, name string
	// config is relative to the home folder.
	config string
	// gain is what connecting gives, for the status line.
	gain string
}

var mcpClients = []mcpClient{
	{"claude-desktop", "Claude Desktop", "Library/Application Support/Claude/claude_desktop_config.json", "lets Cowork run your AI jobs"},
	{"cursor", "Cursor", ".cursor/mcp.json", "lets Cursor's agent run your AI jobs"},
}

func findMCPClient(id string) (mcpClient, string, error) {
	for _, c := range mcpClients {
		if c.id != id {
			continue
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return mcpClient{}, "", err
		}
		return c, filepath.Join(home, filepath.FromSlash(c.config)), nil
	}
	ids := make([]string, 0, len(mcpClients))
	for _, c := range mcpClients {
		ids = append(ids, c.id)
	}
	return mcpClient{}, "", fmt.Errorf("--client %s is not set up automatically (%s are). For another app, add an MCP server that runs `jit mcp`", id, strings.Join(ids, ", "))
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
	client, path, err := findMCPClient(mcpClientName)
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
		fmt.Fprintf(out, " %s already starts jit's MCP server\n", client.name)
		return nil
	case !changed:
		_, _ = cOK.Fprint(out, glyphOK)
		fmt.Fprintf(out, " %s does not start jit's MCP server\n", client.name)
		return nil
	}
	_, _ = cOK.Fprint(out, glyphDone)
	if install {
		fmt.Fprintf(out, " %s will start %s mcp\n", client.name, entry.Command)
	} else {
		fmt.Fprintf(out, " Removed jit from %s's MCP servers\n", client.name)
	}
	fmt.Fprintf(out, "  changed  %s\n", displayPath(home, path))
	if backup != "" {
		fmt.Fprintf(out, "  backup   %s\n", displayPath(home, backup))
	}
	fmt.Fprintf(out, "  Quit and reopen %s to pick this up.\n", client.name)
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
	client, path, err := findMCPClient(mcpClientName)
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
		fmt.Fprintf(out, " %s starts %s mcp\n", client.name, st.Command)
	case st.Installed:
		_, _ = cRisk.Fprint(out, glyphRisk)
		fmt.Fprintf(out, " %s starts %s, which is not there\n", client.name, st.Command)
		fmt.Fprint(out, "  ")
		_, _ = cPath.Fprintf(out, "%s %s", glyphAction, mcpInstallLine(client))
		fmt.Fprintln(out, "   points it at the jit on your PATH")
	default:
		_, _ = cWarn.Fprint(out, glyphWarn)
		fmt.Fprintf(out, " %s does not start jit's MCP server\n", client.name)
		fmt.Fprint(out, "  ")
		_, _ = cPath.Fprintf(out, "%s %s", glyphAction, mcpInstallLine(client))
		fmt.Fprintf(out, "   %s\n", client.gain)
	}
	return nil
}

// mcpInstallLine is the command that connects client, spelled the way the
// user would type it: no flag for the default.
func mcpInstallLine(c mcpClient) string {
	if c.id == mcpClients[0].id {
		return "jit mcp install"
	}
	return "jit mcp install --client " + c.id
}
