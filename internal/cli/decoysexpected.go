// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jitpass/jit/internal/agent"
)

// Expected decoy readers: programs the user says read protected files as
// a matter of course (an editor indexing a folder, a backup tool). Their
// decoy reads stay in the audit, tagged `expected`, so JitPass can count
// them apart and not raise an alarm for them. Nothing here changes what a
// mount serves: an expected program still gets decoys, and still needs a
// grant for a real value. A program's name decides nothing about access,
// only what is said about its reads.

var (
	decoysFormat string
	decoysFile   string
)

// expectedReader is one mark: a program, as the audit's `by` names its
// executable, and the one protected file it covers ("" = every one), in
// the audit's label form ("~/…/.env").
type expectedReader struct {
	Program   string `json:"program"`
	File      string `json:"file,omitempty"`
	SinceUnix int64  `json:"since_unix"`
}

type expectedReaders struct {
	Expected []expectedReader `json:"expected"`
}

func expectedReadersPath(root string) string {
	return filepath.Join(root, "decoys-expected.json")
}

func loadExpectedReaders(root string) (expectedReaders, error) {
	var list expectedReaders
	data, err := os.ReadFile(expectedReadersPath(root)) // #nosec G304 -- jit's own state file
	if errors.Is(err, os.ErrNotExist) {
		return expectedReaders{Expected: []expectedReader{}}, nil
	}
	if err != nil {
		return list, err
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return list, fmt.Errorf("%s: %w", expectedReadersPath(root), err)
	}
	if list.Expected == nil {
		list.Expected = []expectedReader{}
	}
	return list, nil
}

func saveExpectedReaders(root string, list expectedReaders) error {
	sort.Slice(list.Expected, func(i, j int) bool {
		a, b := list.Expected[i], list.Expected[j]
		return a.Program+"\x00"+a.File < b.Program+"\x00"+b.File
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	tmp := expectedReadersPath(root) + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, expectedReadersPath(root))
}

// readerMatches is whether a `by` command line is this program: the
// executable exactly, or followed by its arguments. A path may hold
// spaces ("/Applications/Some Editor.app/…"), so no splitting on them.
func readerMatches(by, program string) bool {
	return program != "" && (by == program || strings.HasPrefix(by, program+" "))
}

// labelForm is a path as a serve event's label names it: "~/…" under home.
func labelForm(path string) string {
	if strings.HasPrefix(path, "~/") {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(abs, home+"/") {
		return "~/" + strings.TrimPrefix(abs, home+"/")
	}
	return abs
}

// isExpected is whether a decoy read matches a mark.
func (l expectedReaders) isExpected(ev agent.SessionEvent) bool {
	if ev.Kind != "serve" || ev.Op == "real" {
		return false
	}
	for _, m := range l.Expected {
		if !readerMatches(ev.By, m.Program) {
			continue
		}
		if m.File == "" {
			return true
		}
		for _, label := range ev.Labels {
			if label == m.File {
				return true
			}
		}
	}
	return false
}

// tagExpected sets Expected on the decoy reads of expected readers, for
// `jit audit`'s output. A list that cannot be read tags nothing: the
// audit then says more, never less.
func tagExpected(root string, events []agent.SessionEvent) {
	list, err := loadExpectedReaders(root)
	if err != nil || len(list.Expected) == 0 {
		return
	}
	for i := range events {
		events[i].Expected = list.isExpected(events[i])
	}
}

func writeExpected(cmd *cobra.Command, list expectedReaders, verb string) error {
	if decoysFormat == "json" {
		return writeJSON(cmd.OutOrStdout(), list)
	}
	if verb != "" {
		fmt.Fprintln(cmd.OutOrStdout(), verb)
	}
	if len(list.Expected) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No expected decoy readers.")
		return nil
	}
	for _, m := range list.Expected {
		scope := "every protected file"
		if m.File != "" {
			scope = m.File
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s %s  %s\n", glyphBullet, m.Program, scope)
	}
	return nil
}

var decoysCmd = &cobra.Command{
	GroupID: groupWorkflow,
	Use:     "decoys",
	Short:   "Say which programs are expected to read protected files",
	Long: "A protected file serves decoys to any program without a grant, and every read is logged. " +
		"Some readers are routine, such as an editor indexing a folder or a backup tool. Marking one expected " +
		"tags its decoy reads `expected` in `jit audit`, so JitPass counts them apart and does not warn about " +
		"them. It still gets decoys and still needs a grant for a real value: this changes what is said, not " +
		"what is served.",
}

var decoysExpectCmd = &cobra.Command{
	Use:   "expect PROGRAM",
	Short: "Mark a program's decoy reads as expected",
	Long: "Mark PROGRAM's decoy reads as expected: of one protected file with --file, else of every one. " +
		"PROGRAM is the reader's executable as `jit audit` names it.",
	Example: "  jit decoys expect /Applications/Editor.app/Contents/MacOS/Editor --file ~/work/app/.env",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, list, err := openExpected()
		if err != nil {
			return fmt.Errorf("jit decoys expect: %w", err)
		}
		mark := expectedReader{Program: args[0], SinceUnix: time.Now().Unix()}
		if decoysFile != "" {
			mark.File = labelForm(decoysFile)
		}
		for _, m := range list.Expected {
			if m.Program == mark.Program && m.File == mark.File {
				return writeExpected(cmd, list, "")
			}
		}
		list.Expected = append(list.Expected, mark)
		if err := saveExpectedReaders(root, list); err != nil {
			return fmt.Errorf("jit decoys expect: %w", err)
		}
		return writeExpected(cmd, list, "Marked expected.")
	},
}

var decoysUnexpectCmd = &cobra.Command{
	Use:   "unexpect PROGRAM",
	Short: "Remove a program's expected mark",
	Long:  "Remove PROGRAM's expected mark: the one for --file, else every mark on PROGRAM.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root, list, err := openExpected()
		if err != nil {
			return fmt.Errorf("jit decoys unexpect: %w", err)
		}
		file := ""
		if decoysFile != "" {
			file = labelForm(decoysFile)
		}
		kept := list.Expected[:0]
		for _, m := range list.Expected {
			if m.Program == args[0] && (decoysFile == "" || m.File == file) {
				continue
			}
			kept = append(kept, m)
		}
		list.Expected = kept
		if err := saveExpectedReaders(root, list); err != nil {
			return fmt.Errorf("jit decoys unexpect: %w", err)
		}
		return writeExpected(cmd, list, "Removed.")
	},
}

var decoysExpectedCmd = &cobra.Command{
	Use:   "expected",
	Short: "List the programs whose decoy reads are expected",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, list, err := openExpected()
		if err != nil {
			return fmt.Errorf("jit decoys expected: %w", err)
		}
		return writeExpected(cmd, list, "")
	},
}

func openExpected() (string, expectedReaders, error) {
	if err := validateOutputFormat(decoysFormat); err != nil {
		return "", expectedReaders{}, err
	}
	root, err := vaultRootDir()
	if err != nil {
		return "", expectedReaders{}, err
	}
	list, err := loadExpectedReaders(root)
	return root, list, err
}

func init() {
	for _, c := range []*cobra.Command{decoysExpectCmd, decoysUnexpectCmd, decoysExpectedCmd} {
		c.Flags().StringVar(&decoysFormat, "format", "text", `output format: "text" (default) or "json"`)
		decoysCmd.AddCommand(c)
	}
	for _, c := range []*cobra.Command{decoysExpectCmd, decoysUnexpectCmd} {
		c.Flags().StringVar(&decoysFile, "file", "", "the protected file the mark covers (default: every protected file)")
	}
	rootCmd.AddCommand(decoysCmd)
}
