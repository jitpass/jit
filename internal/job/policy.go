// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"fmt"
	"path/filepath"
	"strings"
)

// printers hand their input or environment straight back. As a job's program
// they would print the values the job exists to keep from the caller.
var printers = map[string]bool{
	"env": true, "printenv": true, "cat": true, "echo": true, "printf": true,
	"tee": true, "head": true, "tail": true, "less": true, "more": true,
	"strings": true, "xxd": true, "od": true, "hexdump": true, "base64": true,
	"set": true, "export": true, "declare": true,
}

// inlineFlags are, per interpreter family, the flags that take a program as
// an argument instead of from a file. A program written into the command is
// never fingerprinted, and it is the shortest route to printing a secret.
// Short flags are single letters so a cluster (`bash -lc`, `python -Bc`) is
// caught as well.
//
// takes lists the short flags whose value is the NEXT argument, so the scan
// steps over it rather than mistaking it for the script and stopping early:
// `python -X dev -c …` must still be read as far as the -c.
var inlineFlags = map[string]struct {
	short string
	long  []string
	takes string
}{
	"python":    {short: "c", takes: "WXQ"},
	"sh":        {short: "c", takes: "oO"},
	"node":      {short: "ep", long: []string{"--eval", "--print"}, takes: "r"},
	"deno":      {short: "e", long: []string{"--eval"}}, // plus `deno eval`, below
	"bun":       {short: "e", long: []string{"--eval", "--print"}},
	"ruby":      {short: "e"},
	"perl":      {short: "eE"},
	"php":       {short: "r"},
	"osascript": {short: "e"},
	"lua":       {short: "e"},
	"pwsh":      {short: "c", long: []string{"-command", "--command"}},
}

// family maps a program's base name to its inlineFlags key: python3.14 →
// python, zsh → sh.
func family(exe string) string {
	base := strings.ToLower(filepath.Base(exe))
	switch {
	case strings.HasPrefix(base, "python"), strings.HasPrefix(base, "pypy"):
		return "python"
	case base == "sh", base == "bash", base == "zsh", base == "dash", base == "ksh", base == "fish", base == "tcsh", base == "csh":
		return "sh"
	case base == "node", base == "nodejs":
		return "node"
	case base == "powershell":
		return "pwsh"
	}
	return base
}

// CheckArgv refuses a command that would hand the job's values straight back:
// a printer as the program, or an interpreter given its program inline.
// Only the interpreter's own flags are read, up to the first argument that is
// not a flag (the script); what follows belongs to the script.
//
// This is a speed bump for honest mistakes, not a boundary. A script can print
// its environment as easily as `env` can. The boundary is the human reading
// the command, and the fingerprint keeping it the command they read.
func CheckArgv(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return fmt.Errorf("no command given")
	}
	base := strings.ToLower(filepath.Base(argv[0]))
	if printers[base] {
		return fmt.Errorf("%s prints what it is given, so it would print the secrets. Run a script that uses them instead", base)
	}
	fam := family(argv[0])
	flags, isInterp := inlineFlags[fam]
	if !isInterp {
		return nil
	}
	args := argv[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		for _, l := range flags.long {
			if a == l || strings.HasPrefix(a, l+"=") {
				return inlineError(base, a)
			}
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		if flags.short != "" && strings.ContainsAny(a[1:], flags.short) {
			return inlineError(base, a)
		}
		if len(a) == 2 && flags.takes != "" && strings.ContainsRune(flags.takes, rune(a[1])) {
			i++ // the flag's value, not the script
		}
	}
	// deno's subcommand form: `deno eval <code>`.
	if fam == "deno" && len(argv) > 1 && argv[1] == "eval" {
		return inlineError(base, "eval")
	}
	return nil
}

func inlineError(prog, flag string) error {
	return fmt.Errorf("%s %s runs a program written into the command itself, so it can print the secrets it is given. Save it as a file and approve that file", prog, flag)
}
