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
// takesLong is the same for long flags given as two arguments: `node
// --require ./m.js -e …` must be read past ./m.js.
//
// codeShort and codeLong are flags whose value is CODE the interpreter loads
// before the program (`node -r ./hook.js`, `ruby -I ../lib`): they are
// fingerprinted like the program, and refused when they name a folder
// outside the job.
var inlineFlags = map[string]struct {
	short     string
	long      []string
	takes     string
	takesLong []string
	codeShort string
	codeLong  []string
}{
	"python": {short: "c", takes: "WXQ", takesLong: []string{"--check-hash-based-pycs"}},
	"sh":     {short: "c", takes: "oO", takesLong: []string{"--rcfile", "--init-file"}},
	"node": {short: "ep", long: []string{"--eval", "--print"}, takes: "r",
		takesLong: []string{"--require", "--import", "--loader", "--experimental-loader", "--env-file", "--conditions", "--input-type", "--title"},
		codeShort: "r", codeLong: []string{"--require", "--import", "--loader", "--experimental-loader"}},
	"deno":      {short: "e", long: []string{"--eval"}}, // plus `deno eval`, below
	"bun":       {short: "e", long: []string{"--eval", "--print"}},
	"ruby":      {short: "e", takes: "Ir", codeShort: "Ir"},
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
	if flag := scanArgs(argv).inline; flag != "" {
		return inlineError(base, flag)
	}
	// deno's subcommand form: `deno eval <code>`.
	if fam == "deno" && len(argv) > 1 && argv[1] == "eval" {
		return inlineError(base, "eval")
	}
	return nil
}

// argScan is what an interpreter's arguments say, read once, by the one
// scanner every check shares (CheckArgv, ExternalFiles, Label): three copies
// of this loop drifted apart once, and a fix landed in one and not the other.
type argScan struct {
	// program is the file an interpreter runs, "" for `-m module`, for a
	// program jit does not know as an interpreter, or when none is given.
	program string
	// module is `python -m`'s module, for display.
	module string
	// code holds the values of code-loading flags (node -r, ruby -I).
	code []string
	// inline is the flag that took a program inline (`-c`, `--eval`), if any.
	inline string
}

// scanArgs reads an interpreter's own flags up to its program. A short
// cluster is read letter by letter: an inline letter is refused wherever it
// sits (`-Bc`), and a value-taking letter takes the rest of the cluster
// (`-Wignore`) or, when it ends the cluster (`-uW ignore`), the next argument.
func scanArgs(argv []string) argScan {
	var out argScan
	if len(argv) < 2 {
		return out
	}
	flags, ok := inlineFlags[family(argv[0])]
	if !ok {
		return out
	}
	args := argv[1:]
	value := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			out.program = value(i + 1)
			return out
		case a == "-m":
			out.module = value(i + 1)
			return out
		case !strings.HasPrefix(a, "-") || a == "-":
			out.program = a
			return out
		case strings.HasPrefix(a, "--"):
			name, inlineVal, hasVal := strings.Cut(a, "=")
			for _, l := range flags.long {
				if name == l {
					out.inline = a
					return out
				}
			}
			for _, l := range flags.takesLong {
				if name != l {
					continue
				}
				v := inlineVal
				if !hasVal {
					i++
					v = value(i)
				}
				for _, cl := range flags.codeLong {
					if name == cl {
						out.code = append(out.code, v)
					}
				}
			}
		default:
			cluster := a[1:]
			for k, r := range cluster {
				if strings.ContainsRune(flags.short, r) {
					out.inline = a
					return out
				}
				if !strings.ContainsRune(flags.takes, r) {
					continue
				}
				v := cluster[k+1:]
				if v == "" {
					i++
					v = value(i)
				}
				if strings.ContainsRune(flags.codeShort, r) {
					out.code = append(out.code, v)
				}
				break
			}
		}
	}
	return out
}

// programArg is the file an interpreter runs as its program.
func programArg(argv []string) string { return scanArgs(argv).program }

// Label names what a job runs, for the one line the human decides by:
// the folder and the program. The program is the file the interpreter runs
// (`python -W x run.py` → run.py), `-m module` for a module, and otherwise
// the executable itself: never an argument the command merely passes along.
func Label(dir string, argv []string) (folder, program string) {
	folder = filepath.Base(dir)
	sc := scanArgs(argv)
	switch {
	case sc.program != "":
		program = filepath.Base(sc.program)
	case sc.module != "":
		program = "-m " + sc.module
	default:
		program = filepath.Base(argv[0])
	}
	return folder, program
}

func inlineError(prog, flag string) error {
	return fmt.Errorf("%s %s runs a program written into the command itself, so it can print the secrets it is given. Save it as a file and approve that file", prog, flag)
}
