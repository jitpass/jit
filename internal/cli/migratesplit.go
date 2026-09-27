// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jitpass/jit/internal/migrate"
	"github.com/jitpass/jit/internal/profile"
)

// --secret and --setting: the user's word on where a .env variable goes,
// over the scan's (design/secrets-only-vault.md). Each value is NAME, for
// that variable in every .env the run names, or FILE:NAME for one file. The
// app always passes FILE:NAME, so a choice made on one file's line can never
// reach a variable of the same name in another file.
var (
	migrateSecretNames  []string
	migrateSettingNames []string
)

type splitChoice struct {
	file string // absolute; "" for every file
	name string
}

// parseSplitChoices reads one flag's values, refusing a name the shell could
// not export (the manifest's own rule) before anything is planned.
func parseSplitChoices(flag string, values []string) ([]splitChoice, error) {
	out := make([]splitChoice, 0, len(values))
	for _, raw := range values {
		file, name := "", raw
		if i := strings.LastIndex(raw, ":"); i >= 0 {
			file, name = raw[:i], raw[i+1:]
			abs, err := expandSplitFile(file)
			if err != nil {
				return nil, fmt.Errorf("--%s %s: %w", flag, raw, err)
			}
			file = abs
		}
		if !profile.ValidVarName(name) {
			return nil, fmt.Errorf("--%s %s: %q is not a variable name", flag, raw, name)
		}
		out = append(out, splitChoice{file: file, name: name})
	}
	return out, nil
}

func expandSplitFile(file string) (string, error) {
	if rest, ok := strings.CutPrefix(file, "~/"); ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, rest)
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

// migrateSplit is both flags, parsed once per run.
type migrateSplit struct {
	secret, setting []splitChoice
}

// loadMigrateSplit parses the flags and refuses a variable named both ways.
func loadMigrateSplit() (migrateSplit, error) {
	secret, err := parseSplitChoices("secret", migrateSecretNames)
	if err != nil {
		return migrateSplit{}, err
	}
	setting, err := parseSplitChoices("setting", migrateSettingNames)
	if err != nil {
		return migrateSplit{}, err
	}
	for _, a := range secret {
		for _, b := range setting {
			if a.name == b.name && (a.file == "" || b.file == "" || a.file == b.file) {
				return migrateSplit{}, fmt.Errorf("%s is named by both --secret and --setting", a.name)
			}
		}
	}
	return migrateSplit{secret: secret, setting: setting}, nil
}

// forFile is the split that applies to one .env.
func (m migrateSplit) forFile(envPath string) migrate.EnvSplit {
	abs, err := filepath.Abs(envPath)
	if err != nil {
		abs = envPath
	}
	abs = filepath.Clean(abs)
	pick := func(choices []splitChoice) map[string]bool {
		var out map[string]bool
		for _, c := range choices {
			if c.file != "" && c.file != abs {
				continue
			}
			if out == nil {
				out = map[string]bool{}
			}
			out[c.name] = true
		}
		return out
	}
	return migrate.EnvSplit{Secret: pick(m.secret), Setting: pick(m.setting)}
}

// envSplitLine is a plan's per-file annotation: where the variables go, and
// the names worth a second look.
func envSplitLine(plan []migrate.EnvVarPlan) string {
	vaulted, kept := 0, 0
	var checks []string
	for _, vp := range plan {
		if !vp.InVault {
			kept++
			continue
		}
		vaulted++
		if vp.Class == "check" {
			checks = append(checks, vp.Name)
		}
	}
	line := fmt.Sprintf("%d to the vault, %s", vaulted, countWord(kept, "setting", "settings"))
	if len(checks) > 0 {
		line += "; check " + strings.Join(checks, ", ") + " (the name says secret, the value doesn't look like one)"
	}
	return line
}

// envResultCounts is a migrated .env's result in the reader's terms.
func envResultCounts(r migrate.EnvFileMigration) string {
	vaulted := len(r.Variables) - len(r.Settings)
	return fmt.Sprintf("%d to the vault, %s", vaulted, countWord(len(r.Settings), "setting", "settings"))
}

// noteChecks names the variables that went to the vault only because their
// name says secret, with the flag that keeps one plain instead.
func noteChecks(w io.Writer, r migrate.EnvFileMigration) {
	for _, name := range r.Checks {
		_, _ = cWarn.Fprintf(w, "    note: %s went to the vault: the name says secret, the value doesn't look like one\n", name)
		wrapBody(w, 0, "    ", hlCmds(fmt.Sprintf("    to keep it plain: `jit vault move-out %s/%s`", r.ProfileName, name)))
	}
}
