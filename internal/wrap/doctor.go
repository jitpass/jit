// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package wrap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DoctorCheck is one health verdict for `jit wrap doctor` — machine-shaped
// so the CLI owns all formatting, matching jit doctor's own split.
type DoctorCheck struct {
	Name   string
	OK     bool
	Detail string
}

// Doctor verifies the whole wrap installation: the shim dir's permissions,
// its presence on PATH and in the rc file, and — per wrapped tool — the
// shim symlink, its target, the real binary beyond the shim dir, and the
// profile manifest. Checks that can't run (unreadable manifest) surface as
// failed checks, not errors: doctor's job is to always produce a report.
func Doctor(home, pathEnv, shell string) []DoctorCheck {
	var checks []DoctorCheck
	dir := ShimDir(home)

	manifest, err := LoadManifest(home)
	if err != nil {
		return append(checks, DoctorCheck{Name: "manifest", OK: false, Detail: err.Error()})
	}
	if len(manifest.Tools) == 0 {
		return append(checks, DoctorCheck{Name: "wrapped tools", OK: true, Detail: "none, nothing to check"})
	}

	if info, statErr := os.Stat(dir); statErr != nil {
		checks = append(checks, DoctorCheck{Name: "shim dir", OK: false, Detail: dir + " missing, re-run `jit wrap add` for any tool"})
	} else if perm := info.Mode().Perm(); perm != 0o700 {
		checks = append(checks, DoctorCheck{Name: "shim dir", OK: false, Detail: fmt.Sprintf("%s is %o, want 0700, `chmod 700 %s`", dir, perm, dir)})
	} else {
		checks = append(checks, DoctorCheck{Name: "shim dir", OK: true, Detail: dir + " (0700)"})
	}

	onPath := false
	for _, p := range filepath.SplitList(pathEnv) {
		if samePath(p, dir) {
			onPath = true
			break
		}
	}
	if onPath {
		checks = append(checks, DoctorCheck{Name: "PATH", OK: true, Detail: "shim dir is on PATH in this shell"})
	} else {
		checks = append(checks, DoctorCheck{Name: "PATH", OK: false, Detail: "shim dir not on PATH in this shell, open a new shell or `" + PathLine() + "`"})
	}

	rc := RcFile(home, shell)
	if data, readErr := os.ReadFile(rc); readErr == nil && strings.Contains(string(data), ".jit/shims") { // #nosec G304 -- the user's own rc file
		checks = append(checks, DoctorCheck{Name: "rc file", OK: true, Detail: rc + " has the shim PATH line"})
	} else {
		checks = append(checks, DoctorCheck{Name: "rc file", OK: false, Detail: rc + " missing the shim PATH line, re-run `jit wrap add` for any tool"})
	}

	for _, tool := range manifestTools(manifest) {
		entry := manifest.Tools[tool]
		name := "tool " + tool

		link := filepath.Join(dir, tool)
		target, linkErr := os.Readlink(link)
		switch {
		case linkErr != nil:
			checks = append(checks, DoctorCheck{Name: name, OK: false, Detail: "shim symlink missing, `jit wrap add " + tool + " ...` reinstalls it"})
			continue
		default:
			if info, statErr := os.Stat(target); statErr != nil || info.Mode()&0o111 == 0 {
				checks = append(checks, DoctorCheck{Name: name, OK: false, Detail: "shim points at " + target + ", which isn't an executable, jit moved? re-run `jit wrap add " + tool + " ...`"})
				continue
			}
		}

		if _, lookErr := lookPathSkipping(pathEnv, tool, dir); lookErr != nil {
			checks = append(checks, DoctorCheck{Name: name, OK: false, Detail: "real " + tool + " not found on PATH beyond the shim dir, is it still installed?"})
			continue
		}

		// A grant-wrap has no profile — it grants a global mount by name,
		// validated by `jit run --with` at use time. The shim + real binary
		// resolving is all doctor can (and needs to) check here.
		if entry.IsGrant() {
			checks = append(checks, DoctorCheck{Name: name, OK: true, Detail: "shim and real binary resolve; grants the " + entry.With + " mount via `jit run --with`"})
			continue
		}

		profilePath := filepath.Join(home, ".jit", "profiles", entry.Profile+".yaml")
		if _, statErr := os.Stat(profilePath); statErr != nil {
			checks = append(checks, DoctorCheck{Name: name, OK: false, Detail: "profile " + entry.Profile + " missing at " + profilePath})
			continue
		}

		checks = append(checks, DoctorCheck{Name: name, OK: true, Detail: "shim, real binary, and profile all resolve"})
	}
	return checks
}

func manifestTools(m Manifest) []string {
	tools := make([]string, 0, len(m.Tools))
	for t := range m.Tools {
		tools = append(tools, t)
	}
	sort.Strings(tools)
	return tools
}
