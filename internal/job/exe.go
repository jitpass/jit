// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Run limits. The output cap keeps the tail on overflow, since the end of a
// run (the summary, the error) is what the caller needs.
const (
	RunTimeout = 10 * time.Minute
	OutputCap  = 256 << 10
)

// ResolveExe finds argv0 the way the approving shell would: a name with a
// slash is taken relative to dir, a bare name is searched on pathEnv. The
// result is absolute but NOT symlink-resolved: a venv's bin/python must stay
// bin/python, because Python finds its venv from the path it was started as.
// The fingerprint hashes the resolved target separately.
func ResolveExe(argv0, dir, pathEnv string) (string, error) {
	if argv0 == "" {
		return "", fmt.Errorf("no command given")
	}
	if strings.Contains(argv0, "/") {
		p := argv0
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if isExecutable(p) {
			return filepath.Clean(p), nil
		}
		return "", fmt.Errorf("%s: not an executable file", p)
	}
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" || !filepath.IsAbs(d) {
			// A relative PATH entry would resolve against whatever folder the
			// service happens to be in, not the one the human approved from.
			continue
		}
		p := filepath.Join(d, argv0)
		if isExecutable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found on PATH", argv0)
}

func isExecutable(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}
