// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"os"
	"path/filepath"
)

// This file is deliberately un-gated (no darwin build tag), like
// status.go: `jit status` needs agentInstalled for its agent section, and
// status.go stays portable by convention (see agentBuildMismatch's
// comment). The code here is pure path/stat work — only its MEANING is
// macOS-specific — so hosting it portably costs nothing.

const agentPlistLabel = "com.jitpass.agent"

func agentPlistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", agentPlistLabel+".plist"), nil
}

// agentInstalled reports whether the launchd plist exists — i.e. whether
// a non-answering socket means "mid-restart or crashed" (launchd will
// respawn it; retrying and `jit agent restart` are the right moves)
// rather than "never set up" (only `jit agent install` helps).
func agentInstalled() bool {
	plistPath, err := agentPlistPath()
	if err != nil {
		return false
	}
	_, err = os.Stat(plistPath)
	return err == nil
}
