// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package agent

import "path/filepath"

// SocketPath returns the Unix socket path under root (jit's config
// directory, e.g. ~/Library/Application Support/jitpass) — bookkeeping/IPC,
// not secret material, so it lives alongside (not inside) the vault tree,
// same convention as internal/mount's registry.
func SocketPath(root string) string {
	return filepath.Join(root, "agent.sock")
}
