// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// deviceIDFile is where EnsureDeviceID persists this machine's identifier,
// directly under Root (alongside mounts.yaml — bookkeeping metadata, not
// secret material, so it lives outside the vault/ tree).
const deviceIDFile = "device.id"

// EnsureDeviceID returns this machine's stable jit device identifier,
// generating and persisting one under root on first use.
//
// This exists because envelopes used to key their wrapped DEK on
// os.Hostname() — an identifier macOS does not keep stable: renaming the
// Mac in System Settings changes it, and on some networks the hostname
// follows whatever name DHCP hands out. The day it changed, every stored
// secret failed with "no key for this device ... encrypted on a different
// machine" even though nothing had moved. A random ID written once to a
// file jit itself owns can't drift out from under the envelopes that
// reference it. (Vault.Get additionally tolerates a single-recipient
// envelope whose recipient ID doesn't match — see its doc comment — so
// vaults written before this existed keep decrypting after the switch.)
func EnsureDeviceID(root string) (string, error) {
	idPath := filepath.Join(root, deviceIDFile)
	data, err := os.ReadFile(idPath) // #nosec G304 -- fixed, well-known path under jit's own config directory
	if err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
		// An empty file is treated like a missing one: fall through and
		// regenerate rather than silently using "" as every envelope's
		// recipient key.
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("reading device ID %s: %w", idPath, err)
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating device ID: %w", err)
	}
	id := "device-" + hex.EncodeToString(buf)
	if err := AtomicWriteFile(idPath, []byte(id+"\n")); err != nil {
		return "", fmt.Errorf("persisting device ID: %w", err)
	}
	return id, nil
}
