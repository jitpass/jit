// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package secureenclave

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/jitpass/jit/internal/vault"
)

// SealedFile is the vault root's file holding the MEK sealed to the enclave
// key. Its presence is how every jit knows a vault's key is in the enclave
// (design/secure-enclave.md, decision D2); `jit vault delete` must remove it
// with the rest of the vault's local state.
const SealedFile = vault.SealedKeyFile

const (
	sealedVersion = 1
	// wrapECIES names the sealing: ECIES to the enclave key's P-256 public
	// half (cofactor, variable IV, X9.63 SHA-256, AES-GCM). A second scheme
	// gets a second name, and a build that does not know a name refuses it
	// rather than guessing, the way the grant ledger's "aead-v1" works.
	wrapECIES = "se-p256-ecies-v1"
)

// sealedKey is the file's shape. Nothing in it is secret: the blob opens
// only inside this Mac's enclave. Tag records which key sealed it, and is
// checked against the Wrapper's own, never trusted to choose one: the file
// sits in a folder any program running as the user can write.
type sealedKey struct {
	Version int    `json:"version"`
	Wrap    string `json:"wrap"`
	Tag     string `json:"kek_tag"`
	Blob    string `json:"blob"`
}

// readSealed loads and checks the file. A missing file comes back as an
// error satisfying errors.Is(err, os.ErrNotExist).
func readSealed(path string) (sealedKey, []byte, error) {
	var k sealedKey
	data, err := os.ReadFile(path) // #nosec G304 -- the vault root's own file, path built by this package
	if err != nil {
		return k, nil, err
	}
	if err := json.Unmarshal(data, &k); err != nil {
		return k, nil, fmt.Errorf("%s is not a sealed vault key: %w", path, err)
	}
	if k.Version != sealedVersion {
		return k, nil, fmt.Errorf("%s is version %d, and this jit reads version %d; update jit", path, k.Version, sealedVersion)
	}
	if k.Wrap != wrapECIES {
		return k, nil, fmt.Errorf("%s is sealed as %q, which this jit cannot open; update jit", path, k.Wrap)
	}
	blob, err := hex.DecodeString(k.Blob)
	if err != nil || len(blob) == 0 {
		return k, nil, fmt.Errorf("%s holds a damaged sealed key", path)
	}
	return k, blob, nil
}

// writeSealed writes the file atomically at 0600 (vault.AtomicWriteFile):
// a crash leaves the old file or the new one, never half of either.
func writeSealed(path, tag string, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("refusing to write an empty sealed key")
	}
	data, err := json.MarshalIndent(sealedKey{
		Version: sealedVersion,
		Wrap:    wrapECIES,
		Tag:     tag,
		Blob:    hex.EncodeToString(blob),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the sealed key: %w", err)
	}
	return vault.AtomicWriteFile(path, append(data, '\n'))
}
