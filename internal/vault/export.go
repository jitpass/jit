// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// exportVersion is ExportEnvelope's on-disk schema version — bumped if the
// shape or KDF parameters ever change, so a future Import can tell an old
// export apart from a new one rather than guessing. Version 1's payload
// was a bare path→value map; version 2 wraps each value in an exportEntry
// so a reference-kind secret (envelope.Storage) exports as the reference
// it is. Import reads both, forever.
const exportVersion = 2

// exportEntry is one secret inside a version-2 export payload: the stored
// payload bytes plus the envelope's storage marker. Carrying storage is
// what lets a linked secret survive the export/import round trip AS a
// link — without it, an import would freeze the reference URI into a
// literal "secret" whose value is the string "op://…", silently breaking
// the link on the restored machine.
type exportEntry struct {
	Value   []byte `json:"value"`
	Storage string `json:"storage,omitempty"`
}

// Argon2id parameters for deriving an export's encryption key from a
// passphrase. Deliberately memory-hard and reasonably slow (not vault
// Set/Get's hot path — this runs once per export/import, a rare,
// deliberate action) to resist offline brute-force against a stolen
// export file, which is the actual threat model here: unlike the vault's
// own per-secret .enc files (device-bound, useless off-device — see
// ExportEnvelope's doc comment), a passphrase is the ONLY thing standing
// between an exported file and every secret it contains.
const (
	argon2Time      = 3
	argon2MemoryKiB = 64 * 1024 // 64 MiB
	argon2Threads   = 4
	argon2KeyLen    = 32 // AES-256
	argon2SaltSize  = 16
)

// ExportEnvelope is `jit vault export`'s on-disk shape (GAPS.md #23) — a
// single passphrase-encrypted file holding a snapshot of every secret
// currently in the vault, restorable via Import on a DIFFERENT machine.
// This is deliberately NOT the same encryption as the vault's own
// per-secret .enc files: those wrap each DEK for THIS device's KeyWrapper
// (Secure Enclave/keychain-bound), and RFC.md's own cloud-sync note
// already concedes that isn't portable — "syncing the encrypted file to a
// second machine doesn't make it readable there." A passphrase-derived
// key is the only thing that makes an export actually useful for disaster
// recovery: laptop loss/reformat means the original device's Secure
// Enclave/keychain MEK is gone too, so a human-remembered passphrase is
// the only recovery path left. Distinct from gap #13 (a cloud-sync
// storage *backend*, never implemented) — this is a local file, moved
// around by whatever means the caller chooses (a USB drive, a password
// manager's attachment, manually copying it to a second disk), not a
// sync mechanism jit manages.
type ExportEnvelope struct {
	Version int `json:"version"`
	// Salt is the Argon2id KDF's random input (hex) — freshly generated
	// per export, so two exports of the same vault under the same
	// passphrase never derive the same key.
	Salt string `json:"salt"`
	// Payload is the hex-encoded (nonce || ciphertext) of the JSON-encoded
	// map of every secret path to its exportEntry (version 2; version 1
	// mapped straight to plaintext values), AES-256-GCM sealed under the
	// Argon2id-derived key.
	Payload string `json:"payload"`
}

// Export decrypts every secret currently in the vault (via GetStored, so
// it needs the same KeyWrapper/local-auth Get always does — but never the
// RefResolver: an export is a vault backup, and a linked secret exports
// as its reference, not as a 1Password read) and re-encrypts the whole
// set under a single Argon2id-derived key from passphrase. Callers own
// passphrase and should wipe() it once done, same as any other secret
// material.
func (v *Vault) Export(passphrase []byte) (*ExportEnvelope, error) {
	paths, err := v.List()
	if err != nil {
		return nil, fmt.Errorf("listing vault: %w", err)
	}

	secrets := make(map[string]exportEntry, len(paths))
	defer wipeEntries(secrets)
	for _, path := range paths {
		value, storage, err := v.GetStored(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		secrets[path] = exportEntry{Value: value, Storage: storage}
	}

	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("encoding secrets: %w", err)
	}
	defer wipe(plaintext)

	salt := make([]byte, argon2SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	key := deriveExportKey(passphrase, salt)
	defer wipe(key)

	// nil AAD, forever: export files predate AAD and must stay importable
	// across jit versions in both directions within the same exportVersion.
	sealed, err := seal(key, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting export: %w", err)
	}

	return &ExportEnvelope{
		Version: exportVersion,
		Salt:    hex.EncodeToString(salt),
		Payload: hex.EncodeToString(sealed),
	}, nil
}

// Import decrypts env with passphrase and writes every secret it contains
// into v via Set — or SetReference, for an entry exported from a linked
// secret, so a link is restored as a link (so it needs the same
// KeyWrapper Set always does), overwriting any existing secret at the
// same path. Returns the number of secrets restored.
func (v *Vault) Import(env *ExportEnvelope, passphrase []byte) (int, error) {
	secrets, err := decryptExport(env, passphrase)
	if err != nil {
		return 0, err
	}
	defer wipeEntries(secrets)

	for path, entry := range secrets {
		switch entry.Storage {
		case "":
			err = v.Set(path, entry.Value)
		case StorageOpRef:
			err = v.SetReference(path, string(entry.Value), Meta{})
		default:
			// Same fail-closed stance as Get's storage gate: restoring a
			// future marker's payload as a literal secret would silently
			// change what it means.
			err = fmt.Errorf("storage kind %q is newer than this jit understands, upgrade jit to import it", entry.Storage)
		}
		if err != nil {
			return 0, fmt.Errorf("restoring %s: %w", path, err)
		}
	}
	return len(secrets), nil
}

// VerifyExportPassphrase decrypts env just to confirm passphrase is
// correct, discarding the result — for a caller (jit vault import) that
// wants to fail fast on a wrong passphrase or a corrupted file BEFORE
// opening a real Vault, which may trigger a Touch ID/passcode challenge.
// Wasting that prompt on a typo, in what's already a stressful disaster-
// recovery moment, is worth the cost of running the deliberately-slow
// Argon2id KDF (see its own doc comment) a second time — Import doesn't
// call this itself, to avoid paying that cost twice on the normal path.
func VerifyExportPassphrase(env *ExportEnvelope, passphrase []byte) error {
	secrets, err := decryptExport(env, passphrase)
	if err != nil {
		return err
	}
	wipeEntries(secrets)
	return nil
}

// decryptExport is Import and VerifyExportPassphrase's shared core: derive
// the key, open the AEAD payload, and parse the resulting JSON into a
// secret-path-to-entry map. Version 1 files (a bare path→value map, from
// every jit before the storage marker existed) parse forever, as
// literal-value entries.
func decryptExport(env *ExportEnvelope, passphrase []byte) (map[string]exportEntry, error) {
	if env.Version < 1 || env.Version > exportVersion {
		return nil, fmt.Errorf("unsupported export version %d (this jit understands versions 1 to %d)", env.Version, exportVersion)
	}
	salt, err := hex.DecodeString(env.Salt)
	if err != nil {
		return nil, fmt.Errorf("corrupt export: invalid salt encoding: %w", err)
	}
	sealed, err := hex.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("corrupt export: invalid payload encoding: %w", err)
	}

	key := deriveExportKey(passphrase, salt)
	defer wipe(key)

	plaintext, err := open(key, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypting export (wrong passphrase, or the file is corrupted): %w", err)
	}
	defer wipe(plaintext)

	if env.Version == 1 {
		var values map[string][]byte
		if err := json.Unmarshal(plaintext, &values); err != nil {
			return nil, fmt.Errorf("parsing decrypted export: %w", err)
		}
		secrets := make(map[string]exportEntry, len(values))
		for path, value := range values {
			secrets[path] = exportEntry{Value: value}
		}
		return secrets, nil
	}
	var secrets map[string]exportEntry
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, fmt.Errorf("parsing decrypted export: %w", err)
	}
	return secrets, nil
}

func deriveExportKey(passphrase, salt []byte) []byte {
	return argon2.IDKey(passphrase, salt, argon2Time, argon2MemoryKiB, argon2Threads, argon2KeyLen)
}

// wipeEntries zeroes every entry's value bytes — Export/Import's
// secret-bearing maps, so their contents don't linger in memory any
// longer than crypto.go's own wipe() convention already accepts elsewhere
// in this package (best-effort, not a hard guarantee against a GC-moved
// copy — see wipe's own doc comment).
func wipeEntries(m map[string]exportEntry) {
	for _, e := range m {
		wipe(e.Value)
	}
}
