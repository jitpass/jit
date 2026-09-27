// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package inject

import (
	"fmt"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/settings"
	"github.com/jitpass/jit/internal/vault"
)

// Resolve decrypts every secret p references, returning env var name ->
// plaintext value. Callers should treat the returned values the same way
// vault.Get's caller would — never log them, never write them anywhere but
// the target's environment.
//
// An entry naming a plain setting (jit://setting/…, design/secrets-only-
// vault.md) is read from the settings store beside v, with no decrypt: it
// was never a secret.
func Resolve(v *vault.Vault, p profile.Profile) (map[string]string, error) {
	values := make(map[string]string, len(p))
	store := settings.New(v.Root)
	for varName, secretPath := range p {
		if path, ok := settings.PathOf(secretPath); ok {
			val, err := store.Get(path)
			if err != nil {
				return nil, fmt.Errorf("resolving %s (setting %s): %w", varName, path, err)
			}
			values[varName] = string(val)
			continue
		}
		val, err := v.Get(secretPath)
		if err != nil {
			return nil, fmt.Errorf("resolving %s (%s): %w", varName, secretPath, err)
		}
		values[varName] = string(val)
	}
	return values, nil
}

// MergeEnv overlays overrides onto base (an os.Environ()-shaped slice),
// replacing — not duplicating — any existing entry for a key that's being
// overridden. Duplicate keys in a process's environ block are technically
// undefined behavior (which one "wins" varies by libc/lookup order), so a
// naive append would risk the real secret losing to a stale inherited
// value depending on the target runtime — this makes the override
// unambiguous instead of relying on that undefined behavior.
func MergeEnv(base []string, overrides map[string]string) []string {
	merged := make([]string, 0, len(base)+len(overrides))
	for _, kv := range base {
		key, _, found := strings.Cut(kv, "=")
		if found {
			if _, overridden := overrides[key]; overridden {
				continue
			}
		}
		merged = append(merged, kv)
	}
	for k, v := range overrides {
		merged = append(merged, k+"="+v)
	}
	return merged
}
