// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package inject

import (
	"fmt"
	"strings"

	"github.com/jitpass/jit/internal/profile"
	"github.com/jitpass/jit/internal/vault"
)

// Resolve decrypts every secret p references, returning env var name ->
// plaintext value. Callers should treat the returned values the same way
// vault.Get's caller would — never log them, never write them anywhere but
// the target's environment.
func Resolve(v *vault.Vault, p profile.Profile) (map[string]string, error) {
	values := make(map[string]string, len(p))
	for varName, secretPath := range p {
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
