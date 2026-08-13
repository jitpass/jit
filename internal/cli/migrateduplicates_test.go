// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jitpass/jit/internal/vault"
)

// TestNoteDuplicateValues pins migrate's duplicate disclosure: a value the
// vault already held under another group gets one note routing to
// `jit vault duplicates`, while config-named keys, trivially short values,
// the profile's own paths, and a missing index all stay silent — and the
// note never blocks or changes the migration itself (it only prints).
func TestNoteDuplicateValues(t *testing.T) {
	withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}
	set := func(path, value string) {
		t.Helper()
		if err := v.Set(path, []byte(value)); err != nil {
			t.Fatalf("Set(%s): %v", path, err)
		}
	}

	// The pre-existing copy, then the index snapshot, then the "migration".
	set("mcp-caido/CAIDO_URL", "http://127.0.0.1:8080")
	set("mcp-caido/OUTPUT_FILE", "/tmp/out.json")
	idx := buildVaultValueIndex(v)
	set("mcp-caido-2/CAIDO_URL", "http://127.0.0.1:8080") // duplicate value
	set("mcp-caido-2/OUTPUT_FILE", "/tmp/out.json")       // duplicate but config-named
	set("mcp-caido-2/DEPTH", "8080")                      // short: coincidence fodder

	var buf bytes.Buffer
	noteDuplicateValues(&buf, v, idx, "mcp-caido-2", []string{"CAIDO_URL", "OUTPUT_FILE", "DEPTH"})
	out := buf.String()
	if !strings.Contains(out, "1 value is already stored under mcp-caido") ||
		!strings.Contains(out, "jit vault duplicates") {
		t.Errorf("expected one duplicate note naming the group, got:\n%s", out)
	}
	if strings.Contains(out, "OUTPUT_FILE") || strings.Contains(out, "2 values") {
		t.Errorf("config-named and short values must not count, got:\n%s", out)
	}

	// Re-noting the ORIGINAL profile against an index that holds its own
	// paths must stay silent — a group is never its own duplicate.
	buf.Reset()
	noteDuplicateValues(&buf, v, buildVaultValueIndex(v), "mcp-caido", []string{"CAIDO_URL"})
	if strings.Contains(buf.String(), "already stored under mcp-caido,") {
		t.Errorf("a profile must not report itself, got:\n%s", buf.String())
	}

	// A nil index (listing failed) disables disclosure, never errors.
	buf.Reset()
	noteDuplicateValues(&buf, v, nil, "mcp-caido-2", []string{"CAIDO_URL"})
	if buf.Len() != 0 {
		t.Errorf("nil index must print nothing, got:\n%s", buf.String())
	}
}

// TestNoteDuplicateValuesIndexBuiltAfterTheWrite reproduces the ordering
// migrate actually uses: the index is built LAZILY, i.e. after the file's
// secrets are already stored, so the copy's own freshly-written path is in
// the index alongside the original's. A digest->one-path index let the
// new path win the slot and the note went silent on a real duplicate;
// caught by migrating a copied folder on a real machine, where
// "ws-copy/CAIDO_URL" sorts before "ws/CAIDO_URL".
func TestNoteDuplicateValuesIndexBuiltAfterTheWrite(t *testing.T) {
	withFixtureHome(t)
	root, err := vaultRootDir()
	if err != nil {
		t.Fatalf("vaultRootDir: %v", err)
	}
	v := &vault.Vault{Root: root, KeyWrapper: newFakeKeyWrapper(), RecipientID: "test-device"}

	// Both copies exist BEFORE the index is built, and the newer profile's
	// path sorts first — exactly the shape that used to mask the duplicate.
	if err := v.Set("ws/CAIDO_URL", []byte("http://127.0.0.1:8080")); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("ws-copy/CAIDO_URL", []byte("http://127.0.0.1:8080")); err != nil {
		t.Fatal(err)
	}
	idx := buildVaultValueIndex(v)

	var buf bytes.Buffer
	noteDuplicateValues(&buf, v, idx, "ws-copy", []string{"CAIDO_URL"})
	out := buf.String()
	if !strings.Contains(out, "1 value is already stored under ws") {
		t.Errorf("the older copy must be named even though the new path sorts first, got:\n%s", out)
	}
	if strings.Contains(out, "ws-copy") {
		t.Errorf("the migrating profile must never name itself, got:\n%s", out)
	}
}
