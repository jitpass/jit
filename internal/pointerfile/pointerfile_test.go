// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package pointerfile

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestValueRoundTrip(t *testing.T) {
	const vaultPath = "mcp-alpha/TOKEN"
	v := Value(vaultPath)
	if !IsValue(v) {
		t.Fatalf("Value(%q) = %q, which IsValue rejects; a reader would treat jit's own pointer as a credential and vault it a second time", vaultPath, v)
	}
	got, ok := VaultPath(v)
	if !ok || got != vaultPath {
		t.Errorf("VaultPath(%q) = (%q, %v), want (%q, true)", v, got, ok, vaultPath)
	}
	// A real credential must NOT read as a pointer, or migrate would skip it.
	for _, notPointer := range []string{
		"", "sk-ant-api03-realvalue", "https://vault/example", "jit://other/thing",
	} {
		if IsValue(notPointer) {
			t.Errorf("IsValue(%q) = true; a real credential read as a pointer is silently left in place", notPointer)
		}
	}
}

func TestCompanionRoundTrip(t *testing.T) {
	const env = "/proj/.env.local"
	c := CompanionPath(env)
	if !IsCompanion(c) {
		t.Fatalf("CompanionPath(%q) = %q, which IsCompanion rejects", env, c)
	}
	got, ok := TrimCompanionSuffix(c)
	if !ok || got != env {
		t.Errorf("TrimCompanionSuffix(%q) = (%q, %v), want (%q, true)", c, got, ok, env)
	}
	if _, ok := TrimCompanionSuffix("/proj/.env"); ok {
		t.Error("a plain .env reported as a companion; migrate would skip a real file")
	}
}

func TestHasHeader(t *testing.T) {
	if !HasHeader([]byte(Header + " — do not edit\nKEY=" + Value("ns/KEY") + "\n")) {
		t.Error("a file jit wrote is not recognised by its own header check")
	}
	if HasHeader([]byte("# some other file\n")) {
		t.Error("an unrelated comment read as jit's header")
	}
	if HasHeader(nil) {
		t.Error("empty content read as a pointer file")
	}
}

// TestNoRawFormatSpellingsOutsideThisPackage is the guard that gives the format
// an owner rather than thirteen copies.
//
// Both packages' comments record the same real incident (GAPS.md #30): change
// the header wording in the writer and audit stops recognising jit's own
// output, so `jit scan` reports every already-migrated file as an exposed
// secret — and a second `jit migrate` run parses a `.pointers` companion's
// KEY=jit://vault/... lines as though they were real credentials.
//
// Test files are exempt on purpose, for the reason vault's namespace guard
// gives: a fixture should carry the literal, so both sides of an assertion
// cannot move together.
func TestNoRawFormatSpellingsOutsideThisPackage(t *testing.T) {
	spellings := []string{Header, ValuePrefix, CompanionSuffix}
	var offenders []string
	err := filepath.WalkDir("..", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") || strings.Contains(filepath.ToSlash(path), "/pointerfile/") {
			return nil
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- walking jit's own source tree
		if readErr != nil {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx] // prose describes the format freely
			}
			for _, sp := range spellings {
				if strings.Contains(code, `"`+sp) || strings.Contains(code, sp+`"`) {
					offenders = append(offenders, filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+" ("+sp+")")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("pointer-file format spelled out in code rather than using this package:\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
