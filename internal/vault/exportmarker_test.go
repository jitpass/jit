// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLastExportBeforeAnyRecord(t *testing.T) {
	root := t.TempDir()
	_, ok, err := LastExport(root)
	if err != nil {
		t.Fatalf("LastExport on a root with no marker: %v", err)
	}
	if ok {
		t.Error("LastExport ok = true before any RecordExport, want false")
	}
}

func TestRecordExportRoundTrip(t *testing.T) {
	root := t.TempDir()
	before := time.Now().Add(-time.Second)
	if err := RecordExport(root); err != nil {
		t.Fatalf("RecordExport: %v", err)
	}
	at, ok, err := LastExport(root)
	if err != nil {
		t.Fatalf("LastExport: %v", err)
	}
	if !ok {
		t.Fatal("LastExport ok = false right after RecordExport")
	}
	if at.Before(before) || at.After(time.Now().Add(time.Second)) {
		t.Errorf("LastExport time = %v, want approximately now", at)
	}
}

func TestNewestSecretTime(t *testing.T) {
	root := t.TempDir()
	v := &Vault{Root: root}

	newest, err := v.NewestSecretTime()
	if err != nil {
		t.Fatalf("NewestSecretTime on empty root: %v", err)
	}
	if !newest.IsZero() {
		t.Errorf("NewestSecretTime on empty vault = %v, want zero time", newest)
	}

	oldPath := filepath.Join(root, "vault", "aws", "old.enc")
	newPath := filepath.Join(root, "vault", "stripe", "new.enc")
	for _, p := range []string{oldPath, newPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	oldTime := time.Now().Add(-time.Hour)
	if err := os.Chtimes(oldPath, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	newTime := time.Now().Add(-time.Minute)
	if err := os.Chtimes(newPath, newTime, newTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	newest, err = v.NewestSecretTime()
	if err != nil {
		t.Fatalf("NewestSecretTime: %v", err)
	}
	if newest.Sub(newTime).Abs() > time.Second {
		t.Errorf("NewestSecretTime = %v, want the newer file's mtime %v", newest, newTime)
	}
	if newest.Sub(oldTime).Abs() < time.Minute {
		t.Errorf("NewestSecretTime = %v matched the OLDER file's mtime %v", newest, oldTime)
	}
}

// TestExportStalenessComparison locks in the exact check jit status
// performs: a secret written after RecordExport makes the export stale;
// one written before does not — including within the same second, which
// is why the marker records nanosecond precision (a second-truncated
// stamp called a just-covered secret "not covered").
func TestExportStalenessComparison(t *testing.T) {
	root := t.TempDir()
	v := &Vault{Root: root}

	covered := filepath.Join(root, "vault", "covered.enc")
	if err := os.MkdirAll(filepath.Dir(covered), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(covered, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := RecordExport(root); err != nil {
		t.Fatalf("RecordExport: %v", err)
	}
	at, _, err := LastExport(root)
	if err != nil {
		t.Fatalf("LastExport: %v", err)
	}
	newest, err := v.NewestSecretTime()
	if err != nil {
		t.Fatalf("NewestSecretTime: %v", err)
	}
	if newest.After(at) {
		t.Errorf("secret written BEFORE the export reads as stale: newest %v > export %v", newest, at)
	}

	// A secret written after the export must read as stale. Chtimes to a
	// clearly-later mtime avoids depending on wall-clock granularity.
	uncovered := filepath.Join(root, "vault", "uncovered.enc")
	if err := os.WriteFile(uncovered, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(uncovered, later, later); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	newest, err = v.NewestSecretTime()
	if err != nil {
		t.Fatalf("NewestSecretTime: %v", err)
	}
	if !newest.After(at) {
		t.Errorf("secret written AFTER the export doesn't read as stale: newest %v <= export %v", newest, at)
	}
}
