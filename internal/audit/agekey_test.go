// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const fakeAgeKeyFile = `# created: 2026-07-01T10:00:00+02:00
# public key: age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
`

func TestScanSOPSAgeKeysXDGPath(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "sops", "age"))
	writeFile(t, filepath.Join(home, ".config", "sops", "age", "keys.txt"), fakeAgeKeyFile)

	findings, err := ScanSOPSAgeKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSOPSAgeKeys: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityHigh)
	}
	if f.Confidence != ConfidenceHigh {
		t.Errorf("confidence = %q, want %q", f.Confidence, ConfidenceHigh)
	}
	if !strings.Contains(f.Evidence, "decrypts every SOPS-encrypted secret") {
		t.Errorf("evidence = %q, want the blast-radius explanation", f.Evidence)
	}
	if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "AGE-SECRET-KEY-1QQQQ") {
		t.Errorf("value preview must be masked, got %v", f.ValuePreview)
	}
}

func TestScanSOPSAgeKeysMacOSApplicationSupportPath(t *testing.T) {
	home := t.TempDir()
	// sops's default on macOS when XDG_CONFIG_HOME is unset — the common
	// case. Missing this path would skip the standard location entirely.
	mkdirAll(t, filepath.Join(home, "Library", "Application Support", "sops", "age"))
	writeFile(t, filepath.Join(home, "Library", "Application Support", "sops", "age", "keys.txt"), fakeAgeKeyFile)

	findings, err := ScanSOPSAgeKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSOPSAgeKeys: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

func TestScanSOPSAgeKeysMultipleKeysOneFile(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "sops", "age"))
	writeFile(t, filepath.Join(home, ".config", "sops", "age", "keys.txt"),
		fakeAgeKeyFile+"AGE-SECRET-KEY-1WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW\n")

	findings, err := ScanSOPSAgeKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSOPSAgeKeys: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (one per key line)", len(findings))
	}
	if *findings[0].KeyName == *findings[1].KeyName {
		t.Errorf("both findings share key name %q; RecordIDs would collide", *findings[0].KeyName)
	}
}

func TestScanSOPSAgeKeysCommentOnlyFileNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "sops", "age"))
	writeFile(t, filepath.Join(home, ".config", "sops", "age", "keys.txt"),
		"# created: 2026-07-01\n# public key: age1qqq\n")

	findings, err := ScanSOPSAgeKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSOPSAgeKeys: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 (public key and dates are not secrets)", len(findings))
	}
}

func TestScanSOPSAgeKeysSkipsFIFO(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, ".config", "sops", "age"))
	path := filepath.Join(home, ".config", "sops", "age", "keys.txt")
	// jit migrate <path> --only sops turns keys.txt into a live-mount FIFO.
	// The scanner must skip it without ever opening it for read — a bare
	// os.Open here blocks forever when no agent is writing. If the guard
	// regresses, this test hangs rather than fails; the go test timeout is
	// what surfaces it.
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	findings, err := ScanSOPSAgeKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanSOPSAgeKeys: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for a FIFO mount, want 0", len(findings))
	}
}
