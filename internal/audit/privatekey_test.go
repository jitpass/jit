// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func generateUnencryptedKeyPEM(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	_ = pub
	block, err := ssh.MarshalPrivateKey(priv, "test-key")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func generateEncryptedKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test-key", []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("MarshalPrivateKeyWithPassphrase: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestScanPrivateKeysUnencryptedInSSHDir(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	mkdirAll(t, sshDir)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, generateUnencryptedKeyPEM(t), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityHigh)
	}
	if findings[0].Evidence != "no passphrase set" {
		t.Errorf("evidence = %q, want %q", findings[0].Evidence, "no passphrase set")
	}
}

func TestScanPrivateKeysEncryptedNotFlagged(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	mkdirAll(t, sshDir)

	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, generateEncryptedKeyPEM(t), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings for a passphrase-protected key with correct perms, want 0: %+v", len(findings), findings)
	}
}

func TestScanPrivateKeysLoosePermissions(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	mkdirAll(t, sshDir)

	// Encrypted (so "no passphrase" doesn't also fire) but world-readable.
	keyPath := filepath.Join(sshDir, "id_ed25519")
	if err := os.WriteFile(keyPath, generateEncryptedKeyPEM(t), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Evidence == "" || findings[0].Evidence == "no passphrase set" {
		t.Errorf("evidence = %q, want a loose-permissions message", findings[0].Evidence)
	}
}

func TestScanPrivateKeysOutsideSSHDir(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "Downloads"))

	keyPath := filepath.Join(home, "Downloads", "old-server-access.pem")
	if err := os.WriteFile(keyPath, generateEncryptedKeyPEM(t), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Evidence != "private key found outside ~/.ssh" {
		t.Errorf("evidence = %q, want %q", findings[0].Evidence, "private key found outside ~/.ssh")
	}
}

func TestScanPrivateKeysSkipsPublicKeysAndNonKeyFiles(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	mkdirAll(t, sshDir)

	writeFile(t, filepath.Join(sshDir, "id_ed25519.pub"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... comment\n")
	writeFile(t, filepath.Join(sshDir, "known_hosts"), "github.com ssh-ed25519 AAAAC3...\n")
	writeFile(t, filepath.Join(sshDir, "config"), "Host example\n  User git\n")

	// A CA certificate bundle — real-world review showed these often sit
	// alongside real keys under superficially similar names; content
	// sniffing must not flag it, since its PEM header says CERTIFICATE.
	writeFile(t, filepath.Join(sshDir, "ca-bundle.pem"), "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")

	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0: %+v", len(findings), findings)
	}
}

func TestScanPrivateKeysNoSSHDir(t *testing.T) {
	home := t.TempDir()
	findings, err := ScanPrivateKeys(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanPrivateKeys with no ~/.ssh should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
