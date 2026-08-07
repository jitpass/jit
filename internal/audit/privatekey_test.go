// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
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

// TestLooksLikePrivateKeyNeedsABody is the regression test for jit reporting
// its OWN source as a stray private key.
//
// looksLikePrivateKey was `bytes.Contains(content, header)`, so any file that
// NAMES a PEM header matched: documentation, test fixtures, and — the case
// actually observed — internal/audit/tokenpatterns.go, whose whole job is to
// list those headers as patterns. `jit scan internal/audit/tokenpatterns.go`
// reported "HIGH  private key found outside ~/.ssh" against the detector's own
// pattern list.
//
// A false positive is expensive in this category specifically: the remedy
// attached to it is to go delete the file.
func TestLooksLikePrivateKeyNeedsABody(t *testing.T) {
	realKey := generateUnencryptedKeyPEM(t)

	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"a real key", realKey, true},
		{"a real encrypted key", generateEncryptedKeyPEM(t), true},
		// The exact shape jit flagged in its own tree: the header appears as a
		// regexp literal, with source code — not base64 — after it.
		{
			"a scanner's own pattern list",
			[]byte("{\"RSA Private Key\", regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), true, nil, false},\n"),
			false,
		},
		{
			"prose naming the header",
			[]byte("Files beginning with -----BEGIN OPENSSH PRIVATE KEY----- are refused by the uploader.\n"),
			false,
		},
		{
			"a markdown code fence with an elided body",
			[]byte("```\n-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n```\n"),
			false,
		},
		// A key embedded in JSON carries ESCAPED newlines, which pem.Decode
		// rejects outright — the shape a GCP service-account file uses. Still a
		// real credential, so it must still be found.
		{
			"a key embedded in JSON with escaped newlines",
			[]byte(`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----\n"}`),
			true,
		},
		{"a public key", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@host\n"), false},
		{"empty", nil, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikePrivateKey(c.in); got != c.want {
				t.Errorf("looksLikePrivateKey() = %v, want %v", got, c.want)
			}
		})
	}
}

// And the file itself, so the check is against the real thing rather than my
// paraphrase of it — a rewrite of tokenpatterns.go that reintroduces the shape
// must fail here.
func TestJitsOwnPatternListIsNotAPrivateKey(t *testing.T) {
	content, err := os.ReadFile("tokenpatterns.go")
	if err != nil {
		t.Fatalf("reading tokenpatterns.go: %v", err)
	}
	if !bytes.Contains(content, []byte("-----BEGIN")) {
		t.Skip("tokenpatterns.go no longer lists PEM headers; this guard has nothing to check")
	}
	if looksLikePrivateKey(content) {
		t.Error("jit reports its own token-pattern list as a private key; " +
			"a scanner that flags its own source teaches users to disbelieve the report")
	}
}
