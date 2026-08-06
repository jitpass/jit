// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// privateKeyPEMHeaders identify a private key by content, not filename —
// real-world review (2026-07-06) showed public CA certificate bundles
// (e.g. rds-global-bundle.pem) sitting alongside genuine private keys under
// names that don't reliably distinguish the two ("key/cert files" as one
// undifferentiated bucket); sniffing the actual PEM header does distinguish
// them, since a certificate's header says "CERTIFICATE," not "PRIVATE KEY."
var privateKeyPEMHeaders = []string{
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"-----BEGIN RSA PRIVATE KEY-----",
	"-----BEGIN EC PRIVATE KEY-----",
	"-----BEGIN DSA PRIVATE KEY-----",
	"-----BEGIN PRIVATE KEY-----",
	"-----BEGIN ENCRYPTED PRIVATE KEY-----",
}

// commonDumpDirs are non-~/.ssh locations checked for stray private keys.
// Deliberately narrow (not a full home-directory walk) — the scan-breadth
// decision made before the private-key scanner was written — since RFC.md §4
// category 5 is scoped to "keys outside expected directories," and these
// are where real-world review showed stray keys actually accumulate.
var commonDumpDirs = []string{"Desktop", "Downloads"}

// maxKeyFileSize skips content-sniffing files larger than this — a real
// private key is at most a few KB; anything bigger sitting in ~/.ssh or
// Downloads is not worth reading in full just to check for a PEM header.
const maxKeyFileSize = 1 << 20 // 1 MiB

func looksLikePrivateKey(content []byte) bool {
	for _, header := range privateKeyPEMHeaders {
		if bytes.Contains(content, []byte(header)) {
			return true
		}
	}
	return false
}

// ScanPrivateKeys implements RFC.md §4 category 5.
func ScanPrivateKeys(cfg Config) ([]Finding, error) {
	var findings []Finding

	sshDir := filepath.Join(cfg.HomeDir, ".ssh")
	sshFindings, err := scanKeyCandidateDir(cfg, sshDir, true)
	if err != nil {
		return nil, err
	}
	findings = append(findings, sshFindings...)

	for _, dirName := range commonDumpDirs {
		dirFindings, err := scanKeyCandidateDir(cfg, filepath.Join(cfg.HomeDir, dirName), false)
		if err != nil {
			return findings, err
		}
		findings = append(findings, dirFindings...)
	}

	return findings, nil
}

func scanKeyCandidateDir(cfg Config, dir string, inSSHDir bool) ([]Finding, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, nil // unreadable (permissions) — skip, don't fail the whole audit
	}

	var findings []Finding
	for _, e := range entries {
		if e.IsDir() || (inSSHDir && strings.HasSuffix(e.Name(), ".pub")) {
			continue
		}
		f, err := inspectPrivateKeyFile(cfg, filepath.Join(dir, e.Name()), inSSHDir)
		if err != nil || f == nil {
			continue
		}
		findings = append(findings, *f)
	}
	return findings, nil
}

// inspectPrivateKeyFile content-sniffs path and, if it looks like a private
// key, builds one Finding covering every applicable issue (no passphrase,
// loose permissions, wrong location) — one combined finding per file, not
// one per issue, since separate findings for the same file would share the
// same record_id (finding_type + file_path; there's no natural per-issue
// key_name for a whole-file finding).
func inspectPrivateKeyFile(cfg Config, path string, inSSHDir bool) (*Finding, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxKeyFileSize {
		return nil, nil
	}

	content, err := readFile(path)
	if err != nil {
		return nil, nil
	}
	if !looksLikePrivateKey(content) {
		return nil, nil
	}

	var issues []string

	if !inSSHDir {
		issues = append(issues, "private key found outside ~/.ssh")
	} else if info.Mode().Perm()&0077 != 0 {
		issues = append(issues, fmt.Sprintf("loose file permissions (mode %o, should be 0600 or stricter)", info.Mode().Perm()))
	}

	_, parseErr := ssh.ParseRawPrivateKey(content)
	var passphraseErr *ssh.PassphraseMissingError
	switch {
	case parseErr == nil:
		// Parsed successfully with no passphrase supplied at all — unencrypted.
		issues = append(issues, "no passphrase set")
	case errors.As(parseErr, &passphraseErr):
		// Encrypted — this is the good case, not an issue.
	default:
		// Unparseable for some other reason (corrupt, unsupported format) —
		// don't claim anything about passphrase status either way.
	}

	if len(issues) == 0 {
		return nil, nil
	}

	f := cfg.baseFinding()
	f.FindingType = FindingTypePrivateKeyRisk
	f.FilePath = path
	f.Severity = SeverityHigh // RFC.md §4 risk table: all three trigger conditions here map to High
	f.Confidence = ConfidenceHigh
	f.Evidence = strings.Join(issues, "; ")
	f.RecordID = RecordID(f.FindingType, f.FilePath, nil)
	return &f, nil
}
