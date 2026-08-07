// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"encoding/pem"
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
// decision made before task #5 started (ROADMAP.md) — since RFC.md §4
// category 5 is scoped to "keys outside expected directories," and these
// are where real-world review showed stray keys actually accumulate.
var commonDumpDirs = []string{"Desktop", "Downloads"}

// maxKeyFileSize skips content-sniffing files larger than this — a real
// private key is at most a few KB; anything bigger sitting in ~/.ssh or
// Downloads is not worth reading in full just to check for a PEM header.
const maxKeyFileSize = 1 << 20 // 1 MiB

// looksLikePrivateKey reports whether content holds an actual private key,
// rather than merely mentioning one.
//
// A bare `bytes.Contains` on the header was the whole test, and it flagged
// every file that so much as NAMES a PEM header: documentation, test fixtures,
// a scanner's own pattern list. jit reported its own
// internal/audit/tokenpatterns.go as "private key found outside ~/.ssh", which
// is the kind of finding that teaches a user to stop believing the report —
// and this category is one where a false positive is expensive, since the
// advice attached to it is to go delete the file.
//
// A header alone is not a key. A key has a BODY. Two ways of establishing one,
// because either alone has a real gap:
//
//   - encoding/pem, which parses the block properly and so handles the
//     RFC 1421 header lines (Proc-Type/DEK-Info) that an encrypted traditional
//     RSA key carries between its BEGIN line and its base64 — a naive
//     "next line must be base64" test reports those as not-a-key.
//   - a base64 run immediately after the header, for a key embedded in
//     another format, where the newlines are escape sequences rather than
//     real ones (`"-----BEGIN PRIVATE KEY-----\nMIIEv..."`, the shape a GCP
//     service-account JSON uses). pem.Decode rejects those outright.
//
// Erring toward detection deliberately: a missed key is worse than a spurious
// one, so anything with a plausible body is reported.
func looksLikePrivateKey(content []byte) bool {
	for rest := content; ; {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return true
		}
		if len(remainder) >= len(rest) {
			break // no forward progress; refuse to spin
		}
		rest = remainder
	}

	for _, header := range privateKeyPEMHeaders {
		idx := bytes.Index(content, []byte(header))
		if idx < 0 {
			continue
		}
		if hasEncodedKeyBody(content[idx+len(header):]) {
			return true
		}
	}
	return false
}

// minEncodedKeyBody is how many base64 characters must follow a PEM header
// before it counts as a key body. The shortest real key's base64 runs to
// hundreds of characters, so this is far below anything genuine while still
// well above what punctuation-separated source code produces — the string
// after the header in a Go pattern list is a backtick, i.e. a run of zero.
const minEncodedKeyBody = 32

// hasEncodedKeyBody reports whether a base64 run of at least minEncodedKeyBody
// characters begins where a PEM body would, after any real or ESCAPED newline
// (`\n` as two characters is how a key embedded in JSON carries its line
// breaks). Only the immediate position is considered: scanning ahead for
// base64 anywhere later in the file would re-admit the false positives this
// exists to remove, since a long identifier elsewhere in a source file would
// qualify.
func hasEncodedKeyBody(after []byte) bool {
	for len(after) > 0 {
		switch {
		case after[0] == '\n' || after[0] == '\r' || after[0] == ' ' || after[0] == '\t':
			after = after[1:]
		case len(after) >= 2 && after[0] == '\\' && (after[1] == 'n' || after[1] == 'r'):
			after = after[2:]
		default:
			run := 0
			for run < len(after) && isBase64Byte(after[run]) {
				run++
			}
			return run >= minEncodedKeyBody
		}
	}
	return false
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '+' || b == '/' || b == '='
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
