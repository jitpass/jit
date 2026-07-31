// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A single over-long line must never hide the rest of its file.
//
// This is a regression test for a silent false-clean: every scanner here used
// bufio's 64 KiB default token limit, a Scanner that hits that limit STOPS,
// and buildEnvFileFinding turned the resulting bufio.ErrTooLong into "this
// file has no findings" (classifyEnvFile discards the error). A .env whose
// first line was a 66 KB base64 blob — an entirely ordinary thing to find in
// one — therefore vanished from the report, and `jit scan` announced a clean
// machine with exit 0 while a live sk_live_ key sat on line 2.
//
// The sizes here are deliberately spread ACROSS the old cliff (60 KB scanned
// fine, 66 KB reported nothing) and far past the 1 MiB truncation ceiling, so
// this fails if anyone reintroduces a hard stop at any size at all rather than
// just moving the number.
func TestLongLineDoesNotHideLaterSecrets(t *testing.T) {
	var secretLine = "STRIPE_KEY=sk_live_" + strings.Repeat("x", 24) + "\n"

	for _, blob := range []int{
		1_000,      // control: comfortably under every limit
		60_000,     // just under bufio's 64 KiB default
		66_000,     // just over it — the exact case that reported zero
		2_000_000,  // past the 1 MiB truncation ceiling
		20_000_000, // far past it: the tail must still be scanned
	} {
		t.Run(strings.TrimSpace(byteLabel(blob)), func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "project")
			mkdirAll(t, dir)
			envPath := filepath.Join(dir, ".env")
			writeFile(t, envPath, "BLOB="+strings.Repeat("A", blob)+"\n"+secretLine)

			findings, _, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			for _, f := range findings {
				if f.FilePath == envPath {
					return // the file was reported, which is the whole contract
				}
			}
			t.Fatalf("a %d-byte first line hid the whole file: %s is absent from %d findings "+
				"(scan reported a clean machine while it held a live-looking key)", blob, envPath, len(findings))
		})
	}
}

// Line numbering must survive truncation: callers map findings back to line
// numbers and character spans, so an over-long line has to consume exactly one
// line's worth of the count, not zero and not two.
func TestTruncatedLineKeepsLineNumbering(t *testing.T) {
	long := strings.Repeat("A", 2_000_000)
	input := "one\n" + long + "\nthree\nfour\n"

	s := newLineScanner(strings.NewReader(input))
	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}
	if err := lineScanErr(s); err != nil {
		t.Fatalf("lineScanErr: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d lines, want 4 (an over-long line must yield exactly one token): %q", len(got), firstBytes(got))
	}
	if got[0] != "one" || got[2] != "three" || got[3] != "four" {
		t.Errorf("lines around the truncated one are wrong: %q, %q, %q", got[0], got[2], got[3])
	}
	if len(got[1]) != maxContentLineSize {
		t.Errorf("over-long line truncated to %d bytes, want %d", len(got[1]), maxContentLineSize)
	}
}

// A CRLF file must not carry its \r into the parsed line — the scanners match
// values with anchored patterns, and a trailing \r silently breaks them.
func TestLineScannerDropsCR(t *testing.T) {
	s := newLineScanner(strings.NewReader("A=1\r\nB=2\r\n"))
	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}
	if len(got) != 2 || got[0] != "A=1" || got[1] != "B=2" {
		t.Fatalf("CRLF not stripped: %q", got)
	}
}

func byteLabel(n int) string {
	switch {
	case n >= 1_000_000:
		return "MB" + itoa(n/1_000_000)
	case n >= 1_000:
		return "KB" + itoa(n/1_000)
	default:
		return "B" + itoa(n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// firstBytes keeps a failure message readable when one of the lines is
// megabytes long.
func firstBytes(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(l) > 40 {
			l = l[:40] + "…"
		}
		out = append(out, l)
	}
	return out
}

// An unreadable fixed-path store must not take the whole report down with it.
//
// Before this, scan.go returned on the first fixed-scanner error, and several
// fixed scanners error on ordinary conditions — a root-owned ~/.aws/credentials
// left behind by a `sudo` run is the common one. The result was that `jit scan`
// printed nothing at all for the entire machine, so the live key sitting in an
// unrelated project went unmentioned because of a permissions bit two
// directories away.
func TestUnreadableFixedStoreDoesNotAbortScan(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny root, so the failure can't be staged")
	}
	home := t.TempDir()

	mkdirAll(t, filepath.Join(home, ".aws"))
	awsPath := filepath.Join(home, ".aws", "credentials")
	writeFile(t, awsPath, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	if err := os.Chmod(awsPath, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Restore before TempDir cleanup, which cannot remove an unreadable file.
	t.Cleanup(func() { _ = os.Chmod(awsPath, 0o600) })

	mkdirAll(t, filepath.Join(home, "proj"))
	envPath := filepath.Join(home, "proj", ".env")
	writeFile(t, envPath, "STRIPE_KEY=sk_live_"+strings.Repeat("x", 24)+"\n")

	findings, summary, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("one unreadable file aborted the whole scan: %v", err)
	}

	var reported bool
	for _, f := range findings {
		if f.FilePath == envPath {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the readable project secret went unreported because another category failed: %s absent from %d findings", envPath, len(findings))
	}

	// And the gap has to be visible: a partial scan that reports like a
	// complete one is the failure this change exists to avoid, not a fix for it.
	if len(summary.DegradedScanners) == 0 {
		t.Error("scan completed with an unreadable credential store but recorded no degraded scanner, so the report would read as a clean all-clear")
	}
}

// One unreadable credential store must not stop the ELEVEN others in its
// category from being scanned.
//
// scanKnownCredentialFiles ran its sub-scanners in a loop and returned on the
// first error, so a chmod-000 ~/.aws/credentials meant kubeconfig, npmrc,
// cargo, pypirc, MCP tokens, Terraform, Docker, git, GCP, netrc and clisso
// were never looked at at all — the same abort-on-first-failure bug Scan's own
// loop had, one layer down and eleven scanners wide.
func TestUnreadableCredentialStoreDoesNotSkipTheOthers(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny root")
	}
	home := t.TempDir()

	mkdirAll(t, filepath.Join(home, ".aws"))
	awsPath := filepath.Join(home, ".aws", "credentials")
	writeFile(t, awsPath, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
	if err := os.Chmod(awsPath, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(awsPath, 0o600) })

	// A LATER sub-scanner in the same category, with a finding to produce.
	mkdirAll(t, filepath.Join(home, ".kube"))
	writeFile(t, filepath.Join(home, ".kube", "config"),
		"apiVersion: v1\nusers:\n- name: prod\n  user:\n    token: sha256~fixture-token-value\n")

	findings, summary, err := Scan(Config{HomeDir: home, RunID: "test", ScannerVersion: "test"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	var sawKube bool
	for _, f := range findings {
		if strings.Contains(f.FilePath, ".kube") {
			sawKube = true
		}
	}
	if !sawKube {
		t.Errorf("the kubeconfig token went unreported because an EARLIER scanner in the same "+
			"category could not read its file; %d findings total", len(findings))
	}
	if len(summary.DegradedScanners) == 0 {
		t.Error("the unreadable store was not recorded as a degraded scanner")
	}
}
