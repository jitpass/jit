// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TECH_STACK.md §6 names these three parsers as the fuzz targets, and the
// reason is the provenance of their input rather than the complexity of their
// code: a .env, a shell rc and an .mcp.json all routinely arrive with a cloned
// repo, so their bytes are chosen by whoever wrote that repo and not by the
// person running the scan. The table tests around them cover the shapes we
// thought of. These cover the ones we did not.
//
// Every target asserts the same two properties, because they are the two a
// scanner may never lose whatever it is pointed at:
//
//  1. It returns. A panic or a hang in `jit scan` denies the one command a
//     worried user runs first, and this path has already had to be hardened
//     against long lines, FIFOs and symlinks once.
//  2. It does not leak. Every preview it emits is masked, and nothing it emits
//     can write to the reader's terminal.
//
// The seeds are deliberately not "random bytes": each one is a real file shape
// with one hostile property, so a regression shows up on the seed corpus during
// an ordinary `go test` run rather than only under `-fuzz`.
//
// Two constraints on the credential-shaped seeds, both learned the hard way.
// They have to be long enough to match the real pattern — tokenpatterns.go
// wants sk_live_[A-Za-z0-9]{24,}, and a shorter invented string sails past the
// vendor branch this seed exists to reach, testing nothing. And they have to be
// a value GitHub's own push protection will accept, or the commit carrying them
// cannot be pushed at all. sk_live_4eC39HqLyjWDarjtT1zdp7dc is Stripe's
// published documentation example, already used by envfile_test.go and
// migrate_test.go for exactly this reason: it satisfies the pattern and is
// recognised as a doc sample rather than a leak. Do not swap it for a
// realistic-looking invention.

// assertFindingsSafe is the shared invariant check — the part that makes these
// fuzz targets worth more than a crash detector.
func assertFindingsSafe(t *testing.T, cfg Config, findings []Finding) {
	t.Helper()
	if len(findings) == 0 {
		return
	}

	for _, f := range findings {
		if f.ValuePreview == nil {
			continue
		}
		// An already-masked value is passed through verbatim on purpose
		// (ValueFinding: the file had already hidden it, and re-masking a mask
		// tells the reader nothing).
		if f.AlreadyMasked {
			continue
		}
		// Otherwise the preview must be exactly what MaskValue produces: at
		// most revealPrefixLen leading bytes, then the fixed suffix. Anything
		// longer is a secret jit found and then printed — the single worst
		// thing this scanner could do, and the one a clever input is most
		// likely to reach.
		preview := *f.ValuePreview
		if !strings.HasSuffix(preview, maskSuffix) || len(preview) > revealPrefixLen+len(maskSuffix) {
			t.Errorf("unmasked ValuePreview %q (finding %s, key %q): the scanner printed the value it found",
				preview, f.FindingType, derefKey(f.KeyName))
		}
	}

	// The renderers are where a hostile key name becomes a hostile terminal.
	// display_test.go pins this with hand-built findings on purpose — it is a
	// contract of the RENDERERS, and routing it through a scanner would make
	// it hostage to that scanner's matching heuristics. This is the other
	// direction: real scanner output, arbitrary input, same promise.
	summary := buildScanSummary(cfg, findings, 0, 0)
	renderers := map[string]func(*bytes.Buffer){
		"human":    func(b *bytes.Buffer) { WriteHumanReport(b, findings, summary, "") },
		"markdown": func(b *bytes.Buffer) { WriteMarkdownReport(b, findings, summary) },
		"triage": func(b *bytes.Buffer) {
			WriteTriageReport(b, findings, summary, "", ComputeCoverage("", findings))
		},
	}
	for name, render := range renderers {
		var buf bytes.Buffer
		render(&buf)
		if i := bytes.IndexByte(buf.Bytes(), 0x1b); i >= 0 {
			t.Errorf("%s report carries an ESC from the scanned file at offset %d: %q", name, i, excerpt(buf.String(), i))
		}
		if i := bytes.IndexByte(buf.Bytes(), '\r'); i >= 0 {
			t.Errorf("%s report carries a CR from the scanned file at offset %d: %q", name, i, excerpt(buf.String(), i))
		}
	}
}

func derefKey(k *string) string {
	if k == nil {
		return ""
	}
	return *k
}

// fuzzScanTarget wires a corpus of file bodies to one path-taking scanner.
// One temp directory and one reused filename for the whole run, not per
// iteration: a fuzz worker executes its body sequentially, and a fresh
// t.TempDir() per input would make the filesystem, not the parser, the thing
// under test.
func fuzzScanTarget(f *testing.F, filename string, scan func(cfg Config, path string) ([]Finding, error)) {
	f.Helper()
	home := f.TempDir()
	path := filepath.Join(home, filename)
	cfg := Config{HomeDir: home}

	f.Fuzz(func(t *testing.T, body []byte) {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		findings, err := scan(cfg, path)
		if err != nil {
			// A parse failure is a legitimate outcome for arbitrary bytes —
			// these scanners skip what they cannot read. It must not also
			// produce findings.
			if len(findings) != 0 {
				t.Errorf("scanner returned %d finding(s) alongside error %v", len(findings), err)
			}
			return
		}
		assertFindingsSafe(t, cfg, findings)
	})
}

// FuzzScanEnvFile drives the .env parser. buildEnvFileFinding rather than
// ScanEnvFiles: the discovery walk is a separate concern with its own tests,
// and going straight at the parser is what keeps the fuzzer's throughput in
// the parser instead of in filepath.WalkDir.
func FuzzScanEnvFile(f *testing.F) {
	f.Add([]byte("STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"))
	f.Add([]byte("# DATABASE_URL=postgres://admin:hunter2@10.0.0.1:5432/prod\nAPI_KEY=\n"))
	f.Add([]byte("PASSWORD=****\nTOKEN=<redacted>\n"))
	// The forged-row attack, at the parser's door rather than the renderer's.
	f.Add([]byte("EVIL\x1b[31m\x1b[2K\rFORGED=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n"))
	// A key whose value is exactly at, and just past, the reveal boundary.
	f.Add([]byte("A=abcd\nB=abcde\n"))
	f.Add([]byte("HUGE=" + strings.Repeat("A", 200000) + "\n"))
	f.Add([]byte("KEY=\"quoted\"\nKEY2='single'\nKEY3=\xff\xfe not utf8\n"))
	f.Add([]byte(""))

	fuzzScanTarget(f, ".env", func(cfg Config, path string) ([]Finding, error) {
		finding, ok, err := buildEnvFileFinding(cfg, path, false)
		if err != nil || !ok {
			return nil, err
		}
		return []Finding{finding}, nil
	})
}

// FuzzScanShellConfigFile drives the `export KEY=value` parser over a file
// whose every line is attacker-chosen — a .zshrc fragment sourced from a repo
// is a normal thing for a developer machine to have.
func FuzzScanShellConfigFile(f *testing.F) {
	f.Add([]byte("export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"))
	f.Add([]byte("export PATH=/usr/local/bin:$PATH\nexport EDITOR=vim\n"))
	f.Add([]byte("export EVIL\x1b[2K\rTOKEN='sk_live_4eC39HqLyjWDarjtT1zdp7dc'\n"))
	f.Add([]byte("export AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"))
	f.Add([]byte("export ANTHROPIC_BASE_URL=http://127.0.0.1:4000\n"))
	f.Add([]byte("export SSH_KEY_PATH=~/.ssh/id_ed25519\n"))
	f.Add([]byte("export K=" + strings.Repeat("z", 200000) + "\n"))
	f.Add([]byte("export\nexport =\nexport A\n"))

	fuzzScanTarget(f, ".zshrc", scanShellConfigFile)
}

// FuzzScanMCPConfigFile drives the JSON path. The interesting inputs here are
// not malformed JSON (the scanner declines that by design) but WELL-FORMED
// JSON carrying hostile content: \u001b is a legal thing to put in a JSON
// string, and it arrives as a raw ESC in a server name the report then prints.
func FuzzScanMCPConfigFile(f *testing.F) {
	f.Add([]byte(`{"mcpServers":{"jamf":{"env":{"JAMF_API_KEY":"sk_live_4eC39HqLyjWDarjtT1zdp7dc"}}}}`))
	f.Add([]byte(`{"servers":{"ev\u001b[31m\ril":{"env":{"TOKEN":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}}}}`))
	f.Add([]byte(`{"mcpServers":{"s":{"env":{"URL":"https://example.com/hook"}}}}`))
	f.Add([]byte(`{"mcpServers":{"s":{"env":{"EMPTY":""}}}}`))
	f.Add([]byte(`{"mcpServers":{}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{"mcpServers":{"s":{"env":{"K":"` + strings.Repeat("v", 200000) + `"}}}}`))

	fuzzScanTarget(f, ".mcp.json", scanMCPConfigFile)
}
