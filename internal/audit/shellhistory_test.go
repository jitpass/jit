// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeHistory(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanShellHistoryFindsTypedCredentials(t *testing.T) {
	home := t.TempDir()
	writeHistory(t, home, ".zsh_history",
		": 1782826755:0;cd ~/work",
		": 1782826756:0;export GITHUB_TOKEN=ghp_"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		": 1782826757:0;git status",
	)
	cfg := Config{HomeDir: home}
	findings, err := ScanShellHistories(cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.FindingType != FindingTypeShellHistorySecret {
		t.Errorf("finding type = %q", f.FindingType)
	}
	if f.Line == nil || *f.Line != 2 {
		t.Errorf("line = %v, want 2 (the physical line to delete)", f.Line)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.ValuePreview == nil || strings.Contains(*f.ValuePreview, "O5p6Q7r8") {
		t.Errorf("value preview leaks the token: %v", f.ValuePreview)
	}
}

// The scan must never print, store, or echo back the command that was typed.
// A history line is far more likely than a config line to carry unrelated
// private context alongside the credential.
func TestScanShellHistoryNeverEchoesTheCommand(t *testing.T) {
	home := t.TempDir()
	writeHistory(t, home, ".zsh_history",
		": 1782826756:0;curl -H 'Authorization: Bearer ghp_"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' https://internal.example.com/patients/12345",
	)
	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	blob := fmt.Sprintf("%+v", findings[0])
	for _, leak := range []string{"patients", "12345", "internal.example.com", "curl"} {
		if strings.Contains(blob, leak) {
			t.Errorf("finding carries command context %q: %s", leak, blob)
		}
	}
}

func TestScanShellHistoryCoversEveryShell(t *testing.T) {
	home := t.TempDir()
	writeHistory(t, home, ".bash_history",
		"#1782826755",
		"export STRIPE_KEY=sk_live_"+"51H8xQ2KZvMnPq7RtY4wU6iO9pL3kJ5hG2f",
	)
	writeHistory(t, home, filepath.Join(".local", "share", "fish", "fish_history"),
		"- cmd: export HF=hf_abcdefghijklmnopqrstuvwx",
		"  when: 1782826755",
	)
	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (bash + fish): %+v", len(findings), findings)
	}
	// bash's "#<epoch>" line is metadata, so the credential is on line 2.
	for _, f := range findings {
		if strings.HasSuffix(f.FilePath, ".bash_history") && (f.Line == nil || *f.Line != 2) {
			t.Errorf("bash line = %v, want 2", f.Line)
		}
	}
}

func TestScanShellHistoryHonorsHISTFILE(t *testing.T) {
	home := t.TempDir()
	custom := writeHistory(t, home, filepath.Join(".cache", "zsh", "history"),
		": 1782826756:0;export HF=hf_abcdefghijklmnopqrstuvwx",
	)
	t.Setenv("HISTFILE", custom)
	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("a relocated history went unscanned: %d findings", len(findings))
	}
}

// Real history is dense with things that look like credentials and are not.
func TestScanShellHistoryQuietOnNearMisses(t *testing.T) {
	lines := []string{
		"git checkout 4f9c2b1e8a3d5f7091b2c4d6e8f0a2b4c6d8e0f2",
		"docker pull ubuntu@sha256:9b8d3f7a2c1e4b5d6f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6",
		"openssl rand -hex 32",
		"curl -H \"Authorization: Bearer $GITHUB_TOKEN\" https://api.github.com/user",
		"export AWS_PROFILE=production",
		"export ANTHROPIC_API_KEY=$(op read op://Private/anthropic/credential)",
		"aws sts assume-role --role-arn arn:aws:iam::123456789012:role/DeployRole",
		"ssh-keygen -t ed25519 -C \"me@example.com\"",
		"npm i --registry https://registry.npmjs.org/ some-package@1.2.3",
		"echo 550e8400-e29b-41d4-a716-446655440000",
		"terraform apply -var=\"db_password=$TF_VAR_db_password\"",
		"grep -rn \"ghp_\" .",
		"export PATH=/opt/homebrew/bin:$PATH",
		"shasum -a 256 dist/jit_darwin_arm64.tar.gz",
		"docker login ghcr.io -u menitasa --password-stdin < token.txt",
		"git remote set-url origin https://github.com/jitpass/jit.git",
		"rg -n 'password' --glob '!node_modules'",
		"az login --service-principal -u 00000000-0000-0000-0000-000000000000 -p $AZ_SECRET",
	}
	home := t.TempDir()
	hist := make([]string, 0, len(lines))
	for i, l := range lines {
		hist = append(hist, fmt.Sprintf(": 17828267%02d:0;%s", i, l))
	}
	writeHistory(t, home, ".zsh_history", hist...)

	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Errorf("false positive: %s at line %v (%s)", *f.KeyName, f.Line, f.Evidence)
	}
}

// A password that is a shell expansion exposes nothing: the secret lives
// wherever the expansion reads it from. This is the dominant form in history.
func TestConnectionStringIgnoresShellExpansion(t *testing.T) {
	interpolated := []string{
		`psql "postgres://app:$PGPASSWORD@db.internal:5432/app"`,
		`psql "postgres://app:${PGPASSWORD}@db.internal:5432/app"`,
		`mongosh "mongodb://admin:$(op read op://vault/mongo/pw)@cluster0.example.com"`,
		"redis-cli -u \"redis://default:`cat /run/pw`@cache.internal:6379\"",
		`export DATABASE_URL="postgresql+asyncpg://svc:${DB_PASS}@rds.internal/app"`,
		`amqps://guest:$RABBIT_PW@rabbit.internal:5671`,
		`curl "https://user:$API_PASS@api.internal/v1/health"`,
	}
	for _, line := range interpolated {
		if got := matchLineTokens(line); len(got) > 0 {
			t.Errorf("reported an interpolated password as a credential: %q -> %q", line, got[0].Value)
		}
	}

	// ...while a literal password in the same shape is still a real finding.
	literal := []string{
		`psql "postgres://app:s3cr3tPassw0rd@db.internal:5432/app"`,
		`export DATABASE_URL="postgresql://svc:hunter2xyz@rds.internal/app"`,
	}
	for _, line := range literal {
		if got := matchLineTokens(line); len(got) == 0 {
			t.Errorf("missed a real embedded credential: %q", line)
		}
	}
}

// The prefilter is an optimization, so its only real obligation is that it
// never hides a match. Extend `samples` when a pattern is added to
// knownTokenPatterns.
func TestHistoryPrefilterNeverDropsAMatch(t *testing.T) {
	samples := []string{
		"ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		"gith" + "ub_pat_11ABCDEFG0abcdefghijkl_MNOPQRST",
		"glpa" + "t-AbCdEfGhIjKlMnOpQrSt",
		"AKIA" + "IOSFODNN7EXAMPLZ",
		"ASIA" + "IOSFODNN7EXAMPLZ",
		"dop_" + "v1_0123456789abcdef0123456789abcdef0123456789abcdef",
		"npm_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		"pypi" + "-AgEIcHlwaS5vcmcCJDAwMDAwMDAwLTAwMDA",
		"sk-a" + "nt-api03-AbCdEfGhIjKlMnOpQrStUv",
		"sk-a" + "nt-adminAbCdEfGhIjKlMnOpQrStUv",
		"sk-p" + "roj-AbCdEfGhIjKlMnOpQrStUv",
		"sk-s" + "vcacct-AbCdEfGhIjKlMnOpQrStUv",
		"sk-a" + "dmin-AbCdEfGhIjKlMnOpQrStUv",
		"sk-A" + "bCdEfGhIjKlMnOpQrStUv",
		"hf_a" + "bcdefghijklmnopqrstuvwx",
		"sk_l" + "ive_51H8xQ2KZvMnPq7RtY4wU6iO9",
		"sk_t" + "est_51H8xQ2KZvMnPq7RtY4wU6iO9",
		"rk_l" + "ive_51H8xQ2KZvMnPq7RtY4wU6iO9",
		"xoxb" + "-1234567890-AbCdEfGhIj",
		"xoxp" + "-1234567890-AbCdEfGhIj",
		"xapp" + "-1-A012345678-AbCdEfGhIj",
		"xwfp" + "-1-A012345678-AbCdEfGhIj",
		"shpa" + "t_abcdefghijklmnopqrstuvwx",
		"AC01" + "23456789abcdef0123456789abcdef",
		"SG.AbCdEfGhIj.KlMnOpQrStUv",
		"ntn_" + "abcdefghijklmnopqrstuvwx",
		"secr" + "et_0123456789abcdefghijklmnopqrstuvwxyzABCD",
		"AIza" + "SyC1234567890abcdefghijklmnopqrstuv",
		"whse" + "c_AbCdEfGhIjKlMnOpQrStUvWx",
		"sb_s" + "ecret_AbCdEfGhIjKlMnOpQrStUv",
		"glsa" + "_AbCdEfGhIjKlMnOpQrStUv_abcdef12",
		"dp.st.AbCdEfGhIjKlMnOpQrStUv",
		"hvs." + "AbCdEfGhIjKlMnOpQrStUvWxYz01",
		"AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTU",
		"eyJh" + "bGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AbCdEfGhIj",
		"eyJa.b.c",
		"postgres://app:s3cr3tPassw0rd@db.internal:5432/app",
		"scanner_user:hunter2x@db.example.com/postgres",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
	}
	for _, s := range samples {
		matched := false
		for _, tp := range knownTokenPatterns {
			if tp.pattern.MatchString(s) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("sample matches no pattern at all, so it cannot guard the prefilter: %q", s)
			continue
		}
		if !historyLineMayHoldToken(s) {
			t.Errorf("PREFILTER DROPS A REAL MATCH: %q", s)
		}
	}
}

// Every pattern in the list must be represented above, or a pattern added
// later could silently sit behind a prefilter that rejects it.
func TestHistoryPrefilterGuardsEveryPattern(t *testing.T) {
	samples := []string{
		"ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "gith" + "ub_pat_11ABCDEFG0abcdefghijkl_MNOPQRST",
		"gho_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "ghs_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		"ghu_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "ghr_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
		"glpa" + "t-AbCdEfGhIjKlMnOpQrSt", "gldt" + "-AbCdEfGhIjKlMnOpQrSt", "glrt" + "-AbCdEfGhIjKlMnOpQrSt",
		"glrt" + "r-AbCdEfGhIjKlMnOpQrSt", "glcb" + "t-AbCdEfGhIjKlMnOpQrSt", "glpt" + "t-AbCdEfGhIjKlMnOpQrSt",
		"gloa" + "s-AbCdEfGhIjKlMnOpQrSt", "glag" + "ent-AbCdEfGhIjKlMnOpQrSt", "glft" + "-AbCdEfGhIjKlMnOpQrSt",
		"AKIA" + "IOSFODNN7EXAMPLZ", "dop_" + "v1_0123456789abcdef0123456789abcdef0123456789abcdef",
		"npm_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789", "pypi" + "-AgEIcHlwaS5vcmcCJDAwMDAwMDAwLTAwMDA",
		"sk-a" + "nt-api03-AbCdEfGhIjKlMnOpQrStUv", "sk-a" + "nt-adminAbCdEfGhIjKlMnOpQrStUv",
		"sk-p" + "roj-AbCdEfGhIjKlMnOpQrStUv", "sk-s" + "vcacct-AbCdEfGhIjKlMnOpQrStUv",
		"sk-a" + "dmin-AbCdEfGhIjKlMnOpQrStUv", "sk-A" + "bCdEfGhIjKlMnOpQrStUv",
		"hf_a" + "bcdefghijklmnopqrstuvwx", "sk_l" + "ive_51H8xQ2KZvMnPq7RtY4wU6iO9",
		"sk_t" + "est_51H8xQ2KZvMnPq7RtY4wU6iO9", "rk_l" + "ive_51H8xQ2KZvMnPq7RtY4wU6iO9",
		"xoxb" + "-1234567890-AbCdEfGhIj", "xoxp" + "-1234567890-AbCdEfGhIj",
		"shpa" + "t_abcdefghijklmnopqrstuvwx", "AC01" + "23456789abcdef0123456789abcdef",
		"SG.AbCdEfGhIj.KlMnOpQrStUv", "ntn_" + "abcdefghijklmnopqrstuvwx",
		"secr" + "et_0123456789abcdefghijklmnopqrstuvwxyzABCD",
		"AIza" + "SyC1234567890abcdefghijklmnopqrstuv", "xapp" + "-1-A012345678-AbCdEfGhIj",
		"xwfp" + "-1-A012345678-AbCdEfGhIj", "whse" + "c_AbCdEfGhIjKlMnOpQrStUvWx",
		"sb_s" + "ecret_AbCdEfGhIjKlMnOpQrStUv", "glsa" + "_AbCdEfGhIjKlMnOpQrStUv_abcdef12",
		"dp.st.AbCdEfGhIjKlMnOpQrStUv", "hvs." + "AbCdEfGhIjKlMnOpQrStUvWxYz01",
		"hvb." + "AbCdEfGhIjKlMnOpQrStUvWxYz01", "hvr." + "AbCdEfGhIjKlMnOpQrStUvWxYz01",
		"AGE-SECRET-KEY-1ABCDEFGHIJKLMNOPQRSTU",
		"AGE-SECRET-KEY-PQ-1ABCDEFGHIJKLMNOPQRSTU",
		"eyJh" + "bGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.AbCdEfGhIj",
		"-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
		"postgres://app:s3cr3tPassw0rd@db.internal:5432/app",
		"scanner_user:hunter2x@db.example.com/postgres",
		"crsr" + "_AbCdEfGhIjKl", "tvly" + "-AbCdEfGhIjKl",
		"xoxa" + "-1234567890-AbCdEfGhIj", "xoxr" + "-1234567890-AbCdEfGhIj",
		"eyJa.b.c", // degenerate JWT: legal for the pattern, no long run
	}
	covered := map[string]bool{}
	for _, s := range samples {
		if !historyLineMayHoldToken(s) {
			t.Errorf("PREFILTER DROPS A REAL MATCH: %q", s)
		}
		for _, tp := range knownTokenPatterns {
			if tp.pattern.MatchString(s) {
				covered[tp.vendor] = true
			}
		}
	}
	for _, tp := range knownTokenPatterns {
		if !covered[tp.vendor] {
			t.Errorf("pattern %q has no sample guarding the prefilter; add one", tp.vendor)
		}
	}
}

func TestHistoryCommandStripsMetadata(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		isText bool
	}{
		{": 1782826755:0;git status", "git status", true},
		{": 1782826755:12;go test ./...", "go test ./...", true},
		{"git status", "git status", true},
		{"#1782826755", "", false},
		{"#!/bin/sh", "#!/bin/sh", true},
		{"# a real comment", "# a real comment", true},
		{"- cmd: git status", "git status", true},
		{"  when: 1782826755", "", false},
		{"  paths:", "", false},
		{": not-a-timestamp;x", ": not-a-timestamp;x", true},
		{"echo ': 1:0;fake'", "echo ': 1:0;fake'", true},
	}
	for _, c := range cases {
		got, off, ok := historyCommand(c.in)
		if ok != c.isText || (ok && got != c.want) {
			t.Errorf("historyCommand(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.isText)
		}
		// The offset must relocate the command back into the raw line exactly:
		// it is what migrate's redaction splices with, so an off-by-one here is
		// a corrupted history file there.
		if ok && c.in[off:off+len(got)] != got {
			t.Errorf("historyCommand(%q) offset %d does not point at the command text", c.in, off)
		}
	}
}

// HistoryLineTokens must return spans addressed into the RAW line, so a caller
// splicing file bytes cuts the credential and only the credential — on a zsh
// extended_history line a command-relative span would land inside the
// timestamp prefix instead.
func TestHistoryLineTokensSpansAddressTheRawLine(t *testing.T) {
	// Exactly 36 base62 chars after the prefix, mixed so isPlaceholderToken
	// never rejects it.
	token := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	cases := []string{
		": 1782826755:0;git clone https://x:" + token + "@github.com/o/r.git",
		"- cmd: curl -H 'Authorization: token " + token + "' https://api.github.com",
		"export GITHUB_TOKEN=" + token,
	}
	for _, line := range cases {
		toks := HistoryLineTokens(line)
		if len(toks) == 0 {
			t.Errorf("HistoryLineTokens(%q) found nothing", line)
			continue
		}
		found := false
		for _, tk := range toks {
			if line[tk.Start:tk.End] == tk.Value {
				if tk.Value == token {
					found = true
				}
				continue
			}
			t.Errorf("span [%d:%d) of %q yields %q, want %q", tk.Start, tk.End, line, line[tk.Start:tk.End], tk.Value)
		}
		if !found {
			t.Errorf("HistoryLineTokens(%q) never matched the planted token", line)
		}
	}
}

// Metadata-only lines must yield nothing, and a redaction marker must never
// re-detect as a credential — or migrate would loop and scan would re-flag
// the file it just cleaned.
func TestHistoryLineTokensSkipsMetadataAndMarkers(t *testing.T) {
	for _, line := range []string{
		"  when: 1782826755",
		"#1782826755",
		": 1782826755:0;curl -H 'Authorization: token <jit:redacted:GITHUB_PERSONAL_ACCESS_TOKEN>'",
		// The marker in userinfo position — the shape that actually re-matched
		// (as a scheme-less DB connection string) before the bracket-
		// placeholder exclusion existed.
		": 1782826756:0;git clone https://x:<jit:redacted:GITHUB_PERSONAL_ACCESS_TOKEN>@github.com/o/r.git",
		"psql postgres://app:<jit:redacted:DATABASE_PASSWORD>@db.internal:5432/app",
		// And the README placeholder convention the same exclusion covers.
		"psql postgres://app:<password>@db.internal:5432/app",
	} {
		if toks := HistoryLineTokens(line); len(toks) != 0 {
			t.Errorf("HistoryLineTokens(%q) = %d tokens, want none", line, len(toks))
		}
	}
}

// The marker and placeholder exclusions must not cost a real credential. A
// password containing an angle bracket is unusual but legal and gets pasted
// unencoded at a shell prompt all the time; a blanket "reject any span with
// a bracket" rule silently dropped it, which is a false negative on a live
// secret — the one error this scanner weighs as worse than an extra finding.
func TestAngleBracketExclusionKeepsRealPasswords(t *testing.T) {
	for _, line := range []string{
		"psql postgres://app:pa<ss>word@db.example.com/app",
		"psql postgres://app:secret<1@db.example.com/app",
	} {
		if toks := HistoryLineTokens(line); len(toks) == 0 {
			t.Errorf("HistoryLineTokens(%q) found nothing; a real credential was suppressed", line)
		}
	}
}

// The zsh timestamp prefix must never reach the patterns: it is 10 digits on
// every single line, which is exactly the shape the prefilter keys on.
func TestHistoryTimestampDoesNotDefeatThePrefilter(t *testing.T) {
	raw := ": 1782826755:0;git status"
	if !historyLineMayHoldToken(raw) {
		t.Fatal("precondition: the raw line should look like a candidate")
	}
	cmd, _, ok := historyCommand(raw)
	if !ok {
		t.Fatal("timestamped line should still carry a command")
	}
	if historyLineMayHoldToken(cmd) {
		t.Errorf("prefilter still admits %q after parsing; the timestamp is leaking through", cmd)
	}
}

// A NAMED history file jit cannot read must degrade the scan, never report
// clean. The machine-wide route always did; the targeted route used to drop
// the error, so `jit scan ~/.zsh_history` on an unreadable file printed
// "CLEAN — exposure 0/100" and exited 0.
func TestTargetedScanReportsAnUnreadableHistoryFile(t *testing.T) {
	home := t.TempDir()
	path := writeHistory(t, home, ".zsh_history", ": 1782826756:0;export HF=hf_abcdefghijklmnopqrstuvwx")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skip("cannot make a file unreadable here")
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	findings, failures := scanTargetFile(Config{HomeDir: home}, path)
	if len(findings) != 0 {
		t.Errorf("got findings from an unreadable file: %+v", findings)
	}
	if len(failures) == 0 {
		t.Fatal("an unreadable named history file reported no failure; the scan would render as CLEAN")
	}
	if failures[0].Scanner != "shell history" {
		t.Errorf("failure scanner = %q, want \"shell history\"", failures[0].Scanner)
	}

	// And it must reach the summary, which is what the report renders from.
	_, summary, err := TargetedScan(Config{HomeDir: home}, []string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.DegradedScanners) == 0 {
		t.Error("TargetedScan summary has no degraded scanners for an unreadable target")
	}
}

// A history file past the sanity bound must be REPORTED, never silently
// skipped: history is the file most likely to grow past any ceiling, and
// "produced no findings" would read as "clean".
func TestScanShellHistoryReportsOversizeRatherThanSkipping(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".zsh_history")
	f, err := os.Create(path) // #nosec G304 -- test fixture in t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxHistoryScanSize + 1); err != nil {
		f.Close()
		t.Skipf("cannot create a sparse file this large here: %v", err)
	}
	f.Close()

	_, err = ScanShellHistories(Config{HomeDir: home})
	if err == nil {
		t.Fatal("an oversize history was skipped silently; it must surface as a degraded scanner")
	}
	if !strings.Contains(err.Error(), "not read") {
		t.Errorf("error does not say the file went unread: %v", err)
	}
}

// An ordinary history finding is migratable — `jit migrate <historyfile>`
// redacts each occurrence in place — but a production-flagged one stays
// manual: clearing the recorded copy does not un-expose a production
// credential, and offering a command as THE fix would overstate it.
func TestShellHistoryRemedySplitsOnProductionFlag(t *testing.T) {
	home := t.TempDir()
	findings := []Finding{
		{
			FindingType: FindingTypeShellHistorySecret,
			FilePath:    filepath.Join(home, ".zsh_history"),
			Severity:    SeverityHigh,
		},
		{
			FindingType:              FindingTypeShellHistorySecret,
			FilePath:                 filepath.Join(home, ".bash_history"),
			Severity:                 SeverityHigh,
			ProductionIndicatorMatch: true,
		},
	}
	annotateRemedies(findings, home)
	if findings[0].Remedy != RemedyMigrate {
		t.Errorf("ordinary history remedy = %q, want %q", findings[0].Remedy, RemedyMigrate)
	}
	if !strings.Contains(findings[0].FixCommand, "migrate") {
		t.Errorf("ordinary history finding must offer the migrate command, got %q", findings[0].FixCommand)
	}
	if findings[1].Remedy != RemedyManual {
		t.Errorf("production history remedy = %q, want %q", findings[1].Remedy, RemedyManual)
	}
	if findings[1].FixCommand != "" {
		t.Errorf("a production history finding must not offer a fix command, got %q", findings[1].FixCommand)
	}
}

// A token in BOTH a migratable config and a MANUAL (production-flagged)
// history line is one secret the recommended command cannot fully protect:
// vaulting the config leaves that history line readable. An ordinary history
// copy no longer pins its group — redaction rewrites it like any other file.
func TestCoverageDoesNotClaimManualHistorySecretsAsMigratable(t *testing.T) {
	shared := "cause-abc"
	findings := []Finding{
		{
			FindingType: FindingTypeMCPEmbeddedSecret,
			FilePath:    "/home/u/.mcp.json",
			Severity:    SeverityHigh,
			Remedy:      RemedyMigrate,
			CauseGroup:  shared,
			RecordID:    "r1",
		},
		{
			FindingType: FindingTypeShellHistorySecret,
			FilePath:    "/home/u/.zsh_history",
			Severity:    SeverityHigh,
			Remedy:      RemedyManual,
			CauseGroup:  shared,
			RecordID:    "r2",
		},
	}
	cov := ComputeCoverage("", findings)
	if cov.Exposed != 1 {
		t.Errorf("Exposed = %d, want 1 (one secret in two places)", cov.Exposed)
	}
	if cov.Migratable != 0 {
		t.Errorf("Migratable = %d, want 0: the recommended command will not rewrite the manual history copy", cov.Migratable)
	}
	if got := cov.manualRemainder(); got != 1 {
		t.Errorf("manualRemainder = %d, want 1", got)
	}

	// Flip the history copy to the ordinary migratable remedy: the same
	// group now counts, because bare `jit migrate` redacts that copy too.
	findings[1].Remedy = RemedyMigrate
	cov = ComputeCoverage("", findings)
	if cov.Migratable != 1 {
		t.Errorf("Migratable = %d, want 1 once the history copy is redactable", cov.Migratable)
	}
}

// One secret found by two scanners that name it differently is still one
// secret. Before cause groups keyed on the value alone, a token in ~/.mcp.json
// ("internal-tool/GITHUB_TOKEN") and in history ("GitHub Personal Access
// Token") reported as two, so "YOUR SECRETS" over-counted by one per pasted
// token — which shell history makes the common case rather than a corner one.
func TestCauseGroupMergesAcrossScannerKeyNames(t *testing.T) {
	cfg := Config{HomeDir: "/home/u"}
	token := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	findings := []Finding{
		cfg.ValueFinding(ValueFindingParams{
			FindingType: FindingTypeMCPEmbeddedSecret,
			FilePath:    "/home/u/.mcp.json",
			KeyName:     "internal-tool/GITHUB_TOKEN",
			RawValue:    token,
		}),
		cfg.ValueFinding(ValueFindingParams{
			FindingType: FindingTypeShellHistorySecret,
			FilePath:    "/home/u/.zsh_history",
			KeyName:     "GitHub Personal Access Token",
			RawValue:    token,
		}),
	}
	annotateCauseGroups(findings)
	if findings[0].CauseGroup != findings[1].CauseGroup {
		t.Errorf("one token under two key names produced two cause groups: %q vs %q",
			findings[0].CauseGroup, findings[1].CauseGroup)
	}

	// ...but two DIFFERENT tokens must stay apart, even sharing a preview
	// (every GitHub token previews as "ghp_**********").
	other := cfg.ValueFinding(ValueFindingParams{
		FindingType: FindingTypeShellHistorySecret,
		FilePath:    "/home/u/.zsh_history",
		KeyName:     "GitHub Personal Access Token",
		RawValue:    "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2",
	})
	pair := []Finding{findings[0], other}
	annotateCauseGroups(pair)
	if pair[0].CauseGroup == pair[1].CauseGroup {
		t.Error("two different tokens collapsed into one cause group")
	}
}

// The report's two percentage claims must never sum past 100.
func TestCoveragePercentagesAlwaysSumTo100(t *testing.T) {
	cases := []Coverage{
		{Protected: 0, Exposed: 8, Migratable: 6},
		{Protected: 3, Exposed: 9, Migratable: 0},
		{Protected: 5, Exposed: 0, Migratable: 0},
		{Protected: 1, Exposed: 1, Migratable: 1},
		{Protected: 0, Exposed: 1, Migratable: 0},
		{Protected: 12, Exposed: 37, Migratable: 20},
	}
	for _, c := range cases {
		if c.Total() == 0 {
			continue
		}
		gain := c.PercentAfterMigrate() - c.Percent()
		remainder := pctOf(c.manualRemainder(), c.Total())
		if sum := c.Percent() + gain + remainder; sum > 100 {
			t.Errorf("%+v: %d%% + %d%% + %d%% = %d%%, over 100", c, c.Percent(), gain, remainder, sum)
		}
	}
}

func TestShellHistoryTriageCopy(t *testing.T) {
	home := "/home/u"
	line := 4821
	vendor := "GitHub Personal Access Token"
	f := Finding{
		FindingType: FindingTypeShellHistorySecret,
		FilePath:    filepath.Join(home, ".zsh_history"),
		Line:        &line,
		KeyName:     &vendor,
		Severity:    SeverityHigh,
		Remedy:      RemedyManual,
		CauseGroup:  "g1",
	}
	if got := manualNoun(f); got != "A GitHub Personal Access Token in shell history" {
		t.Errorf("noun = %q", got)
	}
	if got := manualDetail([]string{f.FilePath}, f, home); got != "~/.zsh_history:4821" {
		t.Errorf("detail = %q, want the line number", got)
	}
	action := manualAction(f, manualContext{secrets: 1, copies: 1}, home)
	if strings.Contains(action, "jit migrate") {
		t.Errorf("action offers a jit command that cannot work: %q", action)
	}
	for _, want := range []string{"rotate it", "close other shells first"} {
		if !strings.Contains(action, want) {
			t.Errorf("action %q is missing %q", action, want)
		}
	}
	plural := manualAction(f, manualContext{secrets: 2, copies: 1}, home)
	if !strings.Contains(plural, "rotate them") || !strings.Contains(plural, "the lines") {
		t.Errorf("plural action reads wrong: %q", plural)
	}
}

// A production-flagged history secret still gets the history instruction:
// "delete every copy" is wrong advice for a file with one copy.
func TestShellHistoryActionBeatsTheProductionBranch(t *testing.T) {
	vendor := "GitHub Personal Access Token"
	f := Finding{
		FindingType:              FindingTypeShellHistorySecret,
		FilePath:                 "/home/u/.zsh_history",
		KeyName:                  &vendor,
		ProductionIndicatorMatch: true,
		Severity:                 SeverityCritical,
	}
	action := manualAction(f, manualContext{secrets: 1, copies: 1, production: true}, "/home/u")
	if !strings.Contains(action, "close other shells first") {
		t.Errorf("production branch swallowed the history advice: %q", action)
	}
}

func TestShellHistoryIsInEveryTypeList(t *testing.T) {
	found := false
	for _, ft := range AllFindingTypes {
		if ft == FindingTypeShellHistorySecret {
			found = true
		}
	}
	if !found {
		t.Error("FindingTypeShellHistorySecret missing from AllFindingTypes")
	}
	if findingTypeLabels[FindingTypeShellHistorySecret] == "" {
		t.Error("FindingTypeShellHistorySecret has no report label")
	}
}

func TestTargetedScanRoutesNamedHistoryFile(t *testing.T) {
	home := t.TempDir()
	path := writeHistory(t, home, ".zsh_history",
		": 1782826755:0;cd ~/work",
		": 1782826756:0;export HF=hf_abcdefghijklmnopqrstuvwx",
	)
	findings, failures := scanTargetFile(Config{HomeDir: home}, path)
	if len(failures) != 0 {
		t.Errorf("readable file reported failures: %+v", failures)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].FindingType != FindingTypeShellHistorySecret {
		t.Errorf("named history file was scanned as %q, not by its own scanner", findings[0].FindingType)
	}
	if findings[0].Line == nil || *findings[0].Line != 2 {
		t.Errorf("line = %v, want 2", findings[0].Line)
	}
}

// One vendor is reported once per file, with the count in the evidence.
func TestScanShellHistoryCollapsesRepeatVendors(t *testing.T) {
	home := t.TempDir()
	writeHistory(t, home, ".zsh_history",
		": 1782826755:0;export A=hf_abcdefghijklmnopqrstuvwx",
		": 1782826756:0;git status",
		": 1782826757:0;export B=hf_zyxwvutsrqponmlkjihgfed",
	)
	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 collapsed by vendor", len(findings))
	}
	if findings[0].Line == nil || *findings[0].Line != 1 {
		t.Errorf("line = %v, want the first occurrence", findings[0].Line)
	}
	if !strings.Contains(findings[0].Evidence, "2 occurrences") {
		t.Errorf("evidence hides the repeat count: %q", findings[0].Evidence)
	}
}

// Scan is read-only in every mode.
func TestScanShellHistoryDoesNotModifyTheFile(t *testing.T) {
	home := t.TempDir()
	path := writeHistory(t, home, ".zsh_history",
		": 1782826756:0;export GITHUB_TOKEN=ghp_"+"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
	)
	before, err := os.ReadFile(path) // #nosec G304 -- test fixture in t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ScanShellHistories(Config{HomeDir: home}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- test fixture in t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("jit scan modified a history file; scan is read-only in every mode")
	}
}

// When every migratable secret also sits in a MANUAL history copy (a
// production-flagged credential — an ordinary history copy is redactable now
// and gains coverage like any other file), migrate gains no score. The block
// must still recommend the work without printing "0 secrets in 1 file,
// 0% → 0%", which reads as a broken report. Findings are hand-built: the
// state needs a production-flagged history line sharing its exact value with
// a migratable config copy, which real scanners produce only for span-sized
// values (a conn string with "prod" in its userinfo) — the rendering under
// that state is what this test pins, and the coverage arithmetic behind it
// is unit-tested in TestCoverageDoesNotClaimManualHistorySecretsAsMigratable.
func TestTriageZeroGainBlockStaysHonest(t *testing.T) {
	home := t.TempDir()
	key := "t/DATABASE_URL"
	vendor := "Database connection string with embedded credentials"
	preview := "post**********"
	line := 3
	findings := []Finding{
		{
			FindingType:  FindingTypeMCPEmbeddedSecret,
			FilePath:     filepath.Join(home, ".mcp.json"),
			KeyName:      &key,
			ValuePreview: &preview,
			Severity:     SeverityHigh,
			Remedy:       RemedyMigrate,
			FixCommand:   "jit migrate ~/.mcp.json",
			CauseGroup:   "cause-shared",
			RecordID:     "r1",
		},
		{
			FindingType:              FindingTypeShellHistorySecret,
			FilePath:                 filepath.Join(home, ".zsh_history"),
			KeyName:                  &vendor,
			ValuePreview:             &preview,
			Line:                     &line,
			Severity:                 SeverityHigh,
			ProductionIndicatorMatch: true,
			Remedy:                   RemedyManual,
			CauseGroup:               "cause-shared",
			RecordID:                 "r2",
		},
	}
	cov := ComputeCoverage("", findings)
	if cov.Total() != 1 || cov.Migratable != 0 {
		t.Fatalf("precondition: cov = %+v, want one secret, none migratable", cov)
	}
	summary := ScanSummary{SecretsTotal: cov.Total(), SecretsProtected: cov.Protected, SecretsMigratable: cov.Migratable}

	var buf strings.Builder
	WriteTriageReport(&buf, findings, summary, home, cov)
	out := buf.String()
	if strings.Contains(out, "0 secrets in") || strings.Contains(out, "0% → 0%") {
		t.Errorf("zero-gain block still prints broken arithmetic:\n%s", out)
	}
	if !strings.Contains(out, "jit migrate") {
		t.Errorf("zero-gain block dropped the recommendation entirely:\n%s", out)
	}
	if !strings.Contains(out, "will not rewrite") {
		t.Errorf("zero-gain block does not explain why the score is unmoved:\n%s", out)
	}
}

// The flip side of the zero-gain case: an ORDINARY (non-production) token in
// both a config file and history is fully protectable now — the history copy
// is redactable, so the group counts and the report promises the gain.
func TestTriageCountsOrdinaryHistoryCopiesAsMigratable(t *testing.T) {
	home := t.TempDir()
	token := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	if err := os.WriteFile(filepath.Join(home, ".mcp.json"),
		[]byte(`{"mcpServers":{"t":{"env":{"GITHUB_TOKEN":"`+token+`"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeHistory(t, home, ".zsh_history", ": 1782826801:0;export GITHUB_TOKEN="+token)

	findings, summary, err := Scan(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if summary.SecretsTotal != 1 {
		t.Errorf("SecretsTotal = %d, want 1 (one token in two places)", summary.SecretsTotal)
	}
	if summary.SecretsMigratable != 1 {
		t.Errorf("SecretsMigratable = %d, want 1: both copies are rewritable", summary.SecretsMigratable)
	}
	for _, f := range findings {
		if f.FindingType == FindingTypeShellHistorySecret && !strings.Contains(f.FixCommand, "migrate") {
			t.Errorf("history finding's FixCommand = %q, want the migrate command", f.FixCommand)
		}
	}
}

// Private key material typed at the prompt used to be invisible: the history
// matcher ceded "… Private Key" vendors to ScanPrivateKeys, which only walks
// key FILES and never sees a history line. The prefilter admitted the line,
// the guard forked for it, and the answer was always "clean".
func TestScanShellHistoryFindsPrivateKeyMaterial(t *testing.T) {
	home := t.TempDir()
	writeHistory(t, home, ".zsh_history",
		": 1782826755:0;git status",
		`: 1782826756:0;cat > deploy_key <<'EOF'`,
		": 1782826757:0;-----BEGIN OPENSSH PRIVATE KEY-----",
	)
	findings, err := ScanShellHistories(Config{HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.FindingType != FindingTypeShellHistorySecret {
		t.Errorf("finding type = %q", f.FindingType)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical (a key cannot be rotated at a provider)", f.Severity)
	}
	if f.Remedy != RemedyManual {
		t.Errorf("remedy = %q, want manual: redacting the header would leave the key body behind", f.Remedy)
	}
	if f.FixCommand != "" {
		t.Errorf("offered a fix command for private key material: %q", f.FixCommand)
	}
	// No value preview: the header is public knowledge, and hashing it would
	// fold every key of that type on the machine into one cause group.
	if f.ValuePreview != nil {
		t.Errorf("private-key finding carries a value preview: %v", f.ValuePreview)
	}
	if f.CauseGroup != "" {
		t.Errorf("private-key finding got a cause group keyed on a shared header: %q", f.CauseGroup)
	}
}

// The guard's whole job is prevention, and blocking a pasted key from ever
// reaching the file involves no rewrite — so unlike migrate, it must fire.
func TestHistoryLineTokensReportsPrivateKeyHeaders(t *testing.T) {
	line := `: 1782826756:0;echo "-----BEGIN OPENSSH PRIVATE KEY-----" >> deploy_key`
	toks := HistoryLineTokens(line)
	if len(toks) == 0 {
		t.Fatal("no token: the guard would let a pasted private key be recorded")
	}
	if !IsPrivateKeyVendor(toks[0].Vendor) {
		t.Errorf("vendor = %q, want a private-key vendor", toks[0].Vendor)
	}
	if line[toks[0].Start:toks[0].End] != toks[0].Value {
		t.Error("span does not address the raw line")
	}
}

// The prevention offer belongs where the user LEARNS they have this problem.
// It used to appear only after a real migrate, which meant the people with
// the most to gain — anyone whose history is still clean — never saw it.
func TestScanReportOffersTheGuardOnlyWhenHistoryIsInvolved(t *testing.T) {
	home := t.TempDir()
	key := "GITHUB_TOKEN"
	preview := "ghp_**********"
	line := 2
	histFinding := Finding{
		FindingType:  FindingTypeShellHistorySecret,
		FilePath:     filepath.Join(home, ".zsh_history"),
		KeyName:      &key,
		ValuePreview: &preview,
		Line:         &line,
		Severity:     SeverityHigh,
		Remedy:       RemedyMigrate,
		FixCommand:   "jit migrate ~/.zsh_history",
		RecordID:     "r1",
	}
	render := func(fs []Finding) string {
		cov := ComputeCoverage("", fs)
		var buf strings.Builder
		WriteTriageReport(&buf, fs, ScanSummary{
			SecretsTotal: cov.Total(), SecretsProtected: cov.Protected, SecretsMigratable: cov.Migratable,
		}, home, cov)
		return buf.String()
	}

	out := render([]Finding{histFinding})
	if !strings.Contains(out, "jit guard history") {
		t.Errorf("history finding did not offer the guard:\n%s", out)
	}
	// The offer must explain itself, not just name a command nobody can guess.
	if !strings.Contains(out, "history file") {
		t.Errorf("the guard offer has no explainer:\n%s", out)
	}

	// A machine with no history finding must not be nagged about it.
	envFinding := histFinding
	envFinding.FindingType = FindingTypeShellConfigSecret
	envFinding.FilePath = filepath.Join(home, ".zshrc")
	envFinding.RecordID = "r2"
	if out := render([]Finding{envFinding}); strings.Contains(out, "jit guard") {
		t.Errorf("offered the guard with no history finding:\n%s", out)
	}
}
