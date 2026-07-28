// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatalf("mkdirAll(%q): %v", path, err)
	}
}

func TestScanEnvFiles(t *testing.T) {
	home := t.TempDir()

	// A normal project .env with genuinely mundane config (no secret-shaped
	// names, no cross-cutting signal) — should be Low.
	mkdirAll(t, filepath.Join(home, "code", "webapp"))
	writeFile(t, filepath.Join(home, "code", "webapp", ".env"), `VITE_APP_TITLE=MyApp
VITE_ENVIRONMENT=development
`)

	// A .env with a production-indicator match — should escalate to Critical.
	mkdirAll(t, filepath.Join(home, "code", "api-service"))
	writeFile(t, filepath.Join(home, "code", "api-service", ".env"), `PROD_DATABASE_URL=postgres://admin:hunter2@db.internal/prod
`)

	// A .env.local variant, and a backup directory (real-world evidence:
	// most exposure lives in exactly these kinds of forgotten locations) —
	// with commented-out lines that should still be counted, not dropped.
	mkdirAll(t, filepath.Join(home, "Desktop", "old_project_backup_20250101"))
	writeFile(t, filepath.Join(home, "Desktop", "old_project_backup_20250101", ".env"), `# OPENROUTER_API_KEY=sk-abc123
# LLM_MODEL=gpt-4
ACTIVE_VAR=stillhere
`)
	mkdirAll(t, filepath.Join(home, "code", "internal-tool"))
	writeFile(t, filepath.Join(home, "code", "internal-tool", ".env.local"), `APP_PASSWORD=hunter2
`)

	// A .env sitting inside node_modules must be skipped — it's not a real
	// project file, and node_modules can be huge.
	mkdirAll(t, filepath.Join(home, "code", "webapp", "node_modules", "some-pkg"))
	writeFile(t, filepath.Join(home, "code", "webapp", "node_modules", "some-pkg", ".env"), `SHOULD_NOT_APPEAR=true
`)

	cfg := Config{HomeDir: home}
	findings, err := ScanEnvFiles(cfg)
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}

	if len(findings) != 4 {
		paths := make([]string, len(findings))
		for i, f := range findings {
			paths[i] = f.FilePath
		}
		t.Fatalf("got %d findings, want 4 (node_modules .env must be skipped): %v", len(findings), paths)
	}

	byPath := map[string]Finding{}
	for _, f := range findings {
		byPath[f.FilePath] = f
		if f.KeyName != nil {
			t.Errorf("env_file_present findings must be file-level (KeyName nil), got %q for %s", *f.KeyName, f.FilePath)
		}
		if f.ValuePreview != nil {
			t.Errorf("env_file_present findings must be file-level (ValuePreview nil), got %q for %s", *f.ValuePreview, f.FilePath)
		}
	}

	webapp := byPath[filepath.Join(home, "code", "webapp", ".env")]
	if webapp.Severity != SeverityLow {
		t.Errorf("webapp .env severity = %q, want %q", webapp.Severity, SeverityLow)
	}

	api := byPath[filepath.Join(home, "code", "api-service", ".env")]
	if api.Severity != SeverityCritical {
		t.Errorf("api-service .env severity = %q, want %q (production-indicator match)", api.Severity, SeverityCritical)
	}
	if !api.ProductionIndicatorMatch {
		t.Error("api-service .env should have ProductionIndicatorMatch = true")
	}

	backup := byPath[filepath.Join(home, "Desktop", "old_project_backup_20250101", ".env")]
	if backup.Severity != SeverityLow {
		t.Errorf("backup .env severity = %q, want %q", backup.Severity, SeverityLow)
	}
	wantEvidence := "3 plaintext variable(s) (1 active, 2 commented out)"
	if backup.Evidence != wantEvidence {
		t.Errorf("backup .env evidence = %q, want %q", backup.Evidence, wantEvidence)
	}

	local := byPath[filepath.Join(home, "code", "internal-tool", ".env.local")]
	if local.Severity != SeverityHigh {
		t.Errorf(".env.local severity = %q, want %q (APP_PASSWORD looks secret-shaped)", local.Severity, SeverityHigh)
	}
}

func TestScanEnvFilesPublicIPEscalation(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".env"), `EXTERNAL_HOST=8.8.8.8
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q (public IP match)", findings[0].Severity, SeverityCritical)
	}
	if findings[0].PublicIPMatch == nil || *findings[0].PublicIPMatch != "8.8.8.8" {
		t.Errorf("PublicIPMatch = %v, want 8.8.8.8", findings[0].PublicIPMatch)
	}
}

// TestScanEnvFilesTemplateFileNotFlagged locks in a real-world dogfooding
// finding (2026-07-06): .env.example (and .sample/.template/.dist) is a
// universal convention for safe-to-commit templates with placeholder
// values. Flagging its mere presence the same as a real .env file was
// observed producing roughly half of all .env findings on a real machine —
// pure noise that would erode trust in the tool.
func TestScanEnvFilesTemplateFileNotFlagged(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "webapp"))
	writeFile(t, filepath.Join(home, "code", "webapp", ".env.example"), `API_KEY=your_api_key_here
DATABASE_URL=postgres://user:password@localhost/dbname
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings for a template file with nothing escalating, want 0: %+v", len(findings), findings)
	}
}

// TestScanEnvFilesTemplateFileStillEscalates confirms the other half of
// that fix: a real secret accidentally left in a template file must still
// be caught, not silently ignored just because of the filename.
func TestScanEnvFilesTemplateFileStillEscalates(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "webapp"))
	writeFile(t, filepath.Join(home, "code", "webapp", ".env.sample"), `PROD_DATABASE_URL=postgres://admin:realpassword@db.internal/prod
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (a real secret in a template must still be caught)", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want %q", findings[0].Severity, SeverityCritical)
	}
}

// TestScanEnvFilesSkipsPointerFiles is a real, reported incident's
// regression test: envFileNamePattern's wildcard suffix match (meant to
// catch .env.local/.env.production) also matched jit migrate's own
// `<file>.pointers` companion (internal/migrate/pointerfile.go), since
// it's just ".env" followed by another suffix — so `jit scan` would
// falsely report a git-safe pointer file (holding only
// `KEY=jit://vault/...` lines, never a real value) as an exposed .env
// secret. Unlike a template file (still scanned for an accidental real
// secret), a `.pointers` file is skipped outright — it's jit's own
// generated artifact, never user-authored content, so there's nothing
// to escalate on even in principle. The line below looks exactly like
// something that WOULD escalate if this weren't skipped entirely,
// proving it's a full skip and not just "no escalation happened to
// fire."
func TestScanEnvFilesSkipsPointerFiles(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "webapp"))
	writeFile(t, filepath.Join(home, "code", "webapp", ".env.pointers"), `PROD_DATABASE_URL=jit://vault/webapp/PROD_DATABASE_URL
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings for a .pointers companion file, want 0: %+v", len(findings), findings)
	}
}

// TestScanEnvFilesSkipsInPlacePointerFiles is the regression test for GAPS.md
// #66, the case TestScanEnvFilesSkipsPointerFiles' name-based check misses:
// after `jit migrate`, a backup-suffixed .env file (.env.bak) is replaced in
// place with jit pointer content while keeping its original name, so only the
// content check (isJitPointerContent) can tell it apart from a real stray
// backup. It holds only `KEY=jit://vault/...` lines, never a real value.
// (Inherited from the suspicious-filename scanner's test file when schema
// 0.10.0 removed that category — ScanEnvFiles is the only scanner that
// reports a .env.bak now, so it owns this regression.)
func TestScanEnvFilesSkipsInPlacePointerFiles(t *testing.T) {
	home := t.TempDir()
	pointer := "# jit pointer file — no secret values here, only vault paths.\n" +
		"# Real values come from the live mount or `jit vault get`, never this file.\n" +
		"API_KEY=jit://vault/oldproject-bak/API_KEY\n"
	mkdirAll(t, filepath.Join(home, "proj"))
	writeFile(t, filepath.Join(home, "proj", ".env.bak"), pointer)

	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("env findings = %+v, want none — a pointer file holds no real secret", findings)
	}
}

// TestScanEnvFilesSecretShapedKeyEscalates locks in the exact real-world
// case (2026-07-06) that motivated this fix: a real, company-wide
// management key sitting in a variable named "..._MGMT_KEY" was rated Low,
// identical to a boring file with nothing but NAME=whatever — because
// nothing checked whether the variable NAME looked like a real secret.
func TestScanEnvFilesSecretShapedKeyEscalates(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".env"), `# Company-wide management key
DESCOPE_MGMT_KEY=K3G4pkXnDUxYyKIbkdVPTNKNy5zLPyf2XxaT6KAboEHSHTgCWOA4I2hIaa6EuXKsmZTishm
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("severity = %q, want %q — a secret-shaped active variable name must not be rated the same as a boring file", findings[0].Severity, SeverityHigh)
	}
	if !strings.Contains(findings[0].Evidence, "DESCOPE_MGMT_KEY") {
		t.Errorf("evidence should name the specific variable that looked secret-shaped, got: %q", findings[0].Evidence)
	}
}

// fakeStripeLiveKey is assembled at runtime, never written as one literal:
// a string that satisfies stripeLiveKey's own regexp necessarily also
// satisfies GitHub's secret scanner, and push protection rejects the whole
// push when it finds one — which is precisely the check this project exists
// to make people care about. Matches tokenpatterns_test.go's convention.
var fakeStripeLiveKey = "sk_" + "live_" + tokenBody(24)

// A .env holding SEVERAL credentials used to report only the one signal that
// happened to set its severity — a real file with a Postgres URL, a Stripe
// live key, and an AWS secret key reported the database URL and nothing else,
// so the sk_live_ key never appeared in the report at all and the user had no
// way to know the scanner had seen it. The finding stays file-level per the
// RFC; its evidence now names everything.
func TestScanEnvFilesEvidenceNamesEveryCredential(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".env"), `# demo app config
DATABASE_URL=postgres://app:s3cr3tpassw0rd@db.internal:5432/appdb
STRIPE_API_KEY=`+fakeStripeLiveKey+`
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
PORT=3000
DEBUG=true
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 file-level finding", len(findings))
	}
	ev := findings[0].Evidence
	for _, want := range []string{"STRIPE_API_KEY", "AWS_SECRET_ACCESS_KEY"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence never mentions %s, the user can't act on a credential the report doesn't name; got: %q", want, ev)
		}
	}
	// Non-secret config is not a credential and must not be listed as one.
	for _, unwanted := range []string{"PORT", "DEBUG"} {
		if strings.Contains(ev, unwanted) {
			t.Errorf("evidence names %s, which is ordinary config, not a credential; got: %q", unwanted, ev)
		}
	}
}

// A file with exactly one credential must read as it always did — no dangling
// "; also ..." clause with nothing after it.
func TestScanEnvFilesEvidenceUnchangedForSingleCredential(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".env"), "STRIPE_API_KEY="+fakeStripeLiveKey+"\n")
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if strings.Contains(findings[0].Evidence, "also") {
		t.Errorf("single-credential file grew an 'also' clause with nothing to add: %q", findings[0].Evidence)
	}
}

// TestScanEnvFilesTemplateNotEscalatedBySecretShapedNames confirms templates
// are exempt from the key-name check above: an .env.example's entire
// purpose is documenting which secret-shaped variable NAMES a real .env
// needs, so the name alone can't be evidence of anything for a template.
func TestScanEnvFilesTemplateNotEscalatedBySecretShapedNames(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".env.example"), `API_KEY=your_api_key_here
DATABASE_PASSWORD=changeme
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings for a template with only secret-shaped NAMES (no escalating value), want 0: %+v", len(findings), findings)
	}
}

func TestScanEnvFilesNoneFound(t *testing.T) {
	home := t.TempDir()
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles on empty home dir should not error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings on empty home dir, want 0", len(findings))
	}
}

// mkfifo plants a named pipe, standing in for a live jit mount's FIFO.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo(%q): %v", path, err)
	}
}

// A live jit mount is a named pipe at the .env path. Opening it for read
// would block the whole scan forever when no agent is writing — and when one
// is, it serves DECOY values, which are protection, not an at-rest exposure.
// Either way the scanner must skip it by mode. NOTE: a regression here makes
// this test HANG (blocked open on a writerless pipe), not merely fail.
func TestScanEnvFilesSkipsLiveMountFIFO(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "app"))
	mkfifo(t, filepath.Join(home, "app", ".env"))
	writeFile(t, filepath.Join(home, "app", ".env.local"), "API_KEY=realvalue123456\n")

	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	for _, f := range findings {
		if f.FilePath == filepath.Join(home, "app", ".env") {
			t.Errorf("the live-mount FIFO was scanned and reported: %+v", f)
		}
	}
	if len(findings) != 1 {
		t.Errorf("got %d findings, want exactly 1 (the regular .env.local, not the FIFO)", len(findings))
	}
}

// TestScanEnvFilesPublicBuildVarsNotEscalated is the .env-file half of the
// LooksLikeNonSecretName change. Five real developer scans (2026-07-28) each
// carried a cluster of blockaid-platform .env files holding nothing but
// browser-public Vite variables, and every one rated HIGH — on the strength of
// names like VITE_AUTH0_DOMAIN, whose value was the bare hostname
// id.blockaid.io. Vite's own docs say these are bundled into client source at
// build time, so treating them as credentials is backwards.
func TestScanEnvFilesPublicBuildVarsNotEscalated(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "platform"))
	writeFile(t, filepath.Join(home, "code", "platform", ".env"), `VITE_AUTH0_DOMAIN=id.blockaid.io
VITE_AUTH0_CLIENT_ID=Ab3xKq9ZmPq2LrTvWn5cUd8eFg1hJk0uf4
VITE_DATADOG_CLIENT_TOKEN=pubc9f4a1b2d3e4f5061728394a5b6c7d8e9
REACT_APP_DATADOG_PROXY_URL=/logsProxy
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (the file is still reported, just not escalated)", len(findings))
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want %q — browser-public build vars must not read as credentials", findings[0].Severity, SeverityLow)
	}
}

// TestScanEnvFilesPublicPrefixStillEscalatesRealSecret is the safety property
// the suppression above must never break: the prefix excuses the NAME signal
// only. A live credential behind a public prefix is a genuine misconfiguration
// — the value is about to be shipped to browsers — so it has to stay loud.
func TestScanEnvFilesPublicPrefixStillEscalatesRealSecret(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "webapp"))
	writeFile(t, filepath.Join(home, "code", "webapp", ".env"), `NEXT_PUBLIC_STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dcQ8Zt3Kx1
`)
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity == SeverityLow {
		t.Error("a live Stripe key behind NEXT_PUBLIC_ must still escalate on its value")
	}
}

// TestScanEnvFilesAnonJWTNotEscalated covers the one token format that proves
// nothing on its own. A Supabase anon key IS a JWT, and Supabase documents it
// as safe to expose, so the JWT pattern firing on SUPABASE_ANON_KEY was pure
// noise — while a JWT in any ordinary variable must keep its full weight.
func TestScanEnvFilesAnonJWTNotEscalated(t *testing.T) {
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiJ9.abc123def456"

	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "code", "app"))
	writeFile(t, filepath.Join(home, "code", "app", ".env"), "SUPABASE_ANON_KEY="+jwt+"\n")
	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("severity = %q, want %q for a documented-public anon key", findings[0].Severity, SeverityLow)
	}

	other := t.TempDir()
	mkdirAll(t, filepath.Join(other, "code", "app"))
	writeFile(t, filepath.Join(other, "code", "app", ".env"), "SESSION_TOKEN="+jwt+"\n")
	findings, err = ScanEnvFiles(Config{HomeDir: other})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity == SeverityLow {
		t.Errorf("a JWT in an ordinary variable must still escalate, got %+v", findings)
	}
}

// TestScanEnvFilesUnfilteredRevealsSuppressed pins the escape hatch. The
// name/value gates are normally invisible, so a reader cannot tell "jit found
// nothing" apart from "jit found things and chose not to say". Config.Unfiltered
// shows the second view, and the two must genuinely differ.
func TestScanEnvFilesUnfilteredRevealsSuppressed(t *testing.T) {
	write := func(home string) {
		mkdirAll(t, filepath.Join(home, "app"))
		writeFile(t, filepath.Join(home, "app", ".env"), `VITE_AUTH0_DOMAIN=id.blockaid.io
CALLBACK_PRIVATE_KEY_PATH=/etc/keys/x.pem
HIBOB_SERVICE_USER_TOKEN=service-user-token-here
`)
	}

	quiet := t.TempDir()
	write(quiet)
	findings, err := ScanEnvFiles(Config{HomeDir: quiet})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != SeverityLow {
		t.Fatalf("default scan should report the file only at Low, got %+v", findings)
	}

	loud := t.TempDir()
	write(loud)
	findings, err = ScanEnvFiles(Config{HomeDir: loud, Unfiltered: true})
	if err != nil {
		t.Fatalf("ScanEnvFiles(unfiltered): %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity == SeverityLow {
		t.Error("--unfiltered must surface the names the gates suppressed")
	}
	for _, want := range []string{"VITE_AUTH0_DOMAIN", "CALLBACK_PRIVATE_KEY_PATH", "HIBOB_SERVICE_USER_TOKEN"} {
		if !strings.Contains(findings[0].Evidence, want) {
			t.Errorf("unfiltered evidence should name %q, got %q", want, findings[0].Evidence)
		}
	}
}

// TestScanEnvFilesEntropyEscalatesUnnamedSecret is the .env-level half: a
// credential with neither a vendor prefix nor a secret-shaped name used to
// score Low, indistinguishable from a file of settings.
func TestScanEnvFilesEntropyEscalatesUnnamedSecret(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "svc"))
	writeFile(t, filepath.Join(home, "svc", ".env"), "cfg1=6I1evXdj352FpyVQO8t4lgh9YHLukE0xcW7sGDSm\n")

	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity == SeverityLow {
		t.Error("a credential-shaped value must escalate even when nothing about its NAME says secret")
	}
	// Medium, not High: shape alone is weaker evidence than a vendor prefix or
	// a name that says so, and the finding should not claim more.
	if findings[0].Confidence != ConfidenceMedium {
		t.Errorf("confidence = %q, want %q — a judgement about shape", findings[0].Confidence, ConfidenceMedium)
	}
}

// TestScanEnvFilesEntropyIgnoresBuildMetadata guards the other direction: a
// .env full of SHAs, versions and ports must stay quiet, or the signal is
// worse than not having it.
func TestScanEnvFilesEntropyIgnoresBuildMetadata(t *testing.T) {
	home := t.TempDir()
	mkdirAll(t, filepath.Join(home, "svc"))
	writeFile(t, filepath.Join(home, "svc", ".env"), `BUILD_SHA=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0
GIT_COMMIT=9f8e7d6c5b4a39281706f5e4d3c2b1a098765432
APP_VERSION=2024.11.3-rc4-build8891
REDIS_PORT=6379
`)

	findings, err := ScanEnvFiles(Config{HomeDir: home})
	if err != nil {
		t.Fatalf("ScanEnvFiles: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != SeverityLow {
		t.Errorf("build metadata must not escalate, got %+v", findings)
	}
}
