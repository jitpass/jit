// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: BUSL-1.1

package migrate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallRevealHookPrependsToExistingEnvrc(t *testing.T) {
	dir := t.TempDir()
	envrcPath := filepath.Join(dir, ".envrc")
	writeFile(t, envrcPath, "dotenv\nexport FOO=bar\n")

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookDirenv {
		t.Fatalf("kind = %q, want %q", kind, RevealHookDirenv)
	}

	data, err := os.ReadFile(envrcPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "agent reveal") {
		t.Errorf(".envrc does not contain a reveal command:\n%s", content)
	}
	if !strings.Contains(content, "/fixture/.env") {
		t.Errorf(".envrc does not reference the mount path:\n%s", content)
	}
	lines := strings.Split(content, "\n")
	if !strings.Contains(lines[0], "agent reveal") {
		t.Errorf("reveal command must be the first line (must run before dotenv/source_env), got:\n%s", content)
	}
	if !strings.Contains(content, "dotenv") {
		t.Error("original .envrc content was lost, not preserved")
	}

	backups, _ := filepath.Glob(envrcPath + ".jit-bak-*")
	if len(backups) != 1 {
		t.Errorf("expected exactly one backup file, found %d", len(backups))
	}
}

func TestInstallRevealHookNeverCreatesEnvrc(t *testing.T) {
	dir := t.TempDir()

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNone {
		t.Errorf("kind = %q, want RevealHookNone — a project with no existing .envrc/package.json must get no hook", kind)
	}
	if _, err := os.Stat(filepath.Join(dir, ".envrc")); err == nil {
		t.Error("InstallRevealHook created a .envrc that didn't exist before — must never opt a project into direnv")
	}
}

func TestInstallRevealHookIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	envrcPath := filepath.Join(dir, ".envrc")
	writeFile(t, envrcPath, "dotenv\n")

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("first InstallRevealHook: %v", err)
	}
	firstContent, err := os.ReadFile(envrcPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("second InstallRevealHook: %v", err)
	}
	if kind != RevealHookDirenv {
		t.Errorf("second call kind = %q, want %q (already installed, should still report it)", kind, RevealHookDirenv)
	}

	secondContent, err := os.ReadFile(envrcPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(firstContent) != string(secondContent) {
		t.Errorf("second migrate run changed .envrc — not idempotent:\nfirst:\n%s\nsecond:\n%s", firstContent, secondContent)
	}

	backups, _ := filepath.Glob(envrcPath + ".jit-bak-*")
	if len(backups) != 1 {
		t.Errorf("expected exactly one backup after two idempotent runs, found %d", len(backups))
	}
}

func TestInstallRevealHookNpmDevAndStart(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"name":"x","scripts":{"dev":"vite","start":"node server.js","test":"jest"}}`)

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNpm {
		t.Fatalf("kind = %q, want %q", kind, RevealHookNpm)
	}

	scripts := readPackageScripts(t, pkgPath)
	for _, key := range []string{"predev", "prestart"} {
		v, ok := scripts[key]
		if !ok {
			t.Errorf("missing %q script", key)
			continue
		}
		if !strings.Contains(v, "agent reveal") || !strings.Contains(v, "/fixture/.env") {
			t.Errorf("%s = %q, want it to contain the reveal command", key, v)
		}
		if !strings.Contains(v, "2>/dev/null") {
			t.Errorf("%s = %q, want it to contain the shell redirect", key, v)
		}
	}

	// The bytes ON DISK must not be HTML-escaped: encoding/json's default
	// turns `2>/dev/null` into `2>/dev/null`, which npm runs fine but
	// which reads as corruption in the file a developer opens to see what
	// jit did (a real dogfooding report). marshalJSONNoEscape fixes it.
	// (Checking the parsed value can't catch this — Unmarshal decodes the
	// escapes back; only the raw file reveals them.)
	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("reading package.json: %v", err)
	}
	// The literal 6-char sequence backslash-u-0-0-3-e, i.e. how an
	// HTML-escaped '>' appears in the raw bytes (NOT a decoded '>', which
	// legitimately appears in 2>/dev/null).
	escGT := "\\u003e"
	escAmp := "\\u0026"
	if strings.Contains(string(raw), escGT) || strings.Contains(string(raw), escAmp) {
		t.Errorf("package.json on disk contains HTML-escaped metacharacters:\n%s", raw)
	}
	if _, ok := scripts["pretest"]; ok {
		t.Error("must not add a pretest hook — only dev/start are targeted, not every script")
	}
}

// Issue #2: the install rewrite used to re-marshal the whole file through a
// map, alphabetizing top-level keys and dropping the trailing newline. The
// splice-based edit must leave every byte outside the "scripts" value
// untouched — key order, 4-space indentation, and the final newline — and
// inside "scripts" preserve member order, inserting each pre-hook right
// above its target.
func TestInstallRevealHookNpmPreservesLayout(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	original := `{
    "name": "acme-checkout",
    "version": "1.0.0",
    "private": true,
    "description": "Mock checkout service",
    "scripts": {
        "dev": "node server.js",
        "start": "node server.js"
    }
}
`
	writeFile(t, pkgPath, original)

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNpm {
		t.Fatalf("kind = %q, want %q", kind, RevealHookNpm)
	}

	raw, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("reading package.json: %v", err)
	}
	got := string(raw)

	// Everything outside the scripts value is byte-identical: same key
	// order, same indent, same trailing newline.
	wantPrefix := "{\n    \"name\": \"acme-checkout\",\n    \"version\": \"1.0.0\",\n    \"private\": true,\n    \"description\": \"Mock checkout service\",\n    \"scripts\": {\n"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("top-level layout changed, got:\n%s", got)
	}
	if !strings.HasSuffix(got, "}\n") {
		t.Errorf("trailing newline dropped, file ends with %q", got[len(got)-2:])
	}

	// Scripts keep source order with each pre-hook inserted above its
	// target, at the block's own 8-space member indent.
	for _, pair := range [][2]string{
		{"\"predev\"", "\"dev\""},
		{"\"prestart\"", "\"start\""},
	} {
		hook, target := strings.Index(got, pair[0]), strings.Index(got, pair[1]+":")
		if hook < 0 || target < 0 || hook > target {
			t.Errorf("expected %s inserted before %s, got:\n%s", pair[0], pair[1], got)
		}
	}
	if !strings.Contains(got, "\n        \"predev\":") {
		t.Errorf("scripts member indent not preserved, got:\n%s", got)
	}

	// And the edit round-trips: undo restores the original bytes exactly.
	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	restored, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("reading restored package.json: %v", err)
	}
	if string(restored) != original {
		t.Errorf("undo did not restore original bytes:\nwant:\n%s\ngot:\n%s", original, restored)
	}
}

func TestInstallRevealHookNpmPreservesExistingPreScript(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"scripts":{"dev":"vite","predev":"echo already-here"}}`)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}

	scripts := readPackageScripts(t, pkgPath)
	predev := scripts["predev"]
	if !strings.Contains(predev, "agent reveal") {
		t.Errorf("predev = %q, want it to also contain the reveal command", predev)
	}
	if !strings.Contains(predev, "echo already-here") {
		t.Errorf("predev = %q, want the user's original predev command preserved", predev)
	}
}

func TestInstallRevealHookNpmNoScriptsBlock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "package.json"), `{"name":"x"}`)

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNone {
		t.Errorf("kind = %q, want RevealHookNone for a package.json with no scripts block", kind)
	}
}

func TestInstallRevealHookNoneWhenNothingApplies(t *testing.T) {
	dir := t.TempDir()

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNone {
		t.Errorf("kind = %q, want RevealHookNone for an empty directory", kind)
	}
}

func TestInstallRevealHookDirenvTakesPrecedenceOverNpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".envrc"), "dotenv\n")
	writeFile(t, filepath.Join(dir, "package.json"), `{"scripts":{"dev":"vite"}}`)

	kind, err := InstallRevealHook(dir, "/fixture/.env")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookDirenv {
		t.Errorf("kind = %q, want %q — installs at most one hook", kind, RevealHookDirenv)
	}

	scripts := readPackageScripts(t, filepath.Join(dir, "package.json"))
	if _, ok := scripts["predev"]; ok {
		t.Error("package.json was also modified — InstallRevealHook must install at most one hook, not both")
	}
}

func readPackageScripts(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return pkg.Scripts
}

// A directory with several mounts (.env + .env.local + .npmrc — the common
// playground/monorepo shape) must land in ONE edit of the hook file: the
// per-mount variant left N near-identical package.json.jit-bak-<ts>
// siblings from a single migrate run, a real, observed mess.
func TestInstallRevealHookBatchesAllMountsIntoOneEditOneBackup(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"name":"x","scripts":{"dev":"node server.js"}}`)

	kind, err := InstallRevealHook(dir, "/fixture/.env", "/fixture/.env.local", "/fixture/.npmrc")
	if err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if kind != RevealHookNpm {
		t.Fatalf("kind = %q, want %q", kind, RevealHookNpm)
	}

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, p := range []string{"/fixture/.env", "/fixture/.env.local", "/fixture/.npmrc"} {
		if !strings.Contains(string(data), "agent reveal '"+p+"'") {
			t.Errorf("predev is missing the reveal for %s:\n%s", p, data)
		}
	}

	backups, _ := filepath.Glob(pkgPath + ".jit-bak-*")
	if len(backups) != 1 {
		t.Errorf("expected exactly ONE backup for a 3-mount directory, found %d: %v", len(backups), backups)
	}
}

// A later migrate adding one NEW mount to a directory whose other mounts
// are already wired must add only the new command (and take one new
// backup), never duplicate the existing ones.
func TestInstallRevealHookAddsOnlyTheNewMount(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"name":"x","scripts":{"dev":"node server.js"}}`)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("first InstallRevealHook: %v", err)
	}
	if _, err := InstallRevealHook(dir, "/fixture/.env", "/fixture/.env.local"); err != nil {
		t.Fatalf("second InstallRevealHook: %v", err)
	}

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := strings.Count(string(data), "agent reveal '/fixture/.env'"); got != 1 {
		t.Errorf(".env reveal appears %d time(s), want exactly 1:\n%s", got, data)
	}
	if got := strings.Count(string(data), "agent reveal '/fixture/.env.local'"); got != 1 {
		t.Errorf(".env.local reveal appears %d time(s), want exactly 1:\n%s", got, data)
	}
}

func TestUninstallRevealHookNpmRemovesHookAndBackup(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"name":"x","scripts":{"dev":"node server.js"}}`)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	// A .jit-bak sibling exists after install.
	if baks, _ := filepath.Glob(pkgPath + ".jit-bak-*"); len(baks) == 0 {
		t.Fatal("expected a package.json.jit-bak-* backup after install")
	}

	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	scripts := readPackageScripts(t, pkgPath)
	if _, ok := scripts["predev"]; ok {
		t.Errorf("predev should be gone (it was entirely jit's), got scripts: %+v", scripts)
	}
	if scripts["dev"] != "node server.js" {
		t.Errorf("dev = %q, want the original untouched", scripts["dev"])
	}
	// The .jit-bak siblings are cleaned up once no jit hook remains.
	if baks, _ := filepath.Glob(pkgPath + ".jit-bak-*"); len(baks) != 0 {
		t.Errorf("expected .jit-bak backups cleaned up, still present: %v", baks)
	}
}

func TestUninstallRevealHookNpmPreservesUserPreScript(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"scripts":{"dev":"vite","predev":"echo already-here"}}`)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	scripts := readPackageScripts(t, pkgPath)
	if scripts["predev"] != "echo already-here" {
		t.Errorf("predev = %q, want ONLY the user's original command back", scripts["predev"])
	}
}

func TestUninstallRevealHookNpmPartialUndoKeepsOtherMount(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"scripts":{"dev":"node server.js"}}`)

	if _, err := InstallRevealHook(dir, "/fixture/.env", "/fixture/.env.local"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	// Undo only .env — .env.local's hook must survive, and the backup must
	// be kept since jit still has wiring in the file.
	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	predev := readPackageScripts(t, pkgPath)["predev"]
	if strings.Contains(predev, "agent reveal '/fixture/.env'") {
		t.Errorf("predev = %q, want the .env hook removed", predev)
	}
	if !strings.Contains(predev, "agent reveal '/fixture/.env.local'") {
		t.Errorf("predev = %q, want the .env.local hook still present", predev)
	}
	if baks, _ := filepath.Glob(pkgPath + ".jit-bak-*"); len(baks) == 0 {
		t.Error("partial undo should KEEP the .jit-bak backup (jit wiring remains)")
	}
}

func TestUninstallRevealHookDirenvRemovesLine(t *testing.T) {
	dir := t.TempDir()
	envrcPath := filepath.Join(dir, ".envrc")
	writeFile(t, envrcPath, "dotenv\n")

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	data, err := os.ReadFile(envrcPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "agent reveal") {
		t.Errorf(".envrc still contains a reveal hook:\n%s", data)
	}
	if !strings.Contains(string(data), "dotenv") {
		t.Errorf(".envrc lost the user's own line:\n%s", data)
	}
}

func TestUninstallRevealHookNoOpWhenNothingInstalled(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, `{"scripts":{"dev":"node server.js"}}`)

	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook on a clean project should be a no-op: %v", err)
	}
	if scripts := readPackageScripts(t, pkgPath); scripts["dev"] != "node server.js" {
		t.Errorf("dev = %q, want untouched", scripts["dev"])
	}
}

func TestUninstallRevealHookNpmRestoresOriginalBytes(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	// Deliberately NON-alphabetical key order plus a trailing newline —
	// exactly what a JSON round-trip through Go maps destroys.
	original := "{\n  \"name\": \"acme\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"scripts\": {\n    \"dev\": \"node server.js\"\n  }\n}\n"
	writeFile(t, pkgPath, original)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != original {
		t.Errorf("package.json not restored byte-for-byte after uninstall:\ngot:\n%s\nwant:\n%s", data, original)
	}
	if backups, _ := filepath.Glob(pkgPath + ".jit-bak-*"); len(backups) != 0 {
		t.Errorf("expected .jit-bak siblings cleaned up, found %v", backups)
	}
}

func TestUninstallRevealHookNpmUserEditFallsBackToSurgical(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	writeFile(t, pkgPath, "{\n  \"name\": \"acme\",\n  \"scripts\": {\n    \"dev\": \"node server.js\"\n  }\n}\n")

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	// A user edit since install: the cleaned file can no longer match the
	// backup, so the surgical rewrite must win — never a backup restore
	// that would clobber the edit.
	scripts := readPackageScripts(t, pkgPath)
	scripts["test"] = "vitest"
	pkgRaw, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var pkg map[string]json.RawMessage
	if err := json.Unmarshal(pkgRaw, &pkg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	scriptsJSON, err := marshalJSONNoEscape(scripts, "")
	if err != nil {
		t.Fatalf("marshal scripts: %v", err)
	}
	pkg["scripts"] = scriptsJSON
	edited, err := marshalJSONNoEscape(pkg, "  ")
	if err != nil {
		t.Fatalf("marshal pkg: %v", err)
	}
	writeFile(t, pkgPath, string(edited)+"\n")

	if err := UninstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("UninstallRevealHook: %v", err)
	}
	got := readPackageScripts(t, pkgPath)
	if got["test"] != "vitest" {
		t.Errorf("user-added script lost: scripts = %v", got)
	}
	if _, hasPre := got["predev"]; hasPre {
		t.Errorf("predev hook survived uninstall: scripts = %v", got)
	}
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("surgical rewrite dropped the file's trailing newline")
	}
}

func TestRemoveRevealHooksRestoresOriginalBytesAndCleansBackups(t *testing.T) {
	dir := t.TempDir()
	pkgPath := filepath.Join(dir, "package.json")
	original := "{\n  \"name\": \"acme\",\n  \"version\": \"2.0.0\",\n  \"scripts\": {\n    \"start\": \"node .\"\n  }\n}\n"
	writeFile(t, pkgPath, original)

	if _, err := InstallRevealHook(dir, "/fixture/.env"); err != nil {
		t.Fatalf("InstallRevealHook: %v", err)
	}
	edited, err := RemoveRevealHooks(dir)
	if err != nil {
		t.Fatalf("RemoveRevealHooks: %v", err)
	}
	if len(edited) != 1 || edited[0] != pkgPath {
		t.Fatalf("edited = %v, want [%s]", edited, pkgPath)
	}
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != original {
		t.Errorf("package.json not restored byte-for-byte by RemoveRevealHooks:\ngot:\n%s\nwant:\n%s", data, original)
	}
	if backups, _ := filepath.Glob(pkgPath + ".jit-bak-*"); len(backups) != 0 {
		t.Errorf("expected .jit-bak siblings cleaned up, found %v", backups)
	}
}
