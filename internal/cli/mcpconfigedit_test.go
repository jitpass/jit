// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/audit"
)

var testMCPEntry = &mcpServerEntry{Command: "/opt/homebrew/bin/jit", Args: []string{"mcp"}}

func writeMCPFixture(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // past the umask
		t.Fatal(err)
	}
}

func readMCPFixture(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The help says nothing else in the file changes. Re-encoding the decoded
// file made that false: keys sorted, the file's own four-space indent gone,
// and "&", "<", ">" rewritten as &, <, > (pre-release review,
// 2026-09-26). Install adds exactly the entry, and uninstall gives back the
// file byte for byte.
func TestSetMCPEntryChangesOnlyItsOwnEntry(t *testing.T) {
	const original = `{
    "zeta": "R&D <team> -> ok",
    "mcpServers": {
        "search": {
            "command": "npx",
            "args": ["-y", "server?a=1&b=2"]
        }
    },
    "alpha": {"sidebar": "chat", "name": "Café"}
}`
	const installed = `{
    "zeta": "R&D <team> -> ok",
    "mcpServers": {
        "search": {
            "command": "npx",
            "args": ["-y", "server?a=1&b=2"]
        },
        "jit": {
            "command": "/opt/homebrew/bin/jit",
            "args": [
                "mcp"
            ]
        }
    },
    "alpha": {"sidebar": "chat", "name": "Café"}
}`
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeMCPFixture(t, path, original, 0o600)

	if ed, err := setMCPEntry(path, testMCPEntry, time.Unix(0, 0)); err != nil || !ed.changed {
		t.Fatalf("install: %+v %v", ed, err)
	}
	if got := readMCPFixture(t, path); got != installed {
		t.Fatalf("install changed more than its entry:\n%s\nwant:\n%s", got, installed)
	}
	if ed, err := setMCPEntry(path, nil, time.Unix(1, 0)); err != nil || !ed.changed {
		t.Fatalf("uninstall: %+v %v", ed, err)
	}
	if got := readMCPFixture(t, path); got != original {
		t.Fatalf("install then uninstall did not give back the file:\n%s\nwant:\n%s", got, original)
	}
}

// The entry jit writes is not escaped either: a jit under a folder named
// "R&D" is written as R&D, not R&D.
func TestSetMCPEntryDoesNotEscapeItsOwnEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	writeMCPFixture(t, path, desktopConfig, 0o600)
	entry := &mcpServerEntry{Command: "/Users/x/R&D <tools>/jit", Args: []string{"mcp"}}
	if _, err := setMCPEntry(path, entry, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	got := readMCPFixture(t, path)
	if !strings.Contains(got, `"/Users/x/R&D <tools>/jit"`) || strings.Contains(got, `\u00`) {
		t.Fatalf("the entry was escaped:\n%s", got)
	}
	if !strings.HasPrefix(got, strings.TrimSuffix(desktopConfig, "\n}\n")) {
		t.Fatalf("the keys before the entry changed:\n%s", got)
	}
}

// Every shape the splice meets decodes to what the map edit would give, and
// removes back to where it started when there was no jit entry before.
func TestSetMCPEntryShapes(t *testing.T) {
	for name, tc := range map[string]struct{ in, installed string }{
		"compact": {
			in:        `{"a":1,"mcpServers":{"x":{"command":"y"}}}`,
			installed: `{"a":1,"mcpServers":{"x":{"command":"y"},"jit":{"command":"/opt/homebrew/bin/jit","args":["mcp"]}}}`,
		},
		"no servers": {
			in:        "{\n\t\"a\": 1\n}\n",
			installed: "{\n\t\"a\": 1,\n\t\"mcpServers\": {\n\t\t\"jit\": {\n\t\t\t\"command\": \"/opt/homebrew/bin/jit\",\n\t\t\t\"args\": [\n\t\t\t\t\"mcp\"\n\t\t\t]\n\t\t}\n\t}\n}\n",
		},
		"empty object": {
			in:        "{}",
			installed: "{\n  \"mcpServers\": {\n    \"jit\": {\n      \"command\": \"/opt/homebrew/bin/jit\",\n      \"args\": [\n        \"mcp\"\n      ]\n    }\n  }\n}",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mcp.json")
			writeMCPFixture(t, path, tc.in, 0o600)
			if _, err := setMCPEntry(path, testMCPEntry, time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			if got := readMCPFixture(t, path); got != tc.installed {
				t.Fatalf("installed:\n%q\nwant:\n%q", got, tc.installed)
			}
			if _, err := setMCPEntry(path, nil, time.Unix(1, 0)); err != nil {
				t.Fatal(err)
			}
			if got := readMCPFixture(t, path); got != tc.in {
				t.Fatalf("uninstalled:\n%q\nwant:\n%q", got, tc.in)
			}
		})
	}

	// An entry already there, pointing elsewhere, is replaced where it sits.
	path := filepath.Join(t.TempDir(), "mcp.json")
	writeMCPFixture(t, path, `{"mcpServers": {"jit": {"command": "/old/jit", "args": ["mcp"]}, "z": {}}}`, 0o600)
	if _, err := setMCPEntry(path, testMCPEntry, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if got, want := readMCPFixture(t, path), `{"mcpServers": {"jit": {"command":"/opt/homebrew/bin/jit","args":["mcp"]}, "z": {}}}`; got != want {
		t.Fatalf("replaced:\n%s\nwant:\n%s", got, want)
	}
}

// A config kept elsewhere and linked into place (a dotfiles repo) stays a
// link: the edit goes to the file it points at, which keeps its mode.
// Renaming over the path replaced the link with a regular file, forking the
// app's config from the one the user manages.
func TestSetMCPEntryWritesThroughASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "cursor-mcp.json")
	writeMCPFixture(t, target, desktopConfig, 0o644)
	path := filepath.Join(dir, "home", ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	ed, err := setMCPEntry(path, testMCPEntry, time.Unix(0, 0))
	if err != nil || !ed.changed {
		t.Fatalf("install: %+v %v", ed, err)
	}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the config is no longer a link: %v %v", fi.Mode(), err)
	}
	if dest, _ := os.Readlink(path); dest != target {
		t.Fatalf("the link points at %q, want %q", dest, target)
	}
	if !strings.Contains(readMCPFixture(t, target), `"jit"`) {
		t.Fatal("the file the link points at was not edited")
	}
	if ti, _ := os.Stat(target); ti.Mode().Perm() != 0o644 {
		t.Fatalf("the edited file is %v, want its own 0644 kept", ti.Mode().Perm())
	}
	resolved, _ := filepath.EvalSymlinks(target)
	if ed.written != resolved {
		t.Fatalf("written = %q, want %q", ed.written, resolved)
	}
	// The backup sits beside the path jit knows, not in the dotfiles repo.
	if filepath.Dir(ed.backup) != filepath.Dir(path) || readMCPFixture(t, ed.backup) != desktopConfig {
		t.Fatalf("backup %q is not the file as it was, beside the link", ed.backup)
	}
	if entries, _ := os.ReadDir(filepath.Dir(target)); len(entries) != 1 {
		t.Fatalf("the link's folder holds %d files, want only the config", len(entries))
	}

	// A link to nothing is refused and left alone.
	dangling := filepath.Join(dir, "home", "dangling.json")
	if err := os.Symlink(filepath.Join(dir, "gone.json"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := setMCPEntry(dangling, testMCPEntry, time.Unix(0, 0)); err == nil {
		t.Fatal("a dangling link was written through")
	}
	if _, err := os.Stat(filepath.Join(dir, "gone.json")); !os.IsNotExist(err) {
		t.Fatal("a dangling link's target was created")
	}
}

// Every change saves a copy of the file, API keys and all. One is kept per
// config, 0600; older copies jit made are removed, and nothing else is,
// however it is named.
func TestSetMCPEntryKeepsOnlyTheLatestBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	writeMCPFixture(t, path, desktopConfig, 0o644)

	oldest := audit.MCPConfigBackupName(path, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	writeMCPFixture(t, oldest, "{}", 0o644)
	victim := filepath.Join(dir, "victim.json")
	writeMCPFixture(t, victim, "untouched", 0o600)
	keep := map[string]string{
		path + ".bak":                                              "a",
		path + ".jit-backup-latest":                                "b",
		path + ".jit-backup-20260101-000000.orig":                  "c",
		filepath.Join(dir, ".mcp.json.jit-backup-20260101-000000"): "d", // another config's
		filepath.Join(dir, "notes.txt"):                            "e",
	}
	for p, c := range keep {
		writeMCPFixture(t, p, c, 0o600)
	}
	// A link with a backup's exact name is not a file jit wrote.
	link := audit.MCPConfigBackupName(path, time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	first, err := setMCPEntry(path, testMCPEntry, time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first.pruned, []string{oldest}) || first.pruneErr != nil {
		t.Fatalf("install pruned %q (err %v), want only %q", first.pruned, first.pruneErr, oldest)
	}
	beforeUninstall := readMCPFixture(t, path)
	second, err := setMCPEntry(path, nil, time.Date(2026, 9, 26, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(second.pruned, []string{first.backup}) {
		t.Fatalf("uninstall pruned %q, want %q", second.pruned, first.backup)
	}

	if got := audit.MCPConfigBackups(path); !slices.Equal(got, []string{second.backup}) {
		t.Fatalf("backups left = %q, want only %q", got, second.backup)
	}
	if readMCPFixture(t, second.backup) != beforeUninstall {
		t.Fatal("the backup is not the file as it was before the change")
	}
	if fi, _ := os.Stat(second.backup); fi.Mode().Perm() != 0o600 {
		t.Fatalf("the backup is %v, want 0600", fi.Mode().Perm())
	}
	for p, c := range keep {
		if readMCPFixture(t, p) != c {
			t.Errorf("%s, not a jit backup, was changed or removed", p)
		}
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link named like a backup was removed: %v", err)
	}
	if readMCPFixture(t, victim) != "untouched" {
		t.Error("the file behind the link was changed")
	}
}

// The output says where the copy is and what it holds.
func TestMCPInstallSaysWhereTheBackupIsAndWhatItHolds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldCmd, oldClient := mcpCommandPath, mcpClientName
	t.Cleanup(func() { mcpCommandPath, mcpClientName = oldCmd, oldClient })
	mcpCommandPath, mcpClientName = "/opt/homebrew/bin/jit", "cursor"

	path := filepath.Join(home, ".cursor", "mcp.json")
	writeMCPFixture(t, path, desktopConfig, 0o600)
	var out bytes.Buffer
	if err := runMCPInstall(&out, true); err != nil {
		t.Fatal(err)
	}
	backups := audit.MCPConfigBackups(path)
	if len(backups) != 1 {
		t.Fatalf("backups = %q, want one", backups)
	}
	got := out.String()
	if !strings.Contains(got, "backup   "+displayPath(home, backups[0])) || !strings.Contains(got, "with any API keys in it") {
		t.Fatalf("the output does not say where the backup is and what it holds:\n%s", got)
	}
}

// FuzzSpliceMCPEntry: whatever object the file holds, the edit never has to
// be refused as one the splice got wrong. setMCPEntry checks the spliced file
// decodes to the map edit before writing, so a splice mistake shows up here
// as that refusal, and the file is left exactly as it was.
func FuzzSpliceMCPEntry(f *testing.F) {
	for _, seed := range []string{
		desktopConfig, `{}`, `{"mcpServers":{}}`, `{"mcpServers":null}`,
		`{"mcpServers":{"jit":{"command":"/a"},"jit":{"command":"/b"}}}`,
		`{"mcpServers":{"a":1},"mcpServers":{"jit":{}}}`,
		`{"a":[1,{"b":"}"}],"mcpServers":{"x":{"args":["\"{"]}}}`,
		"{\r\n\t\"mcpServers\" : { \"jit\" : {} }\r\n}",
		`{"mcp\u0053ervers":{"j\u0069t":{}}}`,
	} {
		f.Add(seed)
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, doc string) {
		var top map[string]json.RawMessage
		if json.Unmarshal([]byte(doc), &top) != nil || top == nil {
			return
		}
		path := filepath.Join(dir, "mcp.json")
		for _, entry := range []*mcpServerEntry{testMCPEntry, nil} {
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := setMCPEntry(path, entry, time.Unix(0, 0))
			if err != nil && strings.Contains(err.Error(), "edited in place") && !errors.Is(err, errRepeatedServers) {
				t.Fatalf("install=%v on %q: %v", entry != nil, doc, err)
			}
			if err != nil && readMCPFixture(t, path) != doc {
				t.Fatalf("a refused edit changed the file: %q", doc)
			}
			for _, b := range audit.MCPConfigBackups(path) {
				_ = os.Remove(b)
			}
		}
	})
}

// A config path that is a FIFO (jit's own mounts are FIFOs) is refused
// before it is read: reading it would wait for a writer forever.
func TestSetMCPEntryRefusesAFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := setMCPEntry(path, testMCPEntry, time.Unix(0, 0))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("err = %v, want a refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setMCPEntry blocked reading a FIFO")
	}
}
