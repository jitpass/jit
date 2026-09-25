// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package job

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCheckArgv(t *testing.T) {
	refused := [][]string{
		{"env"},
		{"/usr/bin/printenv", "NOTION_API_KEY"},
		{"cat", ".env"},
		{".venv/bin/python", "-c", "import os; print(os.environ)"},
		{"python3.14", "-Bc", "print(1)"},
		{"python3", "-X", "dev", "-c", "print(1)"}, // -X's value must not end the scan
		{"bash", "-lc", "env"},
		{"/bin/zsh", "-c", "env"},
		{"sh", "-o", "errexit", "-c", "env"},
		{"node", "-e", "console.log(process.env)"},
		{"node", "--eval=console.log(1)"},
		{"node", "-p", "process.env"},
		{"ruby", "-e", "p ENV"},
		{"perl", "-E", "say %ENV"},
		{"php", "-r", "var_dump(getenv());"},
		{"osascript", "-e", "do shell script \"env\""},
		{"deno", "eval", "console.log(Deno.env.toObject())"},
		{"node", "--require", "./m.js", "-e", "console.log(process.env)"}, // review finding 5
		{"bash", "--rcfile", "x", "-c", "env"},
	}
	for _, argv := range refused {
		if err := CheckArgv(argv); err == nil {
			t.Errorf("CheckArgv(%q) = nil, want refused", argv)
		}
	}
	allowed := [][]string{
		{".venv/bin/python", "list_guest_users.py"},
		{"python3", "-u", "script.py", "-c", "config.yaml"}, // -c after the script is the script's own
		{"python3", "-m", "exporter"},
		{"node", "index.js", "-e", "x"},
		{"bash", "run.sh"},
		{"./export.sh"},
		{"go", "run", "."},
	}
	for _, argv := range allowed {
		if err := CheckArgv(argv); err != nil {
			t.Errorf("CheckArgv(%q) = %v, want allowed", argv, err)
		}
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"notion-guests", "a", "jamf2", "0x"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "-x", "Notion", "a_b", "a b", "../x", strings.Repeat("a", 41)} {
		if ValidateName(bad) == nil {
			t.Errorf("ValidateName(%q) = nil, want error", bad)
		}
	}
}

func TestStoreRoundTripAndNewerRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jobs.json")
	jobs, err := Load(path)
	if err != nil || len(jobs) != 0 {
		t.Fatalf("missing file: %v, %d jobs", err, len(jobs))
	}
	jobs["notion-guests"] = &Job{
		Name: "notion-guests", Dir: "/x", Argv: []string{"python", "a.py"}, Exe: "/usr/bin/python3",
		Ask: AskEachTime, Secrets: []Secret{{Var: "K", Path: "notion/K", DeviceDigest: "ab"}},
	}
	if err := Save(path, jobs); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("jobs.json mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	back, err := Load(path)
	if err != nil || back["notion-guests"] == nil || back["notion-guests"].Secrets[0].Path != "notion/K" {
		t.Fatalf("round trip: %v %+v", err, back)
	}

	if err := os.WriteFile(path, []byte(`{"version": 99, "jobs": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrNewerStore) {
		t.Fatalf("newer file: err = %v, want ErrNewerStore", err)
	}
}

// fixture builds a job folder shaped like the notion one: a script, a venv
// with a library and a python symlink out of the folder, a __pycache__, a
// profile manifest, and a jit mount FIFO.
func fixture(t *testing.T) (dir, exe string) {
	t.Helper()
	dir = t.TempDir()
	outside := t.TempDir()
	exe = filepath.Join(outside, "python3.14")
	write(t, exe, "interpreter v1")
	write(t, filepath.Join(dir, "list_guest_users.py"), "print('hi')\n")
	write(t, filepath.Join(dir, ".venv/lib/site-packages/requests/sessions.py"), "def get(): pass\n")
	write(t, filepath.Join(dir, ".jit/profiles/notion.yaml"), "NOTION_API_KEY: notion/NOTION_API_KEY\n")
	write(t, filepath.Join(dir, "__pycache__/list_guest_users.cpython-314.pyc"), "bytecode")
	if err := os.MkdirAll(filepath.Join(dir, ".venv/bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(dir, ".venv/bin/python")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, ".env"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, filepath.Join(dir, ".venv/bin/python")
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFingerprintStableAndSkips(t *testing.T) {
	dir, exe := fixture(t)
	a, err := Compute(dir, exe, nil, nil)
	if err != nil {
		t.Fatal(err) // a FIFO that was opened would hang here, not fail
	}
	if _, ok := a.Files[".env"]; ok {
		t.Error("the mount FIFO was fingerprinted")
	}
	if a.Files[".venv/bin/python"] == "" || !strings.HasPrefix(a.Files[".venv/bin/python"], "link:") {
		t.Errorf("venv symlink = %q, want its target recorded", a.Files[".venv/bin/python"])
	}
	b, err := Compute(dir, exe, nil, nil)
	if err != nil || a.Root != b.Root {
		t.Fatalf("two fingerprints of an unchanged folder differ: %v", err)
	}
}

// Second review, finding 4: `python -I` ignores PYTHONPYCACHEPREFIX and
// loads in-tree bytecode, so a planted .pyc must stop the job.
func TestFingerprintCoversBytecode(t *testing.T) {
	dir, exe := fixture(t)
	before, _ := Compute(dir, exe, nil, nil)
	write(t, filepath.Join(dir, "__pycache__/list_guest_users.cpython-314.pyc"), "planted bytecode")
	after, _ := Compute(dir, exe, nil, nil)
	if d := Diff(before, after); len(d) != 1 || !strings.Contains(d[0].Path, "__pycache__") {
		t.Fatalf("Diff = %v, want the rewritten .pyc", d)
	}
}

// Second review, finding 1: a folder reached through a symlink (cd through
// /tmp, a linked project) used to fingerprint as empty.
func TestFingerprintThroughASymlinkedFolder(t *testing.T) {
	dir, exe := fixture(t)
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	real, _ := Compute(dir, exe, nil, nil)
	via, err := Compute(link, exe, nil, nil)
	if err != nil || len(via.Files) == 0 || via.Root != real.Root {
		t.Fatalf("via symlink: %d files, root match %v, err %v", len(via.Files), via.Root == real.Root, err)
	}
}

// Second review, finding 6: a symlink out of the folder is covered by what it
// points at (a file) or refused (a folder).
func TestFingerprintFollowsLinksOutOfTheFolder(t *testing.T) {
	dir, exe := fixture(t)
	shared := t.TempDir()
	write(t, filepath.Join(shared, "run.py"), "print('v1')\n")
	if err := os.Symlink(filepath.Join(shared, "run.py"), filepath.Join(dir, "run.py")); err != nil {
		t.Fatal(err)
	}
	before, err := Compute(dir, exe, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(shared, "run.py"), "import os; print(os.environ)\n")
	after, _ := Compute(dir, exe, nil, nil)
	if d := Diff(before, after); len(d) != 1 || d[0].Path != "run.py"+LinkTargetSuffix {
		t.Fatalf("Diff = %v, want the linked file's content", d)
	}
	if err := os.Symlink(shared, filepath.Join(dir, "lib")); err != nil {
		t.Fatal(err)
	}
	if _, err := Compute(dir, exe, nil, nil); !errors.Is(err, ErrLinkOutside) {
		t.Fatalf("a link to a folder outside: err = %v, want ErrLinkOutside", err)
	}
}

// Second review, finding 9: a file swapped for a named pipe must fail fast,
// not block every list and run behind it.
func TestFingerprintRefusesAPipeInsteadOfHanging(t *testing.T) {
	dir, exe := fixture(t)
	outside := filepath.Join(t.TempDir(), "run.py")
	if err := syscall.Mkfifo(outside, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := Compute(dir, exe, nil, []string{outside}); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a pipe was fingerprinted as a file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Compute blocked on a named pipe")
	}
}

func TestFingerprintNamesWhatChanged(t *testing.T) {
	cases := []struct {
		name string
		edit func(t *testing.T, dir, exeTarget string)
		want Change
	}{
		{"script edited", func(t *testing.T, dir, _ string) {
			write(t, filepath.Join(dir, "list_guest_users.py"), "import os; print(os.environ)\n")
		}, Change{"list_guest_users.py", Changed}},
		{"library edited", func(t *testing.T, dir, _ string) {
			write(t, filepath.Join(dir, ".venv/lib/site-packages/requests/sessions.py"), "leak()\n")
		}, Change{".venv/lib/site-packages/requests/sessions.py", Changed}},
		{"profile remapped", func(t *testing.T, dir, _ string) {
			write(t, filepath.Join(dir, ".jit/profiles/notion.yaml"), "NOTION_API_KEY: jamf/JAMF_CLIENT_SECRET\n")
		}, Change{".jit/profiles/notion.yaml", Changed}},
		{"file added", func(t *testing.T, dir, _ string) {
			write(t, filepath.Join(dir, ".venv/lib/site-packages/sitecustomize.py"), "leak()\n")
		}, Change{".venv/lib/site-packages/sitecustomize.py", Added}},
		{"file removed", func(t *testing.T, dir, _ string) {
			if err := os.Remove(filepath.Join(dir, "list_guest_users.py")); err != nil {
				t.Fatal(err)
			}
		}, Change{"list_guest_users.py", Removed}},
		{"interpreter swapped", func(t *testing.T, _ string, exeTarget string) {
			write(t, exeTarget, "interpreter v2")
		}, Change{ExePath, Changed}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, exe := fixture(t)
			target, _ := filepath.EvalSymlinks(exe)
			before, err := Compute(dir, exe, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(t, dir, target)
			after, err := Compute(dir, exe, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := Diff(before, after)
			// Swapping the interpreter also changes the venv link's target
			// content: two true facts. Every other edit is exactly one.
			if len(got) == 0 || got[0] != tc.want || (tc.want.Path != ExePath && len(got) != 1) {
				t.Fatalf("Diff = %v, want %v first", got, tc.want)
			}
			if before.Root == after.Root {
				t.Fatal("root hash did not move")
			}
		})
	}
}

func TestFingerprintSkipsOutputs(t *testing.T) {
	dir, exe := fixture(t)
	out := filepath.Join(dir, "reports")
	before, err := Compute(dir, exe, []string{out}, nil)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(out, "notion_guest_users_1.csv"), "a,b\n")
	after, err := Compute(dir, exe, []string{out}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(before, after); len(d) != 0 {
		t.Fatalf("a file in a declared output stopped the job: %v", d)
	}
}

const key = "secret_ntn_4f9a2c81b7e6d5c4"

func masked(t *testing.T, hidden map[string]string, chunks ...string) (string, map[string]int) {
	t.Helper()
	var out bytes.Buffer
	m := NewMasker(&out, hidden)
	for _, c := range chunks {
		if _, err := m.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String(), m.Counts()
}

func TestMaskerHidesPlainAndEncoded(t *testing.T) {
	// Not the shared key: its base64 needs '/' and padding, so the standard
	// and URL-safe forms differ and each is tested for itself. With a key of
	// letters and digits only, the two coincide and dropping either one from
	// encodings() would go unnoticed (it did, the first time).
	const k = "secret_ntn_4f9a2c81b7e6?>~"
	std := base64.StdEncoding.EncodeToString([]byte(k))
	url := base64.RawURLEncoding.EncodeToString([]byte(k))
	if std == url || !strings.HasSuffix(std, "=") {
		t.Fatalf("fixture no longer separates the forms: %s %s", std, url)
	}
	in := "key=" + k + "\nAuthorization: Basic " + std + "\njwt." + url + ".sig\nok\n"
	got, counts := masked(t, map[string]string{"NOTION_API_KEY": k}, in)
	want := "key=[hidden: NOTION_API_KEY]\nAuthorization: Basic [hidden: NOTION_API_KEY]\njwt.[hidden: NOTION_API_KEY].sig\nok\n"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if counts["NOTION_API_KEY"] != 3 {
		t.Fatalf("counts = %v, want 3", counts)
	}
}

// Every split point of a line holding the key, fed as two writes: the
// hold-back is what catches a value the pipe delivered in two reads.
func TestMaskerCatchesAValueSplitAcrossWrites(t *testing.T) {
	line := "token " + key + " end\n"
	for cut := 0; cut <= len(line); cut++ {
		got, _ := masked(t, map[string]string{"K": key}, line[:cut], line[cut:])
		if got != "token [hidden: K] end\n" {
			t.Fatalf("split at %d: %q", cut, got)
		}
	}
}

func TestMaskerPassesOtherOutputAndShortValues(t *testing.T) {
	in := "Total users seen: 264\nx@acme.co\n"
	got, counts := masked(t, map[string]string{"PORT": "443", "K": key}, in)
	if got != in {
		t.Fatalf("output changed with nothing to hide: %q", got)
	}
	if len(counts) != 0 {
		t.Fatalf("counts = %v, want none", counts)
	}
}

func TestMaskerWithNothingHiddenIsAPassThrough(t *testing.T) {
	got, _ := masked(t, nil, "a", "b", "c\n")
	if got != "abc\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMaskerShortValues(t *testing.T) {
	// 4..7 characters: hidden as typed, never as an encoding.
	got, counts := masked(t, map[string]string{"PIN": "4821"}, "pin 4821 ok\n")
	if got != "pin [hidden: PIN] ok\n" || counts["PIN"] != 1 {
		t.Fatalf("got %q %v", got, counts)
	}
	// Under 4: not hidden, and reported so the run can say so.
	got, _ = masked(t, map[string]string{"PORT": "443"}, "port 443\n")
	if got != "port 443\n" {
		t.Fatalf("got %q", got)
	}
	if s := ShortValues(map[string]string{"PORT": "443", "K": key, "E": ""}); len(s) != 1 || s[0] != "PORT" {
		t.Fatalf("ShortValues = %v", s)
	}
}

func TestResolveExe(t *testing.T) {
	dir, venvPython := fixture(t)
	if err := os.Chmod(filepath.Join(filepath.Dir(venvPython), "..", "..", "list_guest_users.py"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, _ := filepath.EvalSymlinks(venvPython)
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveExe(".venv/bin/python", dir, "")
	if err != nil || got != venvPython {
		t.Fatalf("relative: %q %v, want %q (not symlink-resolved: a venv finds itself from this path)", got, err, venvPython)
	}
	bin := filepath.Dir(target)
	got, err = ResolveExe("python3.14", "/nowhere", "relative/dir:"+bin)
	if err != nil || got != target {
		t.Fatalf("PATH search: %q %v, want %q", got, err, target)
	}
	if _, err := ResolveExe("list_guest_users.py", dir, dir); err == nil {
		t.Fatal("a non-executable file resolved")
	}
	if _, err := ResolveExe("python3.14", "/", "relative/dir"); err == nil {
		t.Fatal("a relative PATH entry was searched")
	}
}

// Review finding 4: a script named outside the job folder is fingerprinted.
func TestExternalFilesAreFingerprinted(t *testing.T) {
	dir, exe := fixture(t)
	outside := filepath.Join(t.TempDir(), "run.py")
	write(t, outside, "print('v1')\n")
	cfg := filepath.Join(filepath.Dir(outside), "c.yaml")
	write(t, cfg, "a: 1\n")
	extra, err := ExternalFiles([]string{"python", outside, "--config=" + cfg, "list_guest_users.py", "not-a-file", "-u"}, dir)
	if err != nil || len(extra) != 2 {
		t.Fatalf("ExternalFiles = %v, want the script and the config, nothing inside the folder", extra)
	}
	before, err := Compute(dir, exe, nil, extra)
	if err != nil {
		t.Fatal(err)
	}
	write(t, outside, "import os; print(os.environ)\n")
	outside, _ = filepath.EvalSymlinks(outside) // recorded resolved: /var → /private/var
	after, err := Compute(dir, exe, nil, extra)
	if err != nil {
		t.Fatal(err)
	}
	d := Diff(before, after)
	if len(d) != 1 || d[0].Path != OutsidePrefix+outside {
		t.Fatalf("Diff = %v, want the outside script", d)
	}
}

// Review finding 2: an output that holds the folder would empty the
// fingerprint.
func TestOutputCoversDir(t *testing.T) {
	for _, tc := range []struct {
		out, dir string
		want     bool
	}{
		{"/a/b", "/a/b", true},
		{"/a", "/a/b", true},
		{"/a/b/", "/a/b", true},
		{"/a/b/reports", "/a/b", false},
		{"/a/bc", "/a/b", false},
		{"/x", "/a/b", false},
	} {
		if got := OutputCoversDir(tc.out, tc.dir); got != tc.want {
			t.Errorf("OutputCoversDir(%q, %q) = %v", tc.out, tc.dir, got)
		}
	}
}

// Second review, finding 6: an interpreter pointed at a folder outside the
// job runs code nothing covers.
func TestExternalFilesRefusesAProgramFolderOutside(t *testing.T) {
	dir, _ := fixture(t)
	pkg := t.TempDir()
	if _, err := ExternalFiles([]string{"python", pkg}, dir); err == nil {
		t.Fatal("python <folder outside> was accepted")
	}
	if _, err := ExternalFiles([]string{"python", "run.py", "--out", pkg}, dir); err != nil {
		t.Fatalf("a folder given to the script as an argument was refused: %v", err)
	}
}

// Second review, finding 8: embedded and escaped forms.
func TestMaskerHidesEmbeddedAndEscapedForms(t *testing.T) {
	for _, prefix := range []string{"", "u:", "user:", "me@x.com:"} {
		b64 := base64.StdEncoding.EncodeToString([]byte(prefix + key))
		got, _ := masked(t, map[string]string{"K": key}, "Authorization: Basic "+b64+"\n")
		if strings.Contains(got, b64) || !strings.Contains(got, "[hidden: K]") {
			t.Errorf("prefix %q: base64 of the header passed: %q", prefix, got)
		}
	}
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nq2bm0T2p3xYvS7kEo4jRmN8cWfU1dL6aZqPp9hXvTt0YQeKs1a\n-----END PRIVATE KEY-----\n"
	escaped := strings.ReplaceAll(pem, "\n", `\n`)
	got, _ := masked(t, map[string]string{"SA_KEY": pem}, `{"private_key": "`+escaped+`"}`+"\n")
	if strings.Contains(got, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7") {
		t.Errorf("a JSON-escaped key passed: %q", got)
	}
	// Only the JSON-escaped form catches these: one line with a quote and a
	// backslash, and a multi-line value whose lines are too short to be
	// hidden one by one. (The PEM above is also caught line by line, so it
	// cannot tell whether JSON escaping works; the first version of this test
	// passed with it removed.)
	for _, v := range []string{`pa"ss\word-4f9a2c81`, "tok-line-one\ntok-line-two"} {
		js, _ := json.Marshal(map[string]string{"v": v})
		got, _ := masked(t, map[string]string{"V": v}, string(js)+"\n")
		if !strings.Contains(got, "[hidden: V]") {
			t.Errorf("JSON-escaped %q passed: %s", v, got)
		}
	}
	got, _ = masked(t, map[string]string{"SA_KEY": pem}, "line: q2bm0T2p3xYvS7kEo4jRmN8cWfU1dL6aZqPp9hXvTt0YQeKs1a\n")
	if strings.Contains(got, "q2bm0T2p3xYvS7kEo4jRmN8c") {
		t.Errorf("one line of a multi-line key passed: %q", got)
	}
}
