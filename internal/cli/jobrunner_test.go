// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

//go:build darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jitpass/jit/internal/agent"
	"github.com/jitpass/jit/internal/job"
)

const jobTestKey = "secret_ntn_4f9a2c81b7e6d5c4"

func shJob(t *testing.T, script string, outputs ...string) job.Job {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return job.Job{Name: "t", Dir: dir, Argv: []string{"sh", "run.sh"}, Exe: "/bin/sh", Outputs: outputs, PathEnv: "/usr/bin:/bin"}
}

func TestRunJobCommandHidesValuesAndStartsClean(t *testing.T) {
	// The service's own environment must not reach a job: set something
	// here, in the process that plays the service, and look for it there.
	t.Setenv("SERVICE_ONLY_TOKEN", "leaked-from-the-service")
	j := shJob(t, `echo "key=$NOTION_API_KEY"
echo "domain=$INTERNAL_DOMAINS"
printf '%s' "$NOTION_API_KEY" | base64 >&2
echo "service=${SERVICE_ONLY_TOKEN:-absent}"
echo "cache=$PYTHONPYCACHEPREFIX"
exit 3
`)
	values := map[string]string{"NOTION_API_KEY": jobTestKey, "INTERNAL_DOMAINS": "blockaid.co"}
	hidden := map[string]string{"NOTION_API_KEY": jobTestKey}
	res, err := runJobCommand(j, values, hidden, jobEnv(t.TempDir(), j), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Stdout+res.Stderr, jobTestKey) {
		t.Fatalf("the key reached the caller:\n%s\n%s", res.Stdout, res.Stderr)
	}
	for _, want := range []string{"key=[hidden: NOTION_API_KEY]", "domain=blockaid.co", "service=absent", "cache="} {
		if !strings.Contains(res.Stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, res.Stdout)
		}
	}
	if strings.TrimSpace(res.Stderr) != "[hidden: NOTION_API_KEY]" {
		t.Errorf("stderr = %q, want the base64 form hidden", res.Stderr)
	}
	if res.Exit != 3 || res.Hidden["NOTION_API_KEY"] != 2 {
		t.Errorf("exit %d, hidden %v; want 3 and 2", res.Exit, res.Hidden)
	}
}

func TestRunJobCommandReportsNewOutputFiles(t *testing.T) {
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "old.csv"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := shJob(t, `echo a,b > "$1/new.csv"`+"\n", out)
	j.Argv = append(j.Argv, out)
	res, err := runJobCommand(j, nil, nil, jobEnv(t.TempDir(), j), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NewFiles) != 1 || filepath.Base(res.NewFiles[0]) != "new.csv" {
		t.Fatalf("NewFiles = %v, want only new.csv", res.NewFiles)
	}
}

func TestRunJobCommandStopsAtTheTimeLimit(t *testing.T) {
	j := shJob(t, "echo started\nsleep 30\n")
	start := time.Now()
	res, err := runJobCommand(j, nil, nil, jobEnv(t.TempDir(), j), 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || time.Since(start) > 10*time.Second || !strings.Contains(res.Stdout, "started") {
		t.Fatalf("timed out %v after %s, stdout %q", res.TimedOut, time.Since(start), res.Stdout)
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	b := newTailBuffer(5)
	_, _ = b.Write([]byte("abc"))
	_, _ = b.Write([]byte("defgh"))
	if b.String() != "defgh" || !b.truncated {
		t.Fatalf("got %q truncated=%v", b.String(), b.truncated)
	}
}

// The line `jit job list` prints for a stopped job must approve the SAME
// job again: dropping --show would hide a value the human chose to show.
func TestReapproveCommandKeepsEverySetting(t *testing.T) {
	j := agent.JobStatus{
		Name: "notion-guests", Dir: "/Users/x/Security Ops/notion", Profile: "notion",
		Argv:        []string{".venv/bin/python", "list_guest_users.py"},
		Secrets:     []agent.JobSecretStatus{{Var: "NOTION_API_KEY"}, {Var: "INTERNAL_DOMAINS", Shown: true}},
		Outputs:     []string{"/Users/x/reports"},
		Description: "List Notion guests",
	}
	got := reapproveCommand(j)
	for _, want := range []string{
		"cd '/Users/x/Security Ops/notion' &&", "--replace", "--profile notion",
		"--show INTERNAL_DOMAINS", "--output /Users/x/reports", "--description 'List Notion guests'",
		"-- .venv/bin/python list_guest_users.py",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("reapprove line lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--show NOTION_API_KEY") {
		t.Errorf("a hidden secret was marked shown:\n%s", got)
	}
}

// Review finding 6: the note names the per-stream cap, not the total.
func TestRunJobCommandTruncationNoteNamesTheStreamCap(t *testing.T) {
	j := shJob(t, "head -c 140000 /dev/zero | tr '\\0' a\necho END\n")
	res, err := runJobCommand(j, nil, nil, jobEnv(t.TempDir(), j), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || !strings.HasSuffix(res.Stdout, "END\n") {
		t.Fatalf("truncated=%v, tail %q", res.Truncated, res.Stdout[len(res.Stdout)-10:])
	}
	want := fmt.Sprintf("output passed %d KB on stdout or stderr", job.OutputCap/2>>10)
	if len(res.Notes) == 0 || !strings.Contains(strings.Join(res.Notes, "\n"), want) {
		t.Fatalf("notes = %v, want %q", res.Notes, want)
	}
}
