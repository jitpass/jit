// Copyright 2026 Meni Tasa
// SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0

package migrate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A vendor-format token that passes the placeholder rules (no run, no
// sequence, no filler word).
const shapeProbeToken = "ntn_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"

func writeShapeHome(t *testing.T) (home, transcript, blob string) {
	t.Helper()
	home = t.TempDir()
	transcript = filepath.Join(home, ".claude", "projects", "p", "s.jsonl")
	blob = filepath.Join(home, ".claude", "projects", "p", "blob.bin")
	if err := os.MkdirAll(filepath.Dir(transcript), 0o700); err != nil {
		t.Fatal(err)
	}
	body := "{\"a\":1}\n{\"cmd\":\"export NOTION_TOKEN=" + shapeProbeToken + "\"}\n{\"b\":2}\n{\"again\":\"" + shapeProbeToken + "\"}\n"
	if err := os.WriteFile(transcript, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blob, append([]byte("SQLite\x00\x00"), []byte(shapeProbeToken)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, transcript, blob
}

func TestRedactAgentCacheShapesPlansThenRewritesWithTheMarker(t *testing.T) {
	home, transcript, blob := writeShapeHome(t)

	plan, err := RedactAgentCacheShapes(home, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Edited) != 1 || plan.Edited[0].Path != transcript || plan.Edited[0].Occurrences != 2 {
		t.Fatalf("plan edits = %+v", plan.Edited)
	}
	if len(plan.Skipped) != 1 || plan.Skipped[0].Path != blob || plan.Skipped[0].Kind != SkipBinary {
		t.Fatalf("plan skips = %+v", plan.Skipped)
	}
	if before, _ := os.ReadFile(transcript); !strings.Contains(string(before), shapeProbeToken) {
		t.Fatal("a plan changed the file")
	}

	done, err := RedactAgentCacheShapes(home, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(done.Edited) != 1 || done.Edited[0].BackupPath != "" {
		t.Fatalf("edits = %+v; no backup is taken for a shape redaction", done.Edited)
	}
	after, err := os.ReadFile(transcript)
	if err != nil {
		t.Fatal(err)
	}
	got := string(after)
	if strings.Contains(got, shapeProbeToken) {
		t.Fatalf("token still present:\n%s", got)
	}
	if strings.Count(got, "<jit:redacted:Notion Internal Integration Token>") != 2 {
		t.Fatalf("marker count wrong:\n%s", got)
	}
	if !strings.HasPrefix(got, "{\"a\":1}\n{\"cmd\":\"export NOTION_TOKEN=<jit:redacted:") || !strings.HasSuffix(got, "\"}\n") {
		t.Fatalf("bytes outside the spans changed:\n%s", got)
	}
	if info, _ := os.Stat(transcript); info.Mode().Perm() != 0o600 {
		t.Errorf("permissions changed to %v", info.Mode().Perm())
	}
	if raw, _ := os.ReadFile(blob); !strings.Contains(string(raw), shapeProbeToken) {
		t.Error("the binary store was rewritten")
	}

	// A second run finds nothing: the marker is not a token.
	again, err := RedactAgentCacheShapes(home, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Edited) != 0 {
		t.Errorf("a redacted file still plans edits: %+v", again.Edited)
	}
}

func TestRedactAgentCacheShapesHonoursTheFileAndLineFilters(t *testing.T) {
	home, transcript, _ := writeShapeHome(t)
	other := filepath.Join(home, ".claude", "projects", "q", "t.jsonl")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("{\"x\":\""+shapeProbeToken+"\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Only line 2 of the transcript: the token on line 4 stays.
	done, err := RedactAgentCacheShapes(home, []string{transcript}, []int{2}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(done.Edited) != 1 || done.Edited[0].Occurrences != 1 {
		t.Fatalf("edits = %+v", done.Edited)
	}
	after, _ := os.ReadFile(transcript)
	if strings.Count(string(after), shapeProbeToken) != 1 || strings.Count(string(after), "<jit:redacted:") != 1 {
		t.Fatalf("line filter not honoured:\n%s", after)
	}
	if raw, _ := os.ReadFile(other); !strings.Contains(string(raw), shapeProbeToken) {
		t.Error("a file outside the filter was rewritten")
	}
}

func TestRedactAgentCacheShapesNeverTouchesFilesOutsideAgentCaches(t *testing.T) {
	home, _, _ := writeShapeHome(t)
	mine := filepath.Join(home, "proj", "notes.txt")
	if err := os.MkdirAll(filepath.Dir(mine), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mine, []byte("NOTION_TOKEN="+shapeProbeToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RedactAgentCacheShapes(home, []string{mine}, nil, true); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(mine); !strings.Contains(string(raw), shapeProbeToken) {
		t.Fatal("a file of the user's own was rewritten; only agent caches may be")
	}
}

// A Redact… on a row names the file the scan listed. When that file can no
// longer be read, the run says so instead of "nothing to redact", which
// would leave the row on screen with no reason. An unnamed sweep stays
// quiet about such files: nothing says they held a token.
func TestRedactNamesAFileItCouldNotReadAgain(t *testing.T) {
	home, transcript, _ := writeShapeHome(t)
	if err := os.Chmod(transcript, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(transcript, 0o600) })
	if f, err := os.Open(transcript); err == nil {
		_ = f.Close()
		t.Skip("running as a user who reads a mode-000 file")
	}

	named, err := RedactAgentCacheShapes(home, []string{transcript}, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(named.Skipped) != 1 || named.Skipped[0].Path != transcript || named.Skipped[0].Kind != SkipUnreadable {
		t.Errorf("named: skipped = %+v, want the transcript as unreadable", named.Skipped)
	}

	all, err := RedactAgentCacheShapes(home, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range all.Skipped {
		if s.Kind == SkipUnreadable {
			t.Errorf("unnamed sweep reported %s as unreadable", s.Path)
		}
	}
}

// The file-shaped caches the scan reads with the content scanner are
// redacted with it too. A Telegram bot token has no literal lead, so the
// indexed sweep never matched it: the scan listed the row and Redact
// planned nothing (found 2026-09-28). The token sits on a later line, after
// CRLF line ends, so the spans must be offsets into the file.
func TestRedactFindsWhatTheScanFoundInPasteCacheAndHistory(t *testing.T) {
	const bot = "7384920156:AAfK3n9QzT1xLm8RpW2vYc6HdJ5sGe4BuNo"
	home := t.TempDir()
	files := map[string]string{
		filepath.Join(home, ".claude", "paste-cache", "p.txt"): "first\r\nsecond line\r\nbot token " + bot + " here\r\n",
		filepath.Join(home, ".claude", "history.jsonl"):        "{\"display\":\"hi\"}\n{\"display\":\"use " + bot + "\"}\n",
	}
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for p, body := range files {
		done, err := RedactAgentCacheShapes(home, []string{p}, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(done.Edited) != 1 {
			t.Errorf("%s: edited = %+v, want the file", filepath.Base(p), done.Edited)
			continue
		}
		got, _ := os.ReadFile(p)
		want := strings.Replace(body, bot, "<jit:redacted:Telegram Bot Token>", 1)
		if string(got) != want {
			t.Errorf("%s:\n got %q\nwant %q", filepath.Base(p), got, want)
		}
	}
}
